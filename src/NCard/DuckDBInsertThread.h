#ifndef DUCKDBINSERTTHREAD_H
#define DUCKDBINSERTTHREAD_H

#include <QThread>
#include <QQueue>
#include <QMutex>
#include <Winsock2.h>
#include <QWaitCondition>
#include <QByteArray>
#include <QFile>
#include <QString>
#include <QDebug>
#include <QDir>


#include "pcap.h"
#include "packages/service_pcap/misc.h"

#include "duckdb.hpp"

class DuckDBInsertThread : public QThread {
    Q_OBJECT
public:
    explicit DuckDBInsertThread(QObject* parent = nullptr)
        : QThread(parent), db(nullptr), con(nullptr), stop_(false) {
        db = std::make_shared<duckdb::DuckDB>("packets.db"); // Файл БД
        con = std::make_shared<duckdb::Connection>(*db);
        ensureTableExists();
        con->Query("PRAGMA memory_limit='10MB';");
    }



    ~DuckDBInsertThread() {
        stop();
        // Освобождаем умные указатели
        con.reset();
        db.reset();
    }

    static constexpr int maxQueueSize = 10000;

    void addPacket(const struct pcap_pkthdr header, const QByteArray data) {
        QMutexLocker locker(&mutex_);
        if (packetQueue_.size() >= maxQueueSize) {
            packetQueue_.dequeue();
        }
        packetQueue_.enqueue({ header, data });
        cond_.wakeOne();
    }

    void stop() {
        {
            QMutexLocker locker(&mutex_);
            stop_ = true;
        }
        cond_.wakeOne();
        wait();
    }
    std::shared_ptr<duckdb::Connection> getConnection() const {
        return con;
    }

protected:
    void run() override {
        constexpr int batchSize = 10000;
        constexpr int waitTimeMs = 10;

        while (true) {
            QMutexLocker locker(&mutex_);
            while (packetQueue_.isEmpty() && !stop_) {
                cond_.wait(&mutex_);
            }
            if (stop_ && packetQueue_.isEmpty()) break;

            int count = 0;
            std::vector<std::tuple<pcap_pkthdr, QByteArray>> batch;
            batch.reserve(batchSize); // Резервируем память для оптимизации

            while (!packetQueue_.isEmpty() && count < batchSize) {
                auto pair = packetQueue_.dequeue();
                // Используем std::move для избежания копирования данных
                batch.push_back(std::make_tuple(pair.first, std::move(pair.second)));
                count++;
            }
            locker.unlock();

            if (!batch.empty()) {
                try {
                    con->Query("BEGIN TRANSACTION;");
                    {
                        // Создаем Appender в блоке для автоматического освобождения
                        duckdb::Appender appender(*con, "packets");
                        for (auto &[header, pkt_data] : batch) {
                            appender.BeginRow();
                            appender.Append<int64_t>(header.ts.tv_sec);
                            appender.Append<uint16_t>(header.caplen);
                            appender.Append<uint16_t>(header.len);
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(pkt_data.constData()), pkt_data.size()));
                            appender.EndRow();
                        }
                        appender.Flush();
                        appender.Close(); // Явно закрываем Appender
                    }
                    con->Query("COMMIT;");
                } catch (const std::exception& e) {
                    qWarning() << "Exception in database operation: " << e.what();
                    con->Query("ROLLBACK;"); // Откатываем транзакцию в случае ошибки
                }
            }

            if (count < batchSize) {
                std::this_thread::sleep_for(std::chrono::milliseconds(waitTimeMs));
            }
        }
    }

private:
    void ensureTableExists() {
        try {
            qDebug() << "Using DB at:" << QDir::currentPath();
            con->Query(
                "CREATE TABLE IF NOT EXISTS packets ("
                "ts INTEGER, "
                "caplen SMALLINT, "
                "len SMALLINT, "
                "data BLOB"
                ") WITH (compression='zlib');"
            );
        } catch (const std::exception& e) {
            qWarning() << "Failed to create table: " << e.what();
        }
    }

    std::shared_ptr<duckdb::DuckDB> db;
    std::shared_ptr<duckdb::Connection> con;
    QQueue<QPair<pcap_pkthdr, QByteArray>> packetQueue_;
    QMutex mutex_;
    QWaitCondition cond_;
    bool stop_;
};

#endif // DUCKDBINSERTTHREAD_H
