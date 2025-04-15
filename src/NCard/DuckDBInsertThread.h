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
        con->Query("PRAGMA memory_limit='100MB';");
    }
    ~DuckDBInsertThread() {
        stop();
        con.reset();
        db.reset();
    }
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

    int64_t getMaxId() {
        try {
            auto result = con->Query("SELECT MAX(rowid) FROM packets;");
            if (!result->HasError() && result->RowCount() > 0) {
                return result->GetValue<int64_t>(0, 0);
            }
            return -1;
        } catch (const std::exception& e) {
            qWarning() << "Failed to get max id: " << e.what();
            return -1;
        }
    }

    static constexpr int maxQueueSize = 10000;
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
            batch.reserve(batchSize);
            while (!packetQueue_.isEmpty() && count < batchSize) {
                auto pair = packetQueue_.dequeue();
                batch.push_back(std::make_tuple(pair.first, std::move(pair.second)));
                count++;
            }
            locker.unlock();
            if (!batch.empty()) {
                try {
                    con->Query("BEGIN TRANSACTION;");
                    {
                        duckdb::Appender appender(*con, "packets");
                        for (auto &[header, pkt_data] : batch) {
                            // Извлекаем тип пакета (13-й и 14-й байты)
                            QByteArray packetType;

                            if (pkt_data.size() > 13) {
                                uint8_t eth_type_1 = static_cast<uint8_t>(pkt_data[12]);
                                uint8_t eth_type_2 = static_cast<uint8_t>(pkt_data[13]);

                                // Добавляем этернет тип
                                packetType.append(static_cast<char>(eth_type_1));
                                packetType.append(static_cast<char>(eth_type_2));

                                // Проверяем на IPv4
                                if (eth_type_1 == 0x08 && eth_type_2 == 0x00 && pkt_data.size() > 23) {
                                    // Добавляем тип протокола IPv4 (24-й байт)
                                    packetType.append(pkt_data[23]);
                                }
                                // Проверяем на IPv6
                                else if (eth_type_1 == 0x86 && eth_type_2 == 0xDD && pkt_data.size() > 20) {
                                    // Добавляем тип протокола IPv6 (21-й байт)
                                    packetType.append(pkt_data[20]);
                                }
                            } else if (pkt_data.size() > 12) {
                                // Если есть только 13-й байт
                                packetType.append(pkt_data[12]);
                                packetType.append(static_cast<char>(0));
                            } else {
                                // Если пакет слишком короткий
                                packetType.append(static_cast<char>(0));
                                packetType.append(static_cast<char>(0));
                            }

                            appender.BeginRow();
                            appender.Append<int64_t>(header.ts.tv_sec);
                            appender.Append<uint16_t>(header.caplen);
                            appender.Append<uint16_t>(header.len);
                            // Добавляем тип пакета как BLOB
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(packetType.constData()), packetType.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(pkt_data.constData()), pkt_data.size()));
                            appender.EndRow();
                        }
                        appender.Flush();
                        appender.Close();
                    }
                    con->Query("COMMIT;");
                    emit insertCommited(batch.size());
                } catch (const std::exception& e) {
                    qWarning() << "Exception in database operation: " << e.what();
                    con->Query("ROLLBACK;");
                }
            }
            if (count < batchSize) {
                std::this_thread::sleep_for(std::chrono::milliseconds(waitTimeMs));
            }
        }
    }
signals:
        void insertCommited(int);
private:
    void ensureTableExists() {
        try {
            qDebug() << "Using DB at:" << QDir::currentPath();
            con->Query(
                "CREATE TABLE IF NOT EXISTS packets ("
                "ts INTEGER, "
                "caplen SMALLINT, "
                "len SMALLINT, "
                "packet_type BLOB, "
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
