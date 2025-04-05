#ifndef CLICKHOUSEINSERTTHREAD_H
#define CLICKHOUSEINSERTTHREAD_H

#include <clickhouse/client.h>
#include <QThread>
#include <QQueue>
#include <QMutex>
#include <Winsock2.h>
#include <QWaitCondition>

#include "pcap.h"
#include "packages/service_pcap/misc.h"

class ClickHouseInsertThread : public QThread {
    Q_OBJECT
public:
    explicit ClickHouseInsertThread(QObject* parent = nullptr)
        : QThread(parent), client_(std::make_shared<clickhouse::Client>(clickhouse::ClientOptions().SetHost("localhost"))), stop_(false) {
        ensureTableExists();
    }

    ~ClickHouseInsertThread() {
        stop();
    }

    static constexpr int maxQueueSize = 10000;  // Максимальное количество пакетов в очереди

    void addPacket(const struct pcap_pkthdr* header, const u_char* pkt_data) {
        QMutexLocker locker(&mutex_);
        if (packetQueue_.size() >= maxQueueSize) {
            packetQueue_.dequeue();
        }
        // Создаем копию данных, которые будут автоматически освобождены при удалении
        packetQueue_.enqueue({ *header, QByteArray(reinterpret_cast<const char*>(pkt_data), header->caplen) });
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

protected:
    void run() override {
        constexpr int batchSize = 1000;  // Количество пакетов на вставку
        constexpr int waitTimeMs = 10;   // Время ожидания перед вставкой

        while (true) {
            QMutexLocker locker(&mutex_);
            while (packetQueue_.isEmpty() && !stop_) {
                cond_.wait(&mutex_);
            }
            if (stop_ && packetQueue_.isEmpty()) {
                break;
            }

            clickhouse::Block block;
            auto col_ts = std::make_shared<clickhouse::ColumnDateTime>();
            auto col_caplen = std::make_shared<clickhouse::ColumnUInt32>();
            auto col_len = std::make_shared<clickhouse::ColumnUInt32>();
            auto col_data = std::make_shared<clickhouse::ColumnString>();

            int count = 0;
            while (!packetQueue_.isEmpty() && count < batchSize) {
                auto [header, pkt_data] = packetQueue_.dequeue();
                locker.unlock();

                col_ts->Append(header.ts.tv_sec);
                col_caplen->Append(header.caplen);
                col_len->Append(header.len);
                col_data->Append(pkt_data.toStdString());

                // Очистка данных после обработки
                // Удаляем содержимое QByteArray
                pkt_data.clear();

                count++;
                locker.relock();
            }

            if (count > 0) {
                block.AppendColumn("ts", col_ts);
                block.AppendColumn("caplen", col_caplen);
                block.AppendColumn("len", col_len);
                block.AppendColumn("data", col_data);

                client_->Insert("packets", block);
            }

            // Если данных было мало, ждём немного перед следующей вставкой
            if (count < batchSize) {
                locker.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(waitTimeMs));
            }
        }
    }

private:
    void ensureTableExists() {
        client_->Execute("CREATE TABLE IF NOT EXISTS packets (\
                          ts DateTime,\
                          caplen UInt32,\
                          len UInt32,\
                          data String\
                          ) ENGINE = MergeTree()\
                          ORDER BY ts;");
    }

    std::shared_ptr<clickhouse::Client> client_;
    QQueue<QPair<pcap_pkthdr, QByteArray>> packetQueue_;
    QMutex mutex_;
    QWaitCondition cond_;
    bool stop_;
};

#endif // CLICKHOUSEINSERTTHREAD_H
