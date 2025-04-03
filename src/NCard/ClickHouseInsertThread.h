#ifndef CLICKHOUSEINSERTTHREAD_H
#define CLICKHOUSEINSERTTHREAD_H

#include <QThread>
#include <QQueue>
#include <QDebug>
#include <QMutex>
#include <QWaitCondition>
#include <clickhouse/client.h>

class ClickHouseInsertThread : public QThread
{
    Q_OBJECT

public:
    explicit ClickHouseInsertThread(clickhouse::Client* client, QObject *parent = nullptr)
        : QThread(parent), client(client), stop(false) {}

    void run() override {
        while (!stop) {
            queue_mutex.lock();
            while (queue.isEmpty() && !stop) {
                queue_notifier.wait(&queue_mutex);  // Ждем, пока не появятся новые данные
            }

            QQueue<clickhouse::Block> batch = std::move(queue);  // Берем всю очередь за раз
            qDebug() << "Batch proceed";
            queue_mutex.unlock();

            while (!batch.isEmpty()) {
                client->Insert("packets", batch.dequeue());
            }
        }
    }

    void enqueueBlock(const clickhouse::Block& block) {
        queue_mutex.lock();
        queue.enqueue(block);

        if (queue.size() >= 1000) {  // Дождаться 1000 пакетов перед вставкой
            queue_notifier.wakeOne();
        }
        queue_mutex.unlock();
    }

    void stopThread() {
        stop = true;
        queue_notifier.wakeAll();
    }

private:
    clickhouse::Client* client;
    QQueue<clickhouse::Block> queue;
    QMutex queue_mutex;
    QWaitCondition queue_notifier;
    bool stop;
};

#endif // CLICKHOUSEINSERTTHREAD_H
