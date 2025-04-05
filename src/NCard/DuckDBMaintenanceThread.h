#ifndef DUCKDBMAINTENANCETHREAD_H
#define DUCKDBMAINTENANCETHREAD_H

#include <QThread>
#include <QFileInfo>
#include <QMutex>
#include <QDebug>
#include <QWaitCondition>
#include <chrono>
#include <duckdb.hpp>

class DuckDBMaintenanceThread : public QThread {
    Q_OBJECT

public:
    DuckDBMaintenanceThread(std::shared_ptr<duckdb::Connection> connection, QObject* parent = nullptr)
        : QThread(parent), con(connection), stop_(false) {}

    void stop() {
        {
            QMutexLocker locker(&mutex_);
            stop_ = true;
        }
        waitCond_.wakeOne();
        wait();
    }

protected:
    void run() override {
        constexpr int optimizeIntervalSeconds = 60;
        constexpr int vacuumEveryN = 5; // раз в 5 циклов оптимизации

        int counter = 0;
        while (!stop_) {
            const QString dbPath = "packets.db";
            QFileInfo dbInfo(dbPath);
            qint64 sizeBefore = dbInfo.size();

            QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
            qDebug() << QString("[%1] [DuckDBMaintenance] Starting optimization (cycle %2)...")
                            .arg(timestamp).arg(counter + 1);

            con->Query("PRAGMA optimize;");
            con->Query("ANALYZE;");

            if (++counter % vacuumEveryN == 0) {
                qDebug() << QString("[%1] [DuckDBMaintenance] Running VACUUM...").arg(timestamp);
                con->Query("VACUUM;");
            }

            // обновим инфу после оптимизации
            dbInfo.refresh();
            qint64 sizeAfter = dbInfo.size();

            qDebug() << QString("[%1] [DuckDBMaintenance] DB size: %2 KB -> %3 KB")
                            .arg(timestamp)
                            .arg(sizeBefore / 1024)
                            .arg(sizeAfter / 1024);

            for (int i = 0; i < optimizeIntervalSeconds && !stop_; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

private:
    std::shared_ptr<duckdb::Connection> con;
    QMutex mutex_;
    QWaitCondition waitCond_;
    bool stop_;
};

#endif // DUCKDBMAINTENANCETHREAD_H
