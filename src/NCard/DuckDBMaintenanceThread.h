#ifndef DUCKDBMAINTENANCETHREAD_H
#define DUCKDBMAINTENANCETHREAD_H

#include <QThread>
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
        constexpr int optimizeIntervalSeconds = 30;
        constexpr int vacuumIntervalSeconds = 300;

        int counter = 0;

        while (true) {
            {
                QMutexLocker locker(&mutex_);
                if (stop_) break;
            }

            if (counter % (vacuumIntervalSeconds / optimizeIntervalSeconds) == 0) {
                qDebug() << "[DuckDBMaintenance] Running VACUUM...";
                con->Query("VACUUM;");
            } else {
                qDebug() << "[DuckDBMaintenance] Running PRAGMA optimize...";
                con->Query("PRAGMA optimize;");
            }

            for (int i = 0; i < optimizeIntervalSeconds; ++i) {
                QMutexLocker locker(&mutex_);
                if (stop_) return;
                waitCond_.wait(&mutex_, 1000);
            }

            counter++;
        }
    }

private:
    std::shared_ptr<duckdb::Connection> con;
    QMutex mutex_;
    QWaitCondition waitCond_;
    bool stop_;
};

#endif // DUCKDBMAINTENANCETHREAD_H
