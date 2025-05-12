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
    DuckDBMaintenanceThread(std::shared_ptr<duckdb::Connection> connection, QString _dbPath, QObject* parent = nullptr)
        : QThread(parent), con(connection), dbPath(_dbPath), stop_(false) {}

    ~DuckDBMaintenanceThread() override {
            stop();
        }
    void stop() {
        {
            QMutexLocker locker(&mutex_);
            stop_ = true;
            waitCond_.wakeOne();
        }
        if (isRunning()) { wait(); }
    }
protected:
    void run() override {
        constexpr int optimizeIntervalSeconds = 60;
        constexpr int vacuumEveryN = 5;
        int counter = 0;
        while (true) {
            {
                QMutexLocker locker(&mutex_);
                if (stop_) { break; }
            }
            QFileInfo dbInfo(dbPath);
            qint64 sizeBefore = dbInfo.size();
            QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
            qDebug() << QString("[%1] [DuckDBMaintenance] Starting optimization (cycle %2)...")
                            .arg(timestamp).arg(counter + 1);
            {
                QMutexLocker locker(&mutex_);
                if (con) {
                    con->Query("PRAGMA optimize;");
                    con->Query("ANALYZE;");
                    if (++counter % vacuumEveryN == 0) {
                        qDebug() << QString("[%1] [DuckDBMaintenance] Running VACUUM...").arg(timestamp);
                        con->Query("VACUUM;");
                    }
                }
            }
            dbInfo.refresh();
            qint64 sizeAfter = dbInfo.size();
            qDebug() << QString("[%1] [DuckDBMaintenance] DB size: %2 KB -> %3 KB")
                                        .arg(timestamp)
                                        .arg(sizeBefore / 1024)
                                        .arg(sizeAfter / 1024);
            {
                QMutexLocker locker(&mutex_);
                if (!stop_)
                    waitCond_.wait(&mutex_, optimizeIntervalSeconds * 1000);
            }
        }
    }
private:
    std::shared_ptr<duckdb::Connection> con;
    QMutex mutex_;
    QWaitCondition waitCond_;
    QString dbPath = ",packets.db";
    bool stop_;
};

#endif // DUCKDBMAINTENANCETHREAD_H
