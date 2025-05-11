#ifndef SNIFFERMONITORING_H
#define SNIFFERMONITORING_H


#include <QThread>
#include <QDebug>
#include <QMainWindow>


#include <Winsock2.h>
#include <memory.h>


#include "pcap.h"
#include "packages/service_pcap/misc.h"


#include "DuckDBInsertThread.h"
#include "DuckDBMaintenanceThread.h"
#include "packages/structs/typesAndStructs.h"


class SnifferMonitoring : public QThread {
    Q_OBJECT

public:
    explicit SnifferMonitoring(QString device, std::string _filename, QObject *parent = nullptr)
        : QThread(parent), filename(_filename), deviceName(std::move(device))
    {
        insertThread = new DuckDBInsertThread(filename);
        maintenanceThread = new DuckDBMaintenanceThread(insertThread->getConnection(), QString::fromStdString(filename));
    }
    ~SnifferMonitoring() override {
        stopSniffing();
        qDebug() << "SnifferMonitoring destructed";
    }
    void stopSniffing() {
        if (handle) {
            pcap_breakloop(handle);
            handle = nullptr;
        }
        if (maintenanceThread) {
            maintenanceThread->stop();
            maintenanceThread->wait();
            delete maintenanceThread;
            maintenanceThread = nullptr;
        }
        if (insertThread) {
            insertThread->stop();
            insertThread->wait();
            delete insertThread;
            insertThread = nullptr;
        }
        if (isRunning()) { wait(); }
    }
    void setFilename (std::string _filename) {
        filename = std::move(_filename);
    }
    int count = 0;
protected:
    void run() override {
        if (!insertThread || !maintenanceThread) {
            qWarning() << "Threads not initialized.";
            return;
        }
        insertThread->start();
        count = insertThread->getMaxId();
        maintenanceThread->start();
        connect(this, &SnifferMonitoring::packetIsReadyToBeSentToDB,
                insertThread, &DuckDBInsertThread::addPacket);
        connect(insertThread, &DuckDBInsertThread::insertCommited, this, [this](int x){count += x;});

        QByteArray deviceArray = deviceName.toLocal8Bit();
        const char *deviceChar = deviceArray.constData();
        char errbuf[PCAP_ERRBUF_SIZE] = {};
        handle = pcap_open_live(deviceChar, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
        if (!handle) {
            qDebug() << "Unable to open the adapter:" << errbuf;
            return;
        }
        try {
            pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
        } catch (...) {
            qWarning() << "Exception inside pcap_loop";
        }
        if (handle) {
            pcap_close(handle);
            handle = nullptr;
        }
    }
signals:
    void packetCapturedUchar(int, std::shared_ptr<duckdb::Connection>);
    void packetIsReadyToBeSentToDB(const struct pcap_pkthdr, const QByteArray);

private:
    std::string filename;
    static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    DuckDBInsertThread* insertThread = nullptr;
    DuckDBMaintenanceThread* maintenanceThread = nullptr;
    QString deviceName;
    pcap_t *handle = nullptr;
};

#endif // SNIFFERMONITORING_H
