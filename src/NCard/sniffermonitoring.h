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
    explicit SnifferMonitoring(QString device, QObject *parent = nullptr)
        : QThread(parent), deviceName(device)
    {
    }
    ~SnifferMonitoring() {
        qDebug() << "SnifferMonitoring destructed";
    }
    void stopSniffing() {
        if (handle) {
            pcap_breakloop(handle);
            maintenanceThread->stop();
            maintenanceThread->deleteLater();
            insertThread->stop();
            insertThread->deleteLater();
            wait();
        }              }

protected:
    void run() override {
        insertThread->start();
        maintenanceThread->start();
        connect(this, &SnifferMonitoring::packetIsReadyToBeSentToDB,
                insertThread, &DuckDBInsertThread::addPacket);

        char errbuf[PCAP_ERRBUF_SIZE];
        char *deviceChar = deviceName.toLocal8Bit().data();

        if ((handle = pcap_open_live(deviceChar, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == nullptr) {
            qDebug() << "Unable to open the adapter:" << errbuf;
            return;
        }

        try {
            pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
        } catch (...) {
            pcap_close(handle);
            throw;
        }

        pcap_close(handle);
    }

signals:
    void packetCapturedUchar(const struct pcap_pkthdr*, const u_char*);
    void packetIsReadyToBeSentToDB(const struct pcap_pkthdr, const QByteArray);

private:
    static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

    DuckDBInsertThread* insertThread = new DuckDBInsertThread;
    DuckDBMaintenanceThread* maintenanceThread = new DuckDBMaintenanceThread(insertThread->getConnection());
    QString deviceName;
    pcap_t *handle = nullptr;
};

#endif // SNIFFERMONITORING_H
