#ifndef SNIFFERMONITORING_H
#define SNIFFERMONITORING_H


#include <QThread>
#include <QDebug>
#include <QMainWindow>


#include <Winsock2.h>
#include <memory.h>


#include "pcap.h"
#include "packages/service_pcap/misc.h"


#include "clickhouse/client.h"

#include "ClickHouseInsertThread.h"
#include "packages/structs/typesAndStructs.h"


class SnifferMonitoring : public QThread {
    Q_OBJECT

public:
    explicit SnifferMonitoring(QString device, QObject *parent = nullptr)
        : QThread(parent), deviceName(device)
    {
        client = new clickhouse::Client(clickhouse::ClientOptions().SetHost("localhost"));
        insertThread = new ClickHouseInsertThread(client); // Теперь передаем client*
        insertThread->start();
    }
    ~SnifferMonitoring() {
        if (insertThread) {
            insertThread->quit();
            insertThread->wait();
            delete insertThread;
        }
        qDebug() << "destructed!!!!!!";
    }
    void stopSniffing() { if (handle) {
            pcap_breakloop(handle); wait();
        }               }

protected:
    void run() override {
        char errbuf[PCAP_ERRBUF_SIZE];
        char *deviceChar = deviceName.toLocal8Bit().data();

        if ((handle = pcap_open_live(deviceChar, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf)) == nullptr) {
            qDebug() << "Unable to open the adapter:" << errbuf;
            return;
        }

        client->Execute("CREATE TABLE IF NOT EXISTS packets (\
                       ts DateTime,\
                       caplen UInt32,\
                       len UInt32,\
                       data String\
                   ) ENGINE = MergeTree()\
                   ORDER BY ts;");

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

private:
    static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

    clickhouse::Client* client;
    ClickHouseInsertThread* insertThread;  // Поток для вставки данных
    QString deviceName = "";
    pcap_t *handle = nullptr;
};


#endif // SNIFFERMONITORING_H
