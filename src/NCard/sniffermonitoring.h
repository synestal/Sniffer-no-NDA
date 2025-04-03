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


#include "packages/structs/typesAndStructs.h"


class SnifferMonitoring : public QThread {
    Q_OBJECT

public:
    SnifferMonitoring(QString device, QObject *parent = nullptr) : QThread(parent), deviceName(device) {};
    ~SnifferMonitoring() {qDebug() << "destructed!!!!!!";}
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
        dumper = pcap_dump_open(handle, "C:/Users/kostr/Documents/TestDiploma/output.pcap");
        if (!dumper) {
            qDebug() << "Ошибка открытия PCAP файла для записи:" << pcap_geterr(handle);
            pcap_close(handle);
            return;
        }

        clickhouse::Client client(
            clickhouse::ClientOptions().SetHost("localhost")
        );

        client.Execute("CREATE TABLE test (id UInt64) ENGINE = Memory");

        try {
            pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
        } catch (...) {
            pcap_close(handle);
            pcap_dump_close(dumper);
            throw;
        }

        pcap_close(handle);
        pcap_dump_close(dumper);
    }

signals:
    void packetCapturedUchar(const struct pcap_pkthdr*, const u_char*);

private:
    static void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


    QString deviceName = "";
    pcap_t *handle = nullptr;
    pcap_dumper_t *dumper = nullptr;
};


#endif // SNIFFERMONITORING_H
