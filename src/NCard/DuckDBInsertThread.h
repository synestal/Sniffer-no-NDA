#ifndef DUCKDBINSERTTHREAD_H
#define DUCKDBINSERTTHREAD_H

#include <QThread>
#include <QQueue>
#include <QMutex>
#include <Winsock2.h>
#include <QWaitCondition>
#include <QByteArray>
#include <QDateTime>
#include <QFile>
#include <QString>
#include <QDebug>
#include <QDir>
#include <QAtomicInt>
#include <QSemaphore>

#include <iostream>
#include <fstream>

#include "pcap.h"
#include "packages/service_pcap/misc.h"
#include <io.h>
#include <cstdio>
#include <iostream>
#include "duckdb.hpp"
#include "qdebug.h"

class DuckDBInsertThread : public QThread {
    Q_OBJECT
public:
    DuckDBInsertThread(std::string _filename, QObject* parent = nullptr);
    ~DuckDBInsertThread() override;
    void addPacket(const struct pcap_pkthdr header, const QByteArray data);
    void stop();
    int64_t getMaxId();
    static constexpr int maxQueueSize = 10000;
    std::shared_ptr<duckdb::Connection> getConnection() const;
    void adjustBatchSize(int newSize);

protected:
    void run() override;

signals:
    void insertCommited(int);
    void errorOccurred(const QString& errorMessage);

private:
    struct PacketInfo {
        // Ethernet
        QByteArray eth_src_mac;
        QByteArray eth_dst_mac;
        uint16_t eth_type = 0;

        // IP общее
        uint8_t ip_version = 0;

        // IPv4
        uint8_t ipv4_header_length = 0;
        uint8_t ipv4_tos = 0;
        uint16_t ipv4_total_length = 0;
        uint16_t ipv4_id = 0;
        uint16_t ipv4_flags_fragment = 0;
        uint8_t ipv4_ttl = 0;
        uint8_t ipv4_protocol = 0;
        uint16_t ipv4_checksum = 0;
        QByteArray ipv4_src_ip;
        QByteArray ipv4_dst_ip;

        // IPv6
        uint8_t ipv6_traffic_class = 0;
        uint32_t ipv6_flow_label = 0;
        uint16_t ipv6_payload_length = 0;
        uint8_t ipv6_next_header = 0;
        uint8_t ipv6_hop_limit = 0;
        QByteArray ipv6_src_ip;
        QByteArray ipv6_dst_ip;

        // TCP
        uint16_t tcp_src_port = 0;
        uint16_t tcp_dst_port = 0;
        uint32_t tcp_seq_num = 0;
        uint32_t tcp_ack_num = 0;
        uint8_t tcp_header_length = 0;
        uint8_t tcp_flags = 0;
        uint16_t tcp_window_size = 0;
        uint16_t tcp_checksum = 0;
        uint16_t tcp_urgent_pointer = 0;

        // UDP
        uint16_t udp_src_port = 0;
        uint16_t udp_dst_port = 0;
        uint16_t udp_length = 0;
        uint16_t udp_checksum = 0;

        // ICMP
        uint8_t icmp_type = 0;
        uint8_t icmp_code = 0;
        uint16_t icmp_checksum = 0;
        uint32_t icmp_rest_of_header = 0;

        // ARP
        uint16_t arp_hw_type = 0;
        uint16_t arp_protocol_type = 0;
        uint8_t arp_hw_size = 0;
        uint8_t arp_protocol_size = 0;
        uint16_t arp_opcode = 0;
        QByteArray arp_src_mac;
        QByteArray arp_src_ip;
        QByteArray arp_dst_mac;
        QByteArray arp_dst_ip;
    };
    PacketInfo extractPacketInfo(const QByteArray&);
    void parseTCP(const QByteArray&, int, PacketInfo&);
    void parseUDP(const QByteArray&, int, PacketInfo&);
    void parseICMP(const QByteArray&, int, PacketInfo&);
    bool initializeDatabase();
    void ensureTableExists();
    void appendBlobToRow(duckdb::Appender& appender, const void* data, size_t size);
    void processBatch(std::vector<std::tuple<pcap_pkthdr, QByteArray>>& batch);
    bool beginTransaction();
    bool commitTransaction();
    void rollbackTransaction();
    std::shared_ptr<duckdb::DuckDB> db;
    std::shared_ptr<duckdb::Connection> con;
    QQueue<QPair<pcap_pkthdr, QByteArray>> packetQueue_;
    std::string filename;
    QMutex mutex_;
    QWaitCondition cond_;
    QAtomicInt stop_;
    int batchSize;
    int waitTimeMs;
    bool transactionActive;
    QAtomicInt droppedPackets;
    QAtomicInt processedPackets;
};
#endif // DUCKDBINSERTTHREAD_H
