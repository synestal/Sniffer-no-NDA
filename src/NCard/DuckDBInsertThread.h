#ifndef DUCKDBINSERTTHREAD_H
#define DUCKDBINSERTTHREAD_H

#include <QThread>
#include <QQueue>
#include <QMutex>
#include <Winsock2.h>
#include <QWaitCondition>
#include <QByteArray>
#include <QFile>
#include <QString>
#include <QDebug>
#include <QDir>


#include "pcap.h"
#include "packages/service_pcap/misc.h"

#include "duckdb.hpp"

class DuckDBInsertThread : public QThread {
    Q_OBJECT
public:
    explicit DuckDBInsertThread(QObject* parent = nullptr)
        : QThread(parent), db(nullptr), con(nullptr), stop_(false) {
        db = std::make_shared<duckdb::DuckDB>("packets.db"); // Файл БД
        con = std::make_shared<duckdb::Connection>(*db);
        ensureTableExists();
        con->Query("PRAGMA memory_limit='100MB';");
    }
    ~DuckDBInsertThread() {
        stop();
        con.reset();
        db.reset();
    }
    void addPacket(const struct pcap_pkthdr header, const QByteArray data) {
        QMutexLocker locker(&mutex_);
        if (packetQueue_.size() >= maxQueueSize) {
            packetQueue_.dequeue();
        }
        packetQueue_.enqueue({ header, data });
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

    int64_t getMaxId() {
        try {
            auto result = con->Query("SELECT MAX(rowid) FROM packets;");
            if (!result->HasError() && result->RowCount() > 0) {
                return result->GetValue<int64_t>(0, 0);
            }
            return -1;
        } catch (const std::exception& e) {
            qWarning() << "Failed to get max id: " << e.what();
            return -1;
        }
    }

    static constexpr int maxQueueSize = 10000;
    std::shared_ptr<duckdb::Connection> getConnection() const {
        return con;
    }

protected:
    void run() override {
        constexpr int batchSize = 10000;
        constexpr int waitTimeMs = 10;
        while (true) {
            QMutexLocker locker(&mutex_);
            while (packetQueue_.isEmpty() && !stop_) {
                cond_.wait(&mutex_);
            }
            if (stop_ && packetQueue_.isEmpty()) break;
            int count = 0;
            std::vector<std::tuple<pcap_pkthdr, QByteArray>> batch;
            batch.reserve(batchSize);
            while (!packetQueue_.isEmpty() && count < batchSize) {
                auto pair = packetQueue_.dequeue();
                batch.push_back(std::make_tuple(pair.first, std::move(pair.second)));
                count++;
            }
            locker.unlock();
            if (!batch.empty()) {
                try {
                    con->Query("BEGIN TRANSACTION;");
                    {
                        duckdb::Appender appender(*con, "packets");
                        for (auto &[header, pkt_data] : batch) {
                            // Извлекаем тип пакета (13-й и 14-й байты)
                            QByteArray packetType;

                            if (pkt_data.size() > 13) {
                                uint8_t eth_type_1 = static_cast<uint8_t>(pkt_data[12]);
                                uint8_t eth_type_2 = static_cast<uint8_t>(pkt_data[13]);

                                // Добавляем этернет тип
                                packetType.append(static_cast<char>(eth_type_1));
                                packetType.append(static_cast<char>(eth_type_2));

                                // Проверяем на IPv4
                                if (eth_type_1 == 0x08 && eth_type_2 == 0x00 && pkt_data.size() > 23) {
                                    // Добавляем тип протокола IPv4 (24-й байт)
                                    packetType.append(pkt_data[23]);
                                }
                                // Проверяем на IPv6
                                else if (eth_type_1 == 0x86 && eth_type_2 == 0xDD && pkt_data.size() > 20) {
                                    // Добавляем тип протокола IPv6 (21-й байт)
                                    packetType.append(pkt_data[20]);
                                }
                            } else if (pkt_data.size() > 12) {
                                // Если есть только 13-й байт
                                packetType.append(pkt_data[12]);
                                packetType.append(static_cast<char>(0));
                            } else {
                                // Если пакет слишком короткий
                                packetType.append(static_cast<char>(0));
                                packetType.append(static_cast<char>(0));
                            }



                            PacketInfo info = extractPacketInfo(pkt_data);

                            appender.BeginRow();

                            appender.Append<int64_t>(header.ts.tv_sec);
                            appender.Append<uint16_t>(header.caplen);
                            appender.Append<uint16_t>(header.len);
                            // Добавляем тип пакета как BLOB
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(packetType.constData()), packetType.size()));


                            // Ethernet (канальный уровень)
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.eth_src_mac.constData()), info.eth_src_mac.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.eth_dst_mac.constData()), info.eth_dst_mac.size()));

                            // EtherType as BLOB
                            QByteArray eth_type_bytes(sizeof(uint16_t), 0);
                            memcpy(eth_type_bytes.data(), &info.eth_type, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(eth_type_bytes.constData()), eth_type_bytes.size()));

                            // IP version as BLOB
                            QByteArray ip_version_bytes(sizeof(uint8_t), 0);
                            memcpy(ip_version_bytes.data(), &info.ip_version, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ip_version_bytes.constData()), ip_version_bytes.size()));

                            // IPv4 fields as BLOBs
                            QByteArray ipv4_header_length_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv4_header_length_bytes.data(), &info.ipv4_header_length, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_header_length_bytes.constData()), ipv4_header_length_bytes.size()));

                            QByteArray ipv4_tos_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv4_tos_bytes.data(), &info.ipv4_tos, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_tos_bytes.constData()), ipv4_tos_bytes.size()));

                            QByteArray ipv4_total_length_bytes(sizeof(uint16_t), 0);
                            memcpy(ipv4_total_length_bytes.data(), &info.ipv4_total_length, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_total_length_bytes.constData()), ipv4_total_length_bytes.size()));

                            QByteArray ipv4_id_bytes(sizeof(uint16_t), 0);
                            memcpy(ipv4_id_bytes.data(), &info.ipv4_id, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_id_bytes.constData()), ipv4_id_bytes.size()));

                            QByteArray ipv4_flags_fragment_bytes(sizeof(uint16_t), 0);
                            memcpy(ipv4_flags_fragment_bytes.data(), &info.ipv4_flags_fragment, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_flags_fragment_bytes.constData()), ipv4_flags_fragment_bytes.size()));

                            QByteArray ipv4_ttl_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv4_ttl_bytes.data(), &info.ipv4_ttl, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_ttl_bytes.constData()), ipv4_ttl_bytes.size()));

                            QByteArray ipv4_protocol_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv4_protocol_bytes.data(), &info.ipv4_protocol, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_protocol_bytes.constData()), ipv4_protocol_bytes.size()));

                            QByteArray ipv4_checksum_bytes(sizeof(uint16_t), 0);
                            memcpy(ipv4_checksum_bytes.data(), &info.ipv4_checksum, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv4_checksum_bytes.constData()), ipv4_checksum_bytes.size()));

                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.ipv4_src_ip.constData()), info.ipv4_src_ip.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.ipv4_dst_ip.constData()), info.ipv4_dst_ip.size()));

                            // IPv6 fields as BLOBs
                            QByteArray ipv6_traffic_class_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv6_traffic_class_bytes.data(), &info.ipv6_traffic_class, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv6_traffic_class_bytes.constData()), ipv6_traffic_class_bytes.size()));

                            QByteArray ipv6_flow_label_bytes(sizeof(uint32_t), 0);
                            memcpy(ipv6_flow_label_bytes.data(), &info.ipv6_flow_label, sizeof(uint32_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv6_flow_label_bytes.constData()), ipv6_flow_label_bytes.size()));

                            QByteArray ipv6_payload_length_bytes(sizeof(uint16_t), 0);
                            memcpy(ipv6_payload_length_bytes.data(), &info.ipv6_payload_length, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv6_payload_length_bytes.constData()), ipv6_payload_length_bytes.size()));

                            QByteArray ipv6_next_header_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv6_next_header_bytes.data(), &info.ipv6_next_header, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv6_next_header_bytes.constData()), ipv6_next_header_bytes.size()));

                            QByteArray ipv6_hop_limit_bytes(sizeof(uint8_t), 0);
                            memcpy(ipv6_hop_limit_bytes.data(), &info.ipv6_hop_limit, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(ipv6_hop_limit_bytes.constData()), ipv6_hop_limit_bytes.size()));

                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.ipv6_src_ip.constData()), info.ipv6_src_ip.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.ipv6_dst_ip.constData()), info.ipv6_dst_ip.size()));

                            // TCP fields as BLOBs
                            QByteArray tcp_src_port_bytes(sizeof(uint16_t), 0);
                            memcpy(tcp_src_port_bytes.data(), &info.tcp_src_port, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_src_port_bytes.constData()), tcp_src_port_bytes.size()));

                            QByteArray tcp_dst_port_bytes(sizeof(uint16_t), 0);
                            memcpy(tcp_dst_port_bytes.data(), &info.tcp_dst_port, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_dst_port_bytes.constData()), tcp_dst_port_bytes.size()));

                            QByteArray tcp_seq_num_bytes(sizeof(uint32_t), 0);
                            memcpy(tcp_seq_num_bytes.data(), &info.tcp_seq_num, sizeof(uint32_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_seq_num_bytes.constData()), tcp_seq_num_bytes.size()));

                            QByteArray tcp_ack_num_bytes(sizeof(uint32_t), 0);
                            memcpy(tcp_ack_num_bytes.data(), &info.tcp_ack_num, sizeof(uint32_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_ack_num_bytes.constData()), tcp_ack_num_bytes.size()));

                            QByteArray tcp_header_length_bytes(sizeof(uint8_t), 0);
                            memcpy(tcp_header_length_bytes.data(), &info.tcp_header_length, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_header_length_bytes.constData()), tcp_header_length_bytes.size()));

                            QByteArray tcp_flags_bytes(sizeof(uint8_t), 0);
                            memcpy(tcp_flags_bytes.data(), &info.tcp_flags, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_flags_bytes.constData()), tcp_flags_bytes.size()));

                            QByteArray tcp_window_size_bytes(sizeof(uint16_t), 0);
                            memcpy(tcp_window_size_bytes.data(), &info.tcp_window_size, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_window_size_bytes.constData()), tcp_window_size_bytes.size()));

                            QByteArray tcp_checksum_bytes(sizeof(uint16_t), 0);
                            memcpy(tcp_checksum_bytes.data(), &info.tcp_checksum, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_checksum_bytes.constData()), tcp_checksum_bytes.size()));

                            QByteArray tcp_urgent_pointer_bytes(sizeof(uint16_t), 0);
                            memcpy(tcp_urgent_pointer_bytes.data(), &info.tcp_urgent_pointer, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(tcp_urgent_pointer_bytes.constData()), tcp_urgent_pointer_bytes.size()));

                            // UDP fields as BLOBs
                            QByteArray udp_src_port_bytes(sizeof(uint16_t), 0);
                            memcpy(udp_src_port_bytes.data(), &info.udp_src_port, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(udp_src_port_bytes.constData()), udp_src_port_bytes.size()));

                            QByteArray udp_dst_port_bytes(sizeof(uint16_t), 0);
                            memcpy(udp_dst_port_bytes.data(), &info.udp_dst_port, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(udp_dst_port_bytes.constData()), udp_dst_port_bytes.size()));

                            QByteArray udp_length_bytes(sizeof(uint16_t), 0);
                            memcpy(udp_length_bytes.data(), &info.udp_length, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(udp_length_bytes.constData()), udp_length_bytes.size()));

                            QByteArray udp_checksum_bytes(sizeof(uint16_t), 0);
                            memcpy(udp_checksum_bytes.data(), &info.udp_checksum, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(udp_checksum_bytes.constData()), udp_checksum_bytes.size()));

                            // ICMP fields as BLOBs
                            QByteArray icmp_type_bytes(sizeof(uint8_t), 0);
                            memcpy(icmp_type_bytes.data(), &info.icmp_type, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(icmp_type_bytes.constData()), icmp_type_bytes.size()));

                            QByteArray icmp_code_bytes(sizeof(uint8_t), 0);
                            memcpy(icmp_code_bytes.data(), &info.icmp_code, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(icmp_code_bytes.constData()), icmp_code_bytes.size()));

                            QByteArray icmp_checksum_bytes(sizeof(uint16_t), 0);
                            memcpy(icmp_checksum_bytes.data(), &info.icmp_checksum, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(icmp_checksum_bytes.constData()), icmp_checksum_bytes.size()));

                            QByteArray icmp_rest_of_header_bytes(sizeof(uint32_t), 0);
                            memcpy(icmp_rest_of_header_bytes.data(), &info.icmp_rest_of_header, sizeof(uint32_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(icmp_rest_of_header_bytes.constData()), icmp_rest_of_header_bytes.size()));

                            // ARP fields as BLOBs
                            QByteArray arp_hw_type_bytes(sizeof(uint16_t), 0);
                            memcpy(arp_hw_type_bytes.data(), &info.arp_hw_type, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(arp_hw_type_bytes.constData()), arp_hw_type_bytes.size()));

                            QByteArray arp_protocol_type_bytes(sizeof(uint16_t), 0);
                            memcpy(arp_protocol_type_bytes.data(), &info.arp_protocol_type, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(arp_protocol_type_bytes.constData()), arp_protocol_type_bytes.size()));

                            QByteArray arp_hw_size_bytes(sizeof(uint8_t), 0);
                            memcpy(arp_hw_size_bytes.data(), &info.arp_hw_size, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(arp_hw_size_bytes.constData()), arp_hw_size_bytes.size()));

                            QByteArray arp_protocol_size_bytes(sizeof(uint8_t), 0);
                            memcpy(arp_protocol_size_bytes.data(), &info.arp_protocol_size, sizeof(uint8_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(arp_protocol_size_bytes.constData()), arp_protocol_size_bytes.size()));

                            QByteArray arp_opcode_bytes(sizeof(uint16_t), 0);
                            memcpy(arp_opcode_bytes.data(), &info.arp_opcode, sizeof(uint16_t));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(arp_opcode_bytes.constData()), arp_opcode_bytes.size()));

                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.arp_src_mac.constData()), info.arp_src_mac.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.arp_src_ip.constData()), info.arp_src_ip.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.arp_dst_mac.constData()), info.arp_dst_mac.size()));
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(info.arp_dst_ip.constData()), info.arp_dst_ip.size()));

                            // Full packet payload
                            appender.Append(duckdb::Value::BLOB(
                                reinterpret_cast<duckdb::const_data_ptr_t>(pkt_data.constData()), pkt_data.size()));

                            appender.EndRow();
                        }
                        appender.Flush();
                        appender.Close();
                    }
                    con->Query("COMMIT;");
                    emit insertCommited(batch.size());
                } catch (const std::exception& e) {
                    qWarning() << "Exception in database operation: " << e.what();
                    con->Query("ROLLBACK;");
                }
            }
            if (count < batchSize) {
                std::this_thread::sleep_for(std::chrono::milliseconds(waitTimeMs));
            }
        }
    }

signals:
    void insertCommited(int);

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

    // Функция для извлечения всей информации из пакета
    PacketInfo extractPacketInfo(const QByteArray& pkt_data) {
        PacketInfo info;

        // Проверка на минимальную длину Ethernet заголовка (14 байт)
        if (pkt_data.size() < 14) {
            return info;
        }

        // Извлекаем MAC-адреса (Ethernet уровень)
        info.eth_dst_mac = pkt_data.mid(0, 6);
        info.eth_src_mac = pkt_data.mid(6, 6);

        // Извлекаем EtherType
        info.eth_type = static_cast<uint16_t>((static_cast<uint8_t>(pkt_data[12]) << 8) |
                                              static_cast<uint8_t>(pkt_data[13]));

        // Смещение для следующего заголовка
        int offset = 14;

        // Обработка в зависимости от типа протокола
        if (info.eth_type == 0x0800) {  // IPv4
            if (pkt_data.size() < offset + 20) {  // Минимальный размер IPv4 заголовка
                return info;
            }

            info.ip_version = (static_cast<uint8_t>(pkt_data[offset]) >> 4) & 0x0F;
            info.ipv4_header_length = (static_cast<uint8_t>(pkt_data[offset]) & 0x0F) * 4;  // в байтах
            info.ipv4_tos = static_cast<uint8_t>(pkt_data[offset + 1]);
            info.ipv4_total_length = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                                     static_cast<uint8_t>(pkt_data[offset + 3]);
            info.ipv4_id = (static_cast<uint8_t>(pkt_data[offset + 4]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 5]);
            info.ipv4_flags_fragment = (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                                     static_cast<uint8_t>(pkt_data[offset + 7]);
            info.ipv4_ttl = static_cast<uint8_t>(pkt_data[offset + 8]);
            info.ipv4_protocol = static_cast<uint8_t>(pkt_data[offset + 9]);
            info.ipv4_checksum = (static_cast<uint8_t>(pkt_data[offset + 10]) << 8) |
                               static_cast<uint8_t>(pkt_data[offset + 11]);
            info.ipv4_src_ip = pkt_data.mid(offset + 12, 4);
            info.ipv4_dst_ip = pkt_data.mid(offset + 16, 4);

            int transport_offset = offset + info.ipv4_header_length;

            // Обработка транспортного уровня
            if (info.ipv4_protocol == 6 && pkt_data.size() >= transport_offset + 20) {  // TCP
                parseTCP(pkt_data, transport_offset, info);
            } else if (info.ipv4_protocol == 17 && pkt_data.size() >= transport_offset + 8) {  // UDP
                parseUDP(pkt_data, transport_offset, info);
            } else if (info.ipv4_protocol == 1 && pkt_data.size() >= transport_offset + 8) {  // ICMP
                parseICMP(pkt_data, transport_offset, info);
            }

        } else if (info.eth_type == 0x86DD) {  // IPv6
            if (pkt_data.size() < offset + 40) {  // Фиксированный размер IPv6 заголовка
                return info;
            }

            info.ip_version = (static_cast<uint8_t>(pkt_data[offset]) >> 4) & 0x0F;
            uint8_t tc_high = static_cast<uint8_t>(pkt_data[offset]) & 0x0F;
            uint8_t tc_low = (static_cast<uint8_t>(pkt_data[offset + 1]) >> 4) & 0x0F;
            info.ipv6_traffic_class = (tc_high << 4) | tc_low;

            uint32_t flow_high = static_cast<uint8_t>(pkt_data[offset + 1]) & 0x0F;
            uint32_t flow_mid = static_cast<uint8_t>(pkt_data[offset + 2]);
            uint32_t flow_low = static_cast<uint8_t>(pkt_data[offset + 3]);
            info.ipv6_flow_label = (flow_high << 16) | (flow_mid << 8) | flow_low;

            info.ipv6_payload_length = (static_cast<uint8_t>(pkt_data[offset + 4]) << 8) |
                                     static_cast<uint8_t>(pkt_data[offset + 5]);
            info.ipv6_next_header = static_cast<uint8_t>(pkt_data[offset + 6]);
            info.ipv6_hop_limit = static_cast<uint8_t>(pkt_data[offset + 7]);

            info.ipv6_src_ip = pkt_data.mid(offset + 8, 16);
            info.ipv6_dst_ip = pkt_data.mid(offset + 24, 16);

            int transport_offset = offset + 40;  // IPv6 заголовок фиксированного размера 40 байт

            // Обработка транспортного уровня
            if (info.ipv6_next_header == 6 && pkt_data.size() >= transport_offset + 20) {  // TCP
                parseTCP(pkt_data, transport_offset, info);
            } else if (info.ipv6_next_header == 17 && pkt_data.size() >= transport_offset + 8) {  // UDP
                parseUDP(pkt_data, transport_offset, info);
            } else if (info.ipv6_next_header == 58 && pkt_data.size() >= transport_offset + 8) {  // ICMPv6
                parseICMP(pkt_data, transport_offset, info);
            }

        } else if (info.eth_type == 0x0806) {  // ARP
            if (pkt_data.size() < offset + 28) {  // Минимальный размер ARP
                return info;
            }

            info.arp_hw_type = (static_cast<uint8_t>(pkt_data[offset]) << 8) |
                             static_cast<uint8_t>(pkt_data[offset + 1]);
            info.arp_protocol_type = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                                  static_cast<uint8_t>(pkt_data[offset + 3]);
            info.arp_hw_size = static_cast<uint8_t>(pkt_data[offset + 4]);
            info.arp_protocol_size = static_cast<uint8_t>(pkt_data[offset + 5]);
            info.arp_opcode = (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                           static_cast<uint8_t>(pkt_data[offset + 7]);

            // Для IPv4 + Ethernet
            if (info.arp_hw_size == 6 && info.arp_protocol_size == 4) {
                info.arp_src_mac = pkt_data.mid(offset + 8, 6);
                info.arp_src_ip = pkt_data.mid(offset + 14, 4);
                info.arp_dst_mac = pkt_data.mid(offset + 18, 6);
                info.arp_dst_ip = pkt_data.mid(offset + 24, 4);
            }
        }

        return info;
    }

    void parseTCP(const QByteArray& pkt_data, int offset, PacketInfo& info) {
        info.tcp_src_port = (static_cast<uint8_t>(pkt_data[offset]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 1]);
        info.tcp_dst_port = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 3]);

        info.tcp_seq_num = (static_cast<uint8_t>(pkt_data[offset + 4]) << 24) |
                         (static_cast<uint8_t>(pkt_data[offset + 5]) << 16) |
                         (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                         static_cast<uint8_t>(pkt_data[offset + 7]);

        info.tcp_ack_num = (static_cast<uint8_t>(pkt_data[offset + 8]) << 24) |
                         (static_cast<uint8_t>(pkt_data[offset + 9]) << 16) |
                         (static_cast<uint8_t>(pkt_data[offset + 10]) << 8) |
                         static_cast<uint8_t>(pkt_data[offset + 11]);

        info.tcp_header_length = ((static_cast<uint8_t>(pkt_data[offset + 12]) >> 4) & 0x0F) * 4;  // в байтах
        info.tcp_flags = (static_cast<uint8_t>(pkt_data[offset + 13]));

        info.tcp_window_size = (static_cast<uint8_t>(pkt_data[offset + 14]) << 8) |
                             static_cast<uint8_t>(pkt_data[offset + 15]);

        info.tcp_checksum = (static_cast<uint8_t>(pkt_data[offset + 16]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 17]);

        info.tcp_urgent_pointer = (static_cast<uint8_t>(pkt_data[offset + 18]) << 8) |
                                static_cast<uint8_t>(pkt_data[offset + 19]);
    }

    void parseUDP(const QByteArray& pkt_data, int offset, PacketInfo& info) {
        info.udp_src_port = (static_cast<uint8_t>(pkt_data[offset]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 1]);

        info.udp_dst_port = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 3]);

        info.udp_length = (static_cast<uint8_t>(pkt_data[offset + 4]) << 8) |
                        static_cast<uint8_t>(pkt_data[offset + 5]);

        info.udp_checksum = (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                          static_cast<uint8_t>(pkt_data[offset + 7]);
    }

    void parseICMP(const QByteArray& pkt_data, int offset, PacketInfo& info) {
        info.icmp_type = static_cast<uint8_t>(pkt_data[offset]);
        info.icmp_code = static_cast<uint8_t>(pkt_data[offset + 1]);

        info.icmp_checksum = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                           static_cast<uint8_t>(pkt_data[offset + 3]);

        // Оставшиеся 4 байта заголовка (зависит от типа)
        info.icmp_rest_of_header = (static_cast<uint8_t>(pkt_data[offset + 4]) << 24) |
                                 (static_cast<uint8_t>(pkt_data[offset + 5]) << 16) |
                                 (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                                 static_cast<uint8_t>(pkt_data[offset + 7]);
    }

    void ensureTableExists() {
        try {
            qDebug() << "Using DB at:" << QDir::currentPath();
            con->Query(
                "CREATE TABLE IF NOT EXISTS packets ("
                "ts INTEGER, "
                "caplen SMALLINT, "
                "len SMALLINT, "
                "packet_type BLOB, "

                // Ethernet
                "eth_src_mac BLOB, "
                "eth_dst_mac BLOB, "
                "eth_type BLOB, "

                // IP общее
                "ip_version BLOB, "

                // IPv4
                "ipv4_header_length BLOB, "
                "ipv4_tos BLOB, "
                "ipv4_total_length BLOB, "
                "ipv4_id BLOB, "
                "ipv4_flags_fragment BLOB, "
                "ipv4_ttl BLOB, "
                "ipv4_protocol BLOB, "
                "ipv4_checksum BLOB, "
                "ipv4_src_ip BLOB, "
                "ipv4_dst_ip BLOB, "

                // IPv6
                "ipv6_traffic_class BLOB, "
                "ipv6_flow_label BLOB, "
                "ipv6_payload_length BLOB, "
                "ipv6_next_header BLOB, "
                "ipv6_hop_limit BLOB, "
                "ipv6_src_ip BLOB, "
                "ipv6_dst_ip BLOB, "

                // TCP
                "tcp_src_port BLOB, "
                "tcp_dst_port BLOB, "
                "tcp_seq_num BLOB, "
                "tcp_ack_num BLOB, "
                "tcp_header_length BLOB, "
                "tcp_flags BLOB, "
                "tcp_window_size BLOB, "
                "tcp_checksum BLOB, "
                "tcp_urgent_pointer BLOB, "

                // UDP
                "udp_src_port BLOB, "
                "udp_dst_port BLOB, "
                "udp_length BLOB, "
                "udp_checksum BLOB, "

                // ICMP
                "icmp_type BLOB, "
                "icmp_code BLOB, "
                "icmp_checksum BLOB, "
                "icmp_rest_of_header BLOB, "

                // ARP
                "arp_hw_type BLOB, "
                "arp_protocol_type BLOB, "
                "arp_hw_size BLOB, "
                "arp_protocol_size BLOB, "
                "arp_opcode BLOB, "
                "arp_src_mac BLOB, "
                "arp_src_ip BLOB, "
                "arp_dst_mac BLOB, "
                "arp_dst_ip BLOB, "

                // Полезная нагрузка
                "data BLOB"
                ") WITH (compression='zlib');"
            );
        } catch (const std::exception& e) {
            qWarning() << "Failed to create table: " << e.what();
        }
    }

    std::shared_ptr<duckdb::DuckDB> db;
    std::shared_ptr<duckdb::Connection> con;
    QQueue<QPair<pcap_pkthdr, QByteArray>> packetQueue_;
    QMutex mutex_;
    QWaitCondition cond_;
    bool stop_;
};

#endif // DUCKDBINSERTTHREAD_H
