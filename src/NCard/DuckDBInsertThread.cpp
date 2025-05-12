#include "DuckDBInsertThread.h"

DuckDBInsertThread::DuckDBInsertThread(std::string _filename, QObject* parent)
    : QThread(parent),
      db(nullptr),
      con(nullptr),
      filename(_filename),
      stop_(false),
      batchSize(10000),
      waitTimeMs(10),
      transactionActive(false),
      droppedPackets(0),
      processedPackets(0) {
    if (!initializeDatabase()) {
        qWarning() << "Failed to initialize database";
        stop_ = true;
    }
}

DuckDBInsertThread::~DuckDBInsertThread() {
    stop();
    if (con) {
        try {
            if (transactionActive) {
                rollbackTransaction();
            }
            con->Commit();
            } catch (const std::exception& e) {
                qWarning() << "Exception during connection cleanup in destructor: " << e.what();
        } catch (...) {
            qWarning() << "Unknown exception during connection cleanup in destructor";
        }
    }
    try {
        con.reset();
        db.reset();
    } catch (...) {
        qWarning() << "Exception during pointer cleanup in destructor";
    }
}

std::shared_ptr<duckdb::Connection> DuckDBInsertThread::getConnection() const {
    return con;
}

bool DuckDBInsertThread::initializeDatabase() {
    try {
        db = std::make_shared<duckdb::DuckDB>(filename);
        if (!db) {
            emit errorOccurred("Failed to create database");
            return false;
        }
        con = std::make_shared<duckdb::Connection>(*db);
        if (!con) {
            db.reset();
            emit errorOccurred("Failed to create database connection");
            return false;
        }
        con->Query("PRAGMA memory_limit='100MB';");
        ensureTableExists();
        return true;
    } catch (const std::exception &e) {
        emit errorOccurred(QString("Database initialization error: %1").arg(e.what()));
        return false;
    }
}

void DuckDBInsertThread::addPacket(const struct pcap_pkthdr header, const QByteArray data) {
    QMutexLocker locker(&mutex_);
    if (packetQueue_.size() >= maxQueueSize) {
        packetQueue_.dequeue();
        droppedPackets.fetchAndAddRelaxed(1);
        static QAtomicInt dropNotifyCounter(0);
        if (dropNotifyCounter.fetchAndAddRelaxed(1) % 1000 == 0) {
            emit errorOccurred(QString("Queue overflow: %1 packets dropped").arg(droppedPackets.loadRelaxed()));
        }
    }
    packetQueue_.enqueue({ header, data });
    cond_.wakeOne();
}

void DuckDBInsertThread::stop() {
    stop_.storeRelease(true);
    {
        QMutexLocker locker(&mutex_);
        cond_.wakeAll();
    }
    if (isRunning()) {
        if (!wait(5000)) {
            qWarning() << "Thread did not terminate gracefully, forcing termination";
            terminate();
            wait();
        }
    }
}
int64_t DuckDBInsertThread::getMaxId() {
    if (!con) return -1;
    try {
        auto result = con->Query("SELECT MAX(rowid) FROM packets;");
        if (!result->HasError() && result->RowCount() > 0) {
            return result->GetValue<int64_t>(0, 0);
        }
        return 0;
    } catch (const std::exception& e) {
        qWarning() << "Failed to get max id: " << e.what();
        return -1;
    }
}
void DuckDBInsertThread::adjustBatchSize(int newSize) {
    QMutexLocker locker(&mutex_);
    if (newSize > 0 && newSize <= 100000) {
        batchSize = newSize;
    }
}
bool DuckDBInsertThread::beginTransaction() {
    if (!con) return false;
    try {
        con->Query("BEGIN TRANSACTION;");
        transactionActive = true;
        return true;
    } catch (const std::exception& e) {
        qWarning() << "Failed to begin transaction: " << e.what();
        transactionActive = false;
        return false;
    }
}
bool DuckDBInsertThread::commitTransaction() {
    if (!con || !transactionActive) return false;
    try {
        con->Query("COMMIT;");
        transactionActive = false;
        return true;
    } catch (const std::exception& e) {
        qWarning() << "Failed to commit transaction: " << e.what();
        rollbackTransaction();
        return false;
    }
}

void DuckDBInsertThread::rollbackTransaction() {
    if (!con || !transactionActive) return;
    try {
        con->Query("ROLLBACK;");
    } catch (const std::exception& e) {
        qWarning() << "Failed to rollback transaction: " << e.what();
    }
    transactionActive = false;
}

void DuckDBInsertThread::run() {
    if (!con || stop_.loadAcquire()) return;
    std::vector<std::tuple<pcap_pkthdr, QByteArray>> batch;
    batch.reserve(batchSize);
    while (!stop_.loadAcquire()) {
        {
            QMutexLocker locker(&mutex_);
                        if (stop_.loadAcquire()) break;
                        if (packetQueue_.isEmpty()) {
                            if (!cond_.wait(&mutex_, waitTimeMs)) {
                                if (stop_.loadAcquire()) break;
                                continue;
                            }
                        }
                        int currentBatchSize = batchSize;
                        int count = 0;
                        while (!packetQueue_.isEmpty() && count < currentBatchSize) {
                            auto pair = packetQueue_.dequeue();
                            batch.push_back(std::make_tuple(pair.first, std::move(pair.second)));
                            count++;
                        }
        }
        if (!batch.empty()) {
            try {
                processBatch(batch);
            } catch (const std::exception& e) {
                qWarning() << "Exception processing batch: " << e.what();
                emit errorOccurred(QString("Batch processing error: %1").arg(e.what()));
            }
            batch.clear();
        }
    }
    if (!batch.empty()) {
        try {
            processBatch(batch);
            batch.clear();
        } catch (const std::exception& e) {
            qWarning() << "Exception processing final batch: " << e.what();
            emit errorOccurred(QString("Final batch processing error: %1").arg(e.what()));
        }
    }
}
void DuckDBInsertThread::processBatch(std::vector<std::tuple<pcap_pkthdr, QByteArray>>& batch) {
    if (!con || batch.empty()) return;
    try {
        if (!beginTransaction()) return;
        duckdb::Appender appender(*con, "packets");
        for (auto& [header, pkt_data] : batch) {
            QByteArray packetType;
            if (pkt_data.size() > 13) {
                uint8_t eth_type_1 = static_cast<uint8_t>(pkt_data[12]);
                uint8_t eth_type_2 = static_cast<uint8_t>(pkt_data[13]);
                packetType.append(static_cast<char>(eth_type_1));
                packetType.append(static_cast<char>(eth_type_2));
                // Check for IPv4
                if (eth_type_1 == 0x08 && eth_type_2 == 0x00 && pkt_data.size() > 23) {
                    packetType.append(pkt_data[23]);
                }
                // Check for IPv6
                else if (eth_type_1 == 0x86 && eth_type_2 == 0xDD && pkt_data.size() > 20) {
                    packetType.append(pkt_data[20]);
                }
            } else if (pkt_data.size() > 12) {
                packetType.append(pkt_data[12]);
                packetType.append(static_cast<char>(0));
            } else {
                packetType.append(static_cast<char>(0));
                packetType.append(static_cast<char>(0));
            }
            // Extract packet information
            PacketInfo info = extractPacketInfo(pkt_data);

            // Begin row insertion
            appender.BeginRow();

            // Basic fields
            appender.Append<int64_t>(header.ts.tv_sec);
            appender.Append<uint16_t>(header.caplen);
            appender.Append<uint16_t>(header.len);

            // Packet type
            appendBlobToRow(appender, packetType.constData(), packetType.size());

            // Ethernet fields
            appendBlobToRow(appender, info.eth_src_mac.constData(), info.eth_src_mac.size());
            appendBlobToRow(appender, info.eth_dst_mac.constData(), info.eth_dst_mac.size());
            appendBlobToRow(appender, &info.eth_type, sizeof(info.eth_type));

            // IP version
            appendBlobToRow(appender, &info.ip_version, sizeof(info.ip_version));

            // IPv4 fields
            appendBlobToRow(appender, &info.ipv4_header_length, sizeof(info.ipv4_header_length));
            appendBlobToRow(appender, &info.ipv4_tos, sizeof(info.ipv4_tos));
            appendBlobToRow(appender, &info.ipv4_total_length, sizeof(info.ipv4_total_length));
            appendBlobToRow(appender, &info.ipv4_id, sizeof(info.ipv4_id));
            appendBlobToRow(appender, &info.ipv4_flags_fragment, sizeof(info.ipv4_flags_fragment));
            appendBlobToRow(appender, &info.ipv4_ttl, sizeof(info.ipv4_ttl));
            appendBlobToRow(appender, &info.ipv4_protocol, sizeof(info.ipv4_protocol));
            appendBlobToRow(appender, &info.ipv4_checksum, sizeof(info.ipv4_checksum));
            appendBlobToRow(appender, info.ipv4_src_ip.constData(), info.ipv4_src_ip.size());
            appendBlobToRow(appender, info.ipv4_dst_ip.constData(), info.ipv4_dst_ip.size());

            // IPv6 fields
            appendBlobToRow(appender, &info.ipv6_traffic_class, sizeof(info.ipv6_traffic_class));
            appendBlobToRow(appender, &info.ipv6_flow_label, sizeof(info.ipv6_flow_label));
            appendBlobToRow(appender, &info.ipv6_payload_length, sizeof(info.ipv6_payload_length));
            appendBlobToRow(appender, &info.ipv6_next_header, sizeof(info.ipv6_next_header));
            appendBlobToRow(appender, &info.ipv6_hop_limit, sizeof(info.ipv6_hop_limit));
            appendBlobToRow(appender, info.ipv6_src_ip.constData(), info.ipv6_src_ip.size());
            appendBlobToRow(appender, info.ipv6_dst_ip.constData(), info.ipv6_dst_ip.size());

            // TCP fields
            appendBlobToRow(appender, &info.tcp_src_port, sizeof(info.tcp_src_port));
            appendBlobToRow(appender, &info.tcp_dst_port, sizeof(info.tcp_dst_port));
            appendBlobToRow(appender, &info.tcp_seq_num, sizeof(info.tcp_seq_num));
            appendBlobToRow(appender, &info.tcp_ack_num, sizeof(info.tcp_ack_num));
            appendBlobToRow(appender, &info.tcp_header_length, sizeof(info.tcp_header_length));
            appendBlobToRow(appender, &info.tcp_flags, sizeof(info.tcp_flags));
            appendBlobToRow(appender, &info.tcp_window_size, sizeof(info.tcp_window_size));
            appendBlobToRow(appender, &info.tcp_checksum, sizeof(info.tcp_checksum));
            appendBlobToRow(appender, &info.tcp_urgent_pointer, sizeof(info.tcp_urgent_pointer));

            // UDP fields
            appendBlobToRow(appender, &info.udp_src_port, sizeof(info.udp_src_port));
            appendBlobToRow(appender, &info.udp_dst_port, sizeof(info.udp_dst_port));
            appendBlobToRow(appender, &info.udp_length, sizeof(info.udp_length));
            appendBlobToRow(appender, &info.udp_checksum, sizeof(info.udp_checksum));

            // ICMP fields
            appendBlobToRow(appender, &info.icmp_type, sizeof(info.icmp_type));
            appendBlobToRow(appender, &info.icmp_code, sizeof(info.icmp_code));
            appendBlobToRow(appender, &info.icmp_checksum, sizeof(info.icmp_checksum));
            appendBlobToRow(appender, &info.icmp_rest_of_header, sizeof(info.icmp_rest_of_header));

            // ARP fields
            appendBlobToRow(appender, &info.arp_hw_type, sizeof(info.arp_hw_type));
            appendBlobToRow(appender, &info.arp_protocol_type, sizeof(info.arp_protocol_type));
            appendBlobToRow(appender, &info.arp_hw_size, sizeof(info.arp_hw_size));
            appendBlobToRow(appender, &info.arp_protocol_size, sizeof(info.arp_protocol_size));
            appendBlobToRow(appender, &info.arp_opcode, sizeof(info.arp_opcode));
            appendBlobToRow(appender, info.arp_src_mac.constData(), info.arp_src_mac.size());
            appendBlobToRow(appender, info.arp_src_ip.constData(), info.arp_src_ip.size());
            appendBlobToRow(appender, info.arp_dst_mac.constData(), info.arp_dst_mac.size());
            appendBlobToRow(appender, info.arp_dst_ip.constData(), info.arp_dst_ip.size());

            // Full packet data
            appendBlobToRow(appender, pkt_data.constData(), pkt_data.size());
            appender.EndRow();
            processedPackets.fetchAndAddRelaxed(1);
        }
        appender.Flush();
        appender.Close();
        if (commitTransaction()) {
            emit insertCommited(batch.size());
        }
    } catch (const std::exception& e) {
        qWarning() << "Exception in database operation: " << e.what();
        rollbackTransaction();
        emit errorOccurred(QString("Database error: %1").arg(e.what()));
    }
}

void DuckDBInsertThread::appendBlobToRow(duckdb::Appender& appender, const void* data, size_t size) {
    appender.Append(duckdb::Value::BLOB(
        reinterpret_cast<duckdb::const_data_ptr_t>(data), size));
}

void DuckDBInsertThread::parseTCP(const QByteArray& pkt_data, int offset, PacketInfo& info) {
    if (pkt_data.size() < offset + 20) return;
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
    info.tcp_header_length = ((static_cast<uint8_t>(pkt_data[offset + 12]) >> 4) & 0x0F) * 4;  // in bytes
    info.tcp_flags = (static_cast<uint8_t>(pkt_data[offset + 13]));
    info.tcp_window_size = (static_cast<uint8_t>(pkt_data[offset + 14]) << 8) |
                         static_cast<uint8_t>(pkt_data[offset + 15]);
    info.tcp_checksum = (static_cast<uint8_t>(pkt_data[offset + 16]) << 8) |
                      static_cast<uint8_t>(pkt_data[offset + 17]);
    info.tcp_urgent_pointer = (static_cast<uint8_t>(pkt_data[offset + 18]) << 8) |
                            static_cast<uint8_t>(pkt_data[offset + 19]);
}

void DuckDBInsertThread::parseUDP(const QByteArray& pkt_data, int offset, PacketInfo& info) {
    if (pkt_data.size() < offset + 8) return;
    info.udp_src_port = (static_cast<uint8_t>(pkt_data[offset]) << 8) |
                      static_cast<uint8_t>(pkt_data[offset + 1]);
    info.udp_dst_port = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                      static_cast<uint8_t>(pkt_data[offset + 3]);
    info.udp_length = (static_cast<uint8_t>(pkt_data[offset + 4]) << 8) |
                    static_cast<uint8_t>(pkt_data[offset + 5]);
    info.udp_checksum = (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                      static_cast<uint8_t>(pkt_data[offset + 7]);
}

void DuckDBInsertThread::parseICMP(const QByteArray& pkt_data, int offset, PacketInfo& info) {
    if (pkt_data.size() < offset + 8) return;
    info.icmp_type = static_cast<uint8_t>(pkt_data[offset]);
    info.icmp_code = static_cast<uint8_t>(pkt_data[offset + 1]);
    info.icmp_checksum = (static_cast<uint8_t>(pkt_data[offset + 2]) << 8) |
                       static_cast<uint8_t>(pkt_data[offset + 3]);
    info.icmp_rest_of_header = (static_cast<uint8_t>(pkt_data[offset + 4]) << 24) |
                             (static_cast<uint8_t>(pkt_data[offset + 5]) << 16) |
                             (static_cast<uint8_t>(pkt_data[offset + 6]) << 8) |
                             static_cast<uint8_t>(pkt_data[offset + 7]);
}

DuckDBInsertThread::PacketInfo DuckDBInsertThread::extractPacketInfo(const QByteArray& pkt_data) {
    PacketInfo info;
    if (pkt_data.size() < 14) {
        return info;
    }

    info.eth_dst_mac = pkt_data.mid(0, 6);
    info.eth_src_mac = pkt_data.mid(6, 6);

    info.eth_type = static_cast<uint16_t>((static_cast<uint8_t>(pkt_data[12]) << 8) |
                                          static_cast<uint8_t>(pkt_data[13]));

    int offset = 14;
    if (info.eth_type == 0x0800) {  // IPv4
        if (pkt_data.size() < offset + 20) {  // Minimum IPv4 header size
            return info;
        }

        info.ip_version = (static_cast<uint8_t>(pkt_data[offset]) >> 4) & 0x0F;
        info.ipv4_header_length = (static_cast<uint8_t>(pkt_data[offset]) & 0x0F) * 4;  // in bytes
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

void DuckDBInsertThread::ensureTableExists() {
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
