#include "functionstodeterminepacket.h"

/*
 * Бета-версия (стабильная)
 *
 * To do: переделать хранение на более оптимизированное
 *        уменьшить передаваемые объекты до одного
 *
 *
*/
void functionsToDeterminePacket::mainhandler(std::vector<packet_info>& vect, int start, int end) {
    for (int i = start; i < end; ++i) {
        vect[i - start] = determinator(header[i], pkt_data[i]);
        vect[i - start].index = QString::number(i);
    }
}

QList<QString> functionsToDeterminePacket::headerDataGetter(const struct pcap_pkthdr* header, const u_char* pkt_data) {
    const ip_header* ih = reinterpret_cast<const ip_header*>(pkt_data + 14);
    const u_int ip_len = (ih->ver_ihl & 0xf) * 4;
    const u_int udp_header_offset = 14 + ip_len + sizeof(udp_header);
    const u_char* payload = pkt_data + udp_header_offset;

    const int payload_len = header->len - udp_header_offset;

    QList<QString> output; output.reserve(payload_len / 16 + 1);
    if (payload_len > 0) {
        output.append(QString("Тело (%1 байт):").arg(payload_len));
        for (int i = 0; i < payload_len; i+=16) {
            QString temp; temp.reserve(3 * 16);
            for (int a = i; a < i + 16 && a < payload_len; ++a) {
                temp += QString(" %1").arg(payload[a], 2, 16, QChar('0'));
            }
            output.append(temp);
        }
        output.last().shrink_to_fit();
    } else {
        output.append("В пакете нет тела");
    }
    return(output);
}

packet_info functionsToDeterminePacket::determinator(const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct tm ltime;
    char timestr[16];
    qDebug() << "here1";
    const ip_header* ih = reinterpret_cast<const ip_header*>(pkt_data + 14);
    const u_int ip_len = (ih->ver_ihl & 0xf) * 4;
    const udp_header* uh = reinterpret_cast<const udp_header*>(pkt_data + 14 + ip_len);
    qDebug() << "here2";
    if (uh == nullptr) {
            qDebug() << "Error: Invalid UDP header.";
            return packet_info();
        }
    qDebug() << ih->proto;
    qDebug() << ntohs(uh->sport);
    qDebug() << ntohs(uh->dport);

    const u_short sport = ntohs( uh->sport );
    const u_short dport = ntohs( uh->dport );
    qDebug() << "here3";


    const time_t local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    packet_info inf;
    determinatingPacketType(inf.packetType, pkt_data); // Тип пакета
    inf.timeInfo = QString("%1.%2") // Время принятия
              .arg(timestr)
              .arg(header->ts.tv_usec);
    inf.timeInfo.shrink_to_fit();

    inf.lenInfo = QString("%1").arg(header->len); // Длина пакета
    inf.lenInfo.shrink_to_fit();
    inf.srcInfo = QString("%1.%2.%3.%4 : %5") // Откуда
              .arg(ih->saddr.byte1)
              .arg(ih->saddr.byte2)
              .arg(ih->saddr.byte3)
              .arg(ih->saddr.byte4)
              .arg(sport);
    inf.srcInfo.shrink_to_fit();
    inf.destInfo = QString("%1.%2.%3.%4 : %5") // Куда
              .arg(ih->daddr.byte1)
              .arg(ih->daddr.byte2)
              .arg(ih->daddr.byte3)
              .arg(ih->daddr.byte4)
              .arg(dport);
    inf.destInfo.shrink_to_fit();
    return(inf);
}

void functionsToDeterminePacket::determinatingPacketType(QString& str, const u_char* pkt_data) {
    const u_short eth_type = ntohs(reinterpret_cast<const ethernet_header*>(pkt_data)->eth_type);

    if (eth_type == 0x0800) {
        str = "IPv4";
            const ip_header* ih = reinterpret_cast<const ip_header*>(pkt_data + 14);
            const u_char protocol = ih->proto;
            if (protocol == 6) {
                str += " - TCP";
            } else if (protocol == 17) {
                str += " - UDP";
            } else if (protocol == 1) {
                str += " - ICMP";
            } else if (protocol == 2) {
                str += " - IGMP";
            } else {
                str += QString(" - Unknown Protocol: %1").arg(protocol);
            }
    } else if (eth_type == 0x86DD) {
        str = "IPv6";
            const u_char* ipv6_header = pkt_data + 14;
            const u_char nextHeader = ipv6_header[6];
            if (nextHeader == 6) {
                str += " - TCP";
            } else if (nextHeader == 17) {
                str += " - UDP";
            } else if (nextHeader == 58) {
                str += " - ICMPv6";
            } else {
                str += QString(" - Unknown Protocol: %1").arg(nextHeader);
            }
    } else if (eth_type == 0x0806) {
        str = "ARP";
    } else if (eth_type == 0x8035) {
        str = "RARP";
    } else if (eth_type == 0x8137) {
        str = "IPX";
    } else if (eth_type == 0x8847) {
        str = "MPLS Unicast";
    } else if (eth_type == 0x8848) {
        str = "MPLS Multicast";
    } else if (eth_type == 0x8863) {
        str = "PPPoE Discovery";
    } else if (eth_type == 0x8864) {
        str = "PPPoE Session";
    } else {
        str = QString("Unknown: 0x%1").arg(eth_type, 4, 16, QChar('0')).toUpper();
    }
}
