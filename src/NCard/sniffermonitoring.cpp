#include "sniffermonitoring.h"



/*
 * Бета-версия (стабильная)
 *
 *
 *
*/
void SnifferMonitoring::packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    SnifferMonitoring *sniffer = reinterpret_cast<SnifferMonitoring*>(param);

    if (!sniffer) { return; }

    pcap_pkthdr *headerCopy = new pcap_pkthdr(*header);
    u_char *pktDataCopy = new u_char[header->len];
    std::memcpy(pktDataCopy, pkt_data, header->len);

    //emit sniffer->packetCapturedUchar(headerCopy, pktDataCopy);
    emit sniffer->packetIsReadyToBeSentClickHouse(headerCopy, pktDataCopy);
}
