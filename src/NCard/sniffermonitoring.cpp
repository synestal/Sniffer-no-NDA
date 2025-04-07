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

    try {
        // Использование блока try-catch для перехвата исключений при создании QByteArray
        //emit sniffer->packetCapturedUchar(headerCopy, pktDataCopy);
        emit sniffer->packetIsReadyToBeSentToDB(*header, QByteArray(reinterpret_cast<const char*>(pkt_data), header->caplen));
    } catch (const std::exception& e) {
        qWarning() << "Exception in packetHandler: " << e.what();
    }
}
