#ifndef FUNCTIONSTODETERMINEPACKET_H
#define FUNCTIONSTODETERMINEPACKET_H


#include <QString>
#include <QList>
#include <QDebug>


#include <Winsock2.h>
#include <memory.h>


#include "pcap.h"
#include "packages/service_pcap/misc.h"

#include "packages/structs/typesAndStructs.h"


class functionsToDeterminePacket
{
public:
    functionsToDeterminePacket(std::vector<const struct pcap_pkthdr*>& headerVector, std::vector<const uchar*>& dataVector) : header(headerVector), pkt_data(dataVector) {}; //constructor
    void mainhandler(std::vector<packet_info>&, int, int); //main
    QList<QString> headerDataGetter(const struct pcap_pkthdr*, const u_char*);

private:
    void determinatingPacketType(QString&, const u_char*); //determine tcp, udp...
    packet_info determinator(const struct pcap_pkthdr*, const u_char*); //determine one packet

    std::vector<const struct pcap_pkthdr*>& header;
    std::vector<const uchar*>& pkt_data;

protected:
};


#endif // FUNCTIONSTODETERMINEPACKET_H
