#ifndef TYPESANDSTRUCTS_H
#define TYPESANDSTRUCTS_H

#include <QString>
#include <QList>
#include "pcap.h"

typedef struct packet_info {
    QString index = "";
    QString timeInfo = "";
    QString lenInfo = "";
    QString srcInfo = "";
    QString destInfo = "";
    QString packetType = "";
    QString data = "";
}packet_info;

struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short eth_type;
};


/* 4 bytes IP address */
typedef struct ip_address{
  u_char byte1;
  u_char byte2;
  u_char byte3;
  u_char byte4;
}ip_address;

typedef struct ip_header{
  u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
  u_char  tos;     // Type of service
  u_short tlen;    // Total length
  u_short identification; // Identification
  u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
  u_char  ttl;      // Time to live
  u_char  proto;    // Protocol
  u_short crc;      // Header checksum
  ip_address  saddr; // Source address
  ip_address  daddr; // Destination address
  u_int  op_pad;     // Option + Padding
}ip_header;

typedef struct udp_header{
  u_short sport; // Source port
  u_short dport; // Destination port
  u_short len;   // Datagram length
  u_short crc;   // Checksum
}udp_header;



#endif // TYPESANDSTRUCTS_H
