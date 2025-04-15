#ifndef ROUNDGRAPH_H
#define ROUNDGRAPH_H

#include <QDialog>
#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QVBoxLayout>
#include <QtCharts/QChart>
#include <QPushButton>


#include "src/NCard/functionstodeterminepacket.h"
#include "duckdb.hpp"
#include <unordered_map>

class RoundGraph : public QDialog {
    Q_OBJECT
public:
    RoundGraph(std::unordered_map<QString, int>& obj, QWidget *parent = nullptr);
    QChartView* GetChart();
    void Repaint();
private:
    void ConstructGraph();

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unordered_map<QString, int>* ObjectsCount = nullptr;
};


class RoundGraphBackend : public QDialog {
    Q_OBJECT
public:
    RoundGraphBackend(std::unordered_map<QString, int>& obj, QWidget *parent = nullptr);

    QVBoxLayout* GetLayout();
    QChart* GetCh();
    void Repaint();
    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }
    int SearchByParams(int, int, const QString );
    QChartView* GetChartView();
private:
    void ConstructGraph();

    QVBoxLayout* layout = nullptr;
    RoundGraph* graph = nullptr;
    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unordered_map<QString, int>* ObjectsCount = nullptr;
    std::shared_ptr<duckdb::Connection> connection = nullptr;
    std::unordered_map<QString, QString> ethset = {
        {"\\x08\\x00\\x06", "IPv4 - TCP"},   // EtherType 0x0800 + Protocol 0x06
        {"\\x08\\x00\\x11", "IPv4 - UDP"},   // EtherType 0x0800 + Protocol 0x11
        {"\\x08\\x00\\x01", "IPv4 - ICMP"},  // EtherType 0x0800 + Protocol 0x01
        {"\\x08\\x00\\x02", "IPv4 - IGMP"},  // EtherType 0x0800 + Protocol 0x02
        {"\\x86\\xDD\\x06", "IPv6 - TCP"},   // EtherType 0x86DD + Next Header 0x06
        {"\\x86\\xDD\\x11", "IPv6 - UDP"},   // EtherType 0x86DD + Next Header 0x11
        {"\\x86\\xDD\\x3A", "IPv6 - ICMPv6"},// EtherType 0x86DD + Next Header 0x3A
        {"\\x08\\x06", "ARP"}, // Address Resolution Protocol
        {"\\x80\\x35", "RARP"}, // Reverse Address Resolution Protocol
        {"\\x81\\x37", "IPX"}, // Internetwork Packet Exchange
        {"\\x88\\x47", "MPLS Unicast"}, // MPLS Unicast
        {"\\x88\\x48", "MPLS Multicast"}, // MPLS Multicast
        {"\\x88\\x63", "PPPoE Discovery"}, // PPP over Ethernet Discovery
        {"\\x88\\x64", "PPPoE Session"}, // PPP over Ethernet Session
        {"\\x80\\x00", "SNAP"}, // Subnetwork Access Protocol
        {"\\x81\\x00", "VLAN 802.1Q"}, // Virtual LAN tagging
        {"\\x88\\xA8", "QinQ (802.1ad)"}, // Double VLAN tagging
        {"\\x88\\x8E", "EAPOL"}, // Extensible Authentication Protocol over LAN
        {"\\x88\\xCC", "LLDP"}, // Link Layer Discovery Protocol
        {"\\x89\\x02", "Ethernet OAM"}, // Operations, Administration, and Maintenance
        {"\\x88\\x09", "LACP"}, // Link Aggregation Control Protocol
        {"\\x88\\xF7", "PTP"}, // Precision Time Protocol
        {"\\x88\\x0B", "PPP"}, // Point-to-Point Protocol
        {"\\x88\\xE5", "MACsec"} // Media Access Control Security
    };
};


#endif // ROUNDGRAPH_H
