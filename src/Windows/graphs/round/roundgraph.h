#ifndef ROUNDGRAPH_H
#define ROUNDGRAPH_H

#include <QDialog>
#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QVBoxLayout>
#include <QtCharts/QChart>
#include <QPushButton>

#include "duckdb.hpp"
#include <unordered_map>
#include <memory>

class RoundGraph : public QDialog {
    Q_OBJECT
public slots:
    void setColor(QColor color) {
        if (series) colorCurr = color;
    }
public:
    RoundGraph(std::unordered_map<QString, int>& obj, QWidget *parent = nullptr);
    QChartView* GetChart();
    void Repaint();

private:
    void ConstructGraph();

    QColor colorCurr = 255;

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unordered_map<QString, int>* ObjectsCount = nullptr;
};


class RoundGraphBackend : public QDialog {
    Q_OBJECT
public:
    RoundGraphBackend(QWidget *parent = nullptr);
    ~RoundGraphBackend();

    QVBoxLayout* GetLayout();
    QChart* GetCh();
    void Repaint();
    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }
    int SearchByParams(int, int, const QString);
    QChartView* GetChartView();

    int start = -1;
    int stop = -1;
    int offset = 1000;

    void setLen(int start, int stop, int offset) {};
public slots:
    void setColor(QColor color) {
        if (graph) graph->setColor(color);
    }

private:
    void ConstructGraph();

    QVBoxLayout* layout = nullptr;
    RoundGraph* graph = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unique_ptr<std::unordered_map<QString, int>> ObjectsCount;
    std::shared_ptr<duckdb::Connection> connection = nullptr;

    const std::unordered_map<QString, QString> ethset = {
        {"\\x08\\x00\\x06", "IPv4 - TCP"}, {"\\x08\\x00\\x11", "IPv4 - UDP"},
        {"\\x08\\x00\\x01", "IPv4 - ICMP"}, {"\\x08\\x00\\x02", "IPv4 - IGMP"},
        {"\\x86\\xDD\\x06", "IPv6 - TCP"}, {"\\x86\\xDD\\x11", "IPv6 - UDP"},
        {"\\x86\\xDD\\x3A", "IPv6 - ICMPv6"}, {"\\x08\\x06", "ARP"},
        {"\\x80\\x35", "RARP"}, {"\\x81\\x37", "IPX"}, {"\\x88\\x47", "MPLS Unicast"},
        {"\\x88\\x48", "MPLS Multicast"}, {"\\x88\\x63", "PPPoE Discovery"},
        {"\\x88\\x64", "PPPoE Session"}, {"\\x80\\x00", "SNAP"}, {"\\x81\\x00", "VLAN 802.1Q"},
        {"\\x88\\xA8", "QinQ (802.1ad)"}, {"\\x88\\x8E", "EAPOL"}, {"\\x88\\xCC", "LLDP"},
        {"\\x89\\x02", "Ethernet OAM"}, {"\\x88\\x09", "LACP"}, {"\\x88\\xF7", "PTP"},
        {"\\x88\\x0B", "PPP"}, {"\\x88\\xE5", "MACsec"}
    };
};

#endif // ROUNDGRAPH_H
