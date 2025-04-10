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
    void Repaint();
    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }
    int SearchByParams(int, int, const std::string );
private:
    void ConstructGraph();

    QVBoxLayout* layout = nullptr;
    RoundGraph* graph = nullptr;
    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unordered_map<QString, int>* ObjectsCount = nullptr;
    std::shared_ptr<duckdb::Connection> connection = nullptr;

    std::unordered_map<std::string, std::string> ethset = {
        {"0800", "IPv4"},
        {"86DD", "IPv6"},
        {"0806", "ARP"},
        {"8035", "RARP"},
        {"8137", "IPX"},
        {"8847", "MPLS Unicast"},
        {"8848", "MPLS Multicast"},
        {"8863", "PPPoE Discovery"},
        {"8864", "PPPoE Session"}
    };

    std::unordered_map<std::string, std::string> ethmapv6 = {
        {"0800", "IPv6 - TCP"},
        {"86DD", "IPv6 - UDP"},
        {"0806", "IPv6 - ICMPv6"}
    };
    std::unordered_map<std::string, std::string> ethmapv4 = {
        {"0800", "IPv4 - TCP"},
        {"86DD", "IPv4 - UDP"},
        {"0806", "IPv4 - ICMP"},
        {"8035", "IPv4 - IGMP"}
    };
};


#endif // ROUNDGRAPH_H
