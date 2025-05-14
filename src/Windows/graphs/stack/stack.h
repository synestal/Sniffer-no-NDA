#ifndef STACK_H
#define STACK_H

#include <QtCharts/QChartView>
#include <QtCharts/QStackedBarSeries>
#include <QtCharts/QValueAxis>
#include <QBarCategoryAxis>
#include <QBarSet>
#include <QVBoxLayout>
#include <QDateTime>
#include <QtCharts/QChart>
#include <QDialog>
#include <QPushButton>
#include <QCategoryAxis>
#include <QToolTip>



#include <ctime>
#include <unordered_map>

#include "duckdb.hpp"

class StackGraph : public QDialog {
    Q_OBJECT
public slots:
    void setColor(QColor color) {
        if (series) colorCurr = color;
    }
public:
    StackGraph(std::vector<std::pair<QBarSet*, QString>>& dta, QWidget *parent = nullptr);
    QChartView* GetChart();
    void Repaint();
    void setGrid(bool state);

private:
    void ConstructGraph();
    int CalculateMaxValue();
    int currentStep = 0;

    QColor colorCurr = 255;

    QBarCategoryAxis* axisX = nullptr;
    QValueAxis* axisY = nullptr;

    std::vector<std::pair<QBarSet*, QString>>* dataColumns = nullptr;
    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QStackedBarSeries* series = nullptr;
};



class StackGraphBackend : public QDialog {
    Q_OBJECT
public:
    StackGraphBackend(QWidget *parent = nullptr);
    ~StackGraphBackend();

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
    void setGrid(bool state);
    QString queryRaw = "SELECT COUNT(*) FROM packets WHERE (packet_type = '%1');";
    bool applyChangesFromChoosing(QString);
public slots:
    void setColor(QColor color) {
        if (graph) graph->setColor(color);
    }

private:
    void ConstructGraph();
    bool queryIsChanged = false;

    QVBoxLayout* layout = nullptr;
    StackGraph* graph = nullptr;
    QChart* chart = nullptr;
    QStackedBarSeries* series = nullptr;
    std::shared_ptr<duckdb::Connection> connection = nullptr;

    std::vector<std::pair<QBarSet*, QString>>* dataColumns = nullptr;

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

#endif // STACK_H
