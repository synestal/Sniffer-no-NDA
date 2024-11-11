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
#include <unordered_map>

class RoundGraph : public QDialog {
    Q_OBJECT
public:
    RoundGraph(std::unordered_map<QString, int>& obj, QWidget *parent = nullptr);
    QChartView* GetChart();
    void Repaint();
    int maxValCounted = 0; //Сколько пакетов было посчитано
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
    RoundGraphBackend(std::unordered_map<QString, int>& obj, std::vector<const struct pcap_pkthdr*>& hdr, std::vector<const uchar*>& dta, QWidget *parent = nullptr);

    QVBoxLayout* GetLayout();
    void Repaint();
private:
    void ConstructGraph();

    QVBoxLayout* layout = nullptr;
    RoundGraph* graph = nullptr;
    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unordered_map<QString, int>* ObjectsCount = nullptr;
    std::vector<const struct pcap_pkthdr*>* header = nullptr;
    std::vector<const uchar*>* pkt_data;
};


#endif // ROUNDGRAPH_H
