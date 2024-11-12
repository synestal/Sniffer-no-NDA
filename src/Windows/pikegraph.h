#ifndef PIKEGRAPH_H
#define PIKEGRAPH_H

#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QVBoxLayout>
#include <QDateTime>
#include <QtCharts/QChart>
#include <QDialog>
#include <QPushButton>


#include <ctime>
#include <unordered_map>

#include "src/NCard/functionstodeterminepacket.h"

class PikesGraph : public QDialog {
    Q_OBJECT
public:
    explicit PikesGraph(std::vector<int>& vect, QWidget *parent = nullptr) : QDialog(parent), packetData(&vect) {
        ConstructGraph();
    }

    QChartView* GetChart() {
        return chartView;
    }

    void setMaxObjects(int maxSize, int maxValue, int prevMaxSize) {
        this->maxSize = maxSize;
        this->maxValue = maxValue;
        if((this->prevMaxSize != prevMaxSize && this->prevMaxSize == 0) || prevMaxSize == 0) {series->clear();}
        this->prevMaxSize = prevMaxSize;
    }

public slots:
    void Repaint() {
        axisX->setRange(0, maxSize);
        axisY->setRange(0, maxValue);
        if (!series->points().isEmpty()) { // Изменяем значение последней точки
            QPointF lastPoint = series->at(series->count() - 1);
            if (lastPoint.x() + 1 == packetData->size()) {
                series->replace(lastPoint, QPointF(lastPoint.x(), (*packetData)[lastPoint.x()]));
            } else {
                for (int i = lastPoint.x(); i < packetData->size(); ++i) {
                    series->append(i, (*packetData)[i]);
                }
            }
            return;
        }
        for (int i = 0; i < packetData->size(); ++i) { // Наполняем модель точками
            series->append(i, (*packetData)[i]);
        }
    }
private:
    void ConstructGraph() {
        chart = new QChart;
        axisX = new QValueAxis();
        axisY = new QValueAxis();
        chartView = new QChartView(chart);
        series = new QLineSeries();

        chart->addSeries(series);
        chart->setTitle("Распределение количества пакетов от времени");
        axisX->setTitleText("Время");
        chart->addAxis(axisX, Qt::AlignBottom);
        series->attachAxis(axisX);
        axisY->setTitleText("Количество пакетов");
        chart->addAxis(axisY, Qt::AlignLeft);
        series->attachAxis(axisY);
        chartView->setRenderHint(QPainter::Antialiasing);
    }

    int maxSize = 0;
    int maxValue = 0;

    int prevMaxSize = 0;

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QValueAxis *axisX = nullptr;
    QValueAxis *axisY = nullptr;
    QLineSeries* series = nullptr;
    std::vector<int>* packetData = nullptr;
};



class PikesGraphBackend : public QDialog {
    Q_OBJECT
public:
    PikesGraphBackend(std::array<std::array<std::array<int,60>,60>, 24>& obj, std::vector<int>& vect, std::vector<const struct pcap_pkthdr*>& hdr, QWidget *parent = nullptr);

    QVBoxLayout* GetLayout();

public slots:
    void Repaint();
private:
    void ConstructGraph();

    void setGraphMode(int mode);
    int settingsApply();
    void addPackets();

    int getPacketsInHour(int hh);
    int getPacketsInMinute(int hh, int mm);
    int getPacketsInSecond(int hh, int mm, int ss);

    QVBoxLayout* layout = nullptr;
    PikesGraph* graph = nullptr;

    std::array<std::array<std::array<int,60>,60>, 24>* vault = nullptr;
    std::vector<int>* packetData = nullptr;

    std::vector<const struct pcap_pkthdr*>*  header = nullptr;

    int timeLive = -1;
    int maxSize = 0;
    int maxValue = 0;

    int prevMaxSize = 0;

    enum Settings {hour, minute, second, liveH, liveM, liveS};
    Settings currentSetting = second;

};

#endif // PIKEGRAPH_H
