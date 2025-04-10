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
#include <QCategoryAxis>
#include <QToolTip>



#include <ctime>
#include <unordered_map>

#include "src/NCard/functionstodeterminepacket.h"
#include "duckdb.hpp"

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
    void setGraphData(std::vector<std::pair<std::string, int>>* dta) {
        GraphData = dta;
    }

public slots:
    void Repaint() {
        axisX->setRange(0, maxSize);
        axisY->setRange(0, maxValue);
        int index = 0;
        for (auto i : *GraphData) {
            series->append(index, i.second);
            axisX->append(QString::fromStdString(i.first), index);
            ++index;
        }
    }
private:
    void ConstructGraph() {
        chart = new QChart;
        axisX = new QCategoryAxis();
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
        connect(series, &QLineSeries::hovered, this, [=](const QPointF &point, bool state) {
            if (state) {
                QString text = QString("X: %1\nY: %2")
                                    .arg(point.x(), 0, 'f', 2)
                                    .arg(point.y(), 0, 'f', 2);
                QToolTip::showText(QCursor::pos(), text);
            } else {
                QToolTip::hideText();
            }
        });
        chartView->setRubberBand(QChartView::RectangleRubberBand);
        chartView->setDragMode(QGraphicsView::ScrollHandDrag);
    }

    int maxSize = 0;
    int maxValue = 0;

    int prevMaxSize = 0;

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QCategoryAxis *axisX = nullptr;
    QValueAxis *axisY = nullptr;
    QLineSeries* series = nullptr;
    std::vector<int>* packetData = nullptr;

    std::vector<std::pair<std::string, int>>* GraphData = nullptr;
};



class PikesGraphBackend : public QDialog {
    Q_OBJECT
public:
    PikesGraphBackend(std::array<std::array<std::array<int,60>,60>, 24>& obj, std::vector<int>& vect, std::vector<const struct pcap_pkthdr*>& hdr, QWidget *parent = nullptr);

    QVBoxLayout* GetLayout();
    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }

public slots:
    void Repaint();
private:
    void ConstructGraph();

    std::vector<std::pair<std::string, int>> SearchByParams(int, int);

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

    std::vector<std::pair<std::string, int>>* GraphData = new std::vector<std::pair<std::string, int>>;

    std::shared_ptr<duckdb::Connection> connection = nullptr;

};

#endif // PIKEGRAPH_H
