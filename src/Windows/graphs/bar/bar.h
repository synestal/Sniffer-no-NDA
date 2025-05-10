#ifndef BAR_H
#define BAR_H

#include <QtCharts/QChartView>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
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

#include "duckdb.hpp"

class BarGraph : public QDialog {
    Q_OBJECT
public:
    explicit BarGraph(QWidget *parent = nullptr) : QDialog(parent) {
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
    void setGraphData(std::vector<std::pair<QString, int>>* dta) {
        GraphData = dta;
    }

public slots:
    void Repaint() {
        series->clear();
        axisX->setRange(0, maxSize);
        axisY->setRange(0, maxValue);
        int index = 0;
        QBarSet *packetSizes = new QBarSet("Размеры пакетов (байт)");
        for (auto i : *GraphData) {
            *packetSizes << i.second;
            axisX->append(i.first, index);
            ++index;
        }
        packetSizes->setColor(colorCurr);
        series->append(packetSizes);
    }
    void setColor(QColor color) {
        if (series == nullptr) {return;}
        colorCurr = color;
    }
private:
    void ConstructGraph() {
        chart = new QChart;
        axisX = new QCategoryAxis();
        axisY = new QValueAxis();
        chartView = new QChartView(chart);
        series = new QBarSeries();

        chart->addSeries(series);
        chart->setTitle("Распределение");
        axisX->setTitleText("Время");
        chart->addAxis(axisX, Qt::AlignBottom);
        series->attachAxis(axisX);
        axisY->setTitleText("Количество пакетов");
        chart->addAxis(axisY, Qt::AlignLeft);
        series->attachAxis(axisY);
        chartView->setRenderHint(QPainter::Antialiasing);
        chartView->setRubberBand(QChartView::RectangleRubberBand);
        chartView->setDragMode(QGraphicsView::ScrollHandDrag);
    }

    int maxSize = 0;
    int maxValue = 0;

    int prevMaxSize = -1;

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QCategoryAxis* axisX = nullptr;
    QValueAxis* axisY = nullptr;
    QBarSeries* series = nullptr;
    QColor colorCurr;

    std::vector<std::pair<QString, int>>* GraphData = nullptr;
};



class BarGraphBackend : public QDialog {
    Q_OBJECT
public:
    BarGraphBackend(QWidget *parent = nullptr);

    QVBoxLayout* GetLayout();
    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }
    QChartView* GetChartView() {
        return graph->GetChart();
    }

    int start = -2;
    int stop = -1;
    int offset = 1000;
    ~BarGraphBackend();

public slots:
    void Repaint();
    void setColor(QColor color) {
        if (graph == nullptr) {return;}
        graph->setColor(color);
    }
private:
    void ConstructGraph();

    std::vector<std::pair<QString, int>> SearchByParams(int, int, int);

    void setGraphMode(int mode);
    int settingsApply();

    QVBoxLayout* layout = nullptr;
    BarGraph* graph = nullptr;

    int timeLive = -1;
    int maxSize = 0;
    int maxValue = 0;

    int prevMaxSize = 0;

    std::vector<std::pair<QString, int>>* GraphData = new std::vector<std::pair<QString, int>>;

    std::shared_ptr<duckdb::Connection> connection = nullptr;

};

#endif // BAR_H
