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

#include "duckdb.hpp"

class PikesGraph : public QDialog {
    Q_OBJECT
public:
    explicit PikesGraph(QWidget *parent = nullptr) : QDialog(parent) {
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
        axisX->setRange(0, maxSize);
        axisY->setRange(0, maxValue);
        int index = 0;
        for (auto i : *GraphData) {
            series->append(index, i.second);
            axisX->append(i.first, index);
            ++index;
        }
        series->setColor(colorCurr);
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

    int prevMaxSize = -1;

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QCategoryAxis *axisX = nullptr;
    QValueAxis *axisY = nullptr;
    QLineSeries* series = nullptr;
    QColor colorCurr;

    std::vector<std::pair<QString, int>>* GraphData = nullptr;
};



class PikesGraphBackend : public QDialog {
    Q_OBJECT
public:
    PikesGraphBackend(QWidget *parent = nullptr);
    ~PikesGraphBackend();

    QVBoxLayout* GetLayout();
    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }
    QChartView* GetChartView() {
        return graph->GetChart();
    }
    int start = -1;
    int stop = -1;
    int offset = 1000;

    void setLen(int start, int stop, int offset) {};

public slots:
    void Repaint();
    void setColor(QColor color) {
        if (graph == nullptr) {return;}
        graph->setColor(color);
    }
private:
    void ConstructGraph();

    std::vector<std::pair<QString, int>> SearchByParams(int, int, int, int);

    void setGraphMode(int mode);
    int settingsApply();

    QVBoxLayout* layout = nullptr;
    PikesGraph* graph = nullptr;

    int timeLive = -1;
    int maxSize = 0;
    int maxValue = 0;

    int prevMaxSize = 0;

    enum Settings {hour, minute, second, liveH, liveM, liveS};
    Settings currentSetting = second;

    std::vector<std::pair<QString, int>>* GraphData = new std::vector<std::pair<QString, int>>;

    std::shared_ptr<duckdb::Connection> connection = nullptr;

};

#endif // PIKEGRAPH_H
