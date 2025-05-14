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

#include <memory>
#include <unordered_map>
#include <vector>

#include "duckdb.hpp"

class BarGraph : public QDialog {
    Q_OBJECT
public:
    explicit BarGraph(QWidget *parent = nullptr);

    QChartView* GetChart();
    void setMaxObjects(int maxSize, int maxValue, int prevMaxSize);
    void setGraphData(const std::shared_ptr<std::vector<std::pair<QString, int>>>& data);
    void setColor(const QColor& color);
    void setGrid(bool state);

public slots:
    void Repaint();

private:
    void ConstructGraph();

    int maxSize = 0;
    int maxValue = 0;
    int prevMaxSize = -1;

    QChartView *chartView = nullptr;
    QChart *chart = nullptr;
    QCategoryAxis *axisX = nullptr;
    QValueAxis *axisY = nullptr;
    QBarSeries *series = nullptr;
    QColor colorCurr;

    std::shared_ptr<std::vector<std::pair<QString, int>>> graphData = nullptr;
};

class BarGraphBackend : public QDialog {
    Q_OBJECT
public:
    explicit BarGraphBackend(QWidget *parent = nullptr);
    ~BarGraphBackend();

    QVBoxLayout* GetLayout();
    QChartView* GetChartView();
    void setConnection(const std::shared_ptr<duckdb::Connection>& conn);
    void setColor(const QColor& color);

    void setLen(int, int, int);
    void setGrid(bool state);
    QString queryRaw = "SELECT COUNT(*) FROM packets WHERE (packet_type = '%1');";
    bool applyChangesFromChoosing(QString);

public slots:
    void Repaint();

private:
    void ConstructGraph();
    bool queryIsChanged = false;
    std::vector<std::pair<QString, int>> SearchByParams(int start, int stop, int offset);

    QVBoxLayout *layout = nullptr;
    std::unique_ptr<BarGraph> graph;
    std::shared_ptr<std::vector<std::pair<QString, int>>> graphData;

    int lenStart = -2;
    int lenStop = -1;
    int offset = 1000;

    int prevMaxSize = 0;

    std::shared_ptr<duckdb::Connection> connection = nullptr;
};

#endif // BAR_H
