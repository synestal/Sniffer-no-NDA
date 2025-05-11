#include "src/Windows/graphs/bar/bar.h"
#include <QDebug>
#include <sstream>
#include <algorithm>

BarGraph::BarGraph(QWidget *parent)
    : QDialog(parent) {
    ConstructGraph();
}

QChartView* BarGraph::GetChart() {
    return chartView;
}

void BarGraph::setGraphData(const std::shared_ptr<std::vector<std::pair<QString, int>>>& data) {
    graphData = data;
}

void BarGraph::setMaxObjects(int maxSize, int maxValue, int prevMaxSize) {
    this->maxSize = maxSize;
    this->maxValue = maxValue;
    if (prevMaxSize == 0 || (this->prevMaxSize == 0 && this->prevMaxSize != prevMaxSize)) {
        series->clear();
    }
    this->prevMaxSize = prevMaxSize;
}

void BarGraph::setColor(const QColor& color) {
    if (!series) return;
    colorCurr = color;
}

void BarGraph::Repaint() {
    if (!graphData) return;

    series->clear();
    axisX->setRange(0, maxSize);
    axisY->setRange(0, maxValue);

    auto *packetSizes = new QBarSet("Размеры пакетов (байт)");
    int index = 0;
    for (const auto& entry : *graphData) {
        *packetSizes << entry.second;
        axisX->append(entry.first, index++);
    }
    packetSizes->setColor(colorCurr);
    series->append(packetSizes);
}

void BarGraph::ConstructGraph() {
    chart = new QChart;
    axisX = new QCategoryAxis();
    axisY = new QValueAxis();
    chartView = new QChartView(chart);
    series = new QBarSeries();

    chart->addSeries(series);
    chart->setTitle("Распределение");
    axisX->setTitleText("Диапазон длины");
    axisY->setTitleText("Количество пакетов");

    chart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);

    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);

    chartView->setRenderHint(QPainter::Antialiasing);
    chartView->setRubberBand(QChartView::RectangleRubberBand);
    chartView->setDragMode(QGraphicsView::ScrollHandDrag);
}

// BarGraphBackend

BarGraphBackend::BarGraphBackend(QWidget *parent)
    : QDialog(parent), graphData(std::make_shared<std::vector<std::pair<QString, int>>>()) {
    ConstructGraph();
    graph->setGraphData(graphData);
}

BarGraphBackend::~BarGraphBackend() = default;

QVBoxLayout* BarGraphBackend::GetLayout() {
    return layout;
}

QChartView* BarGraphBackend::GetChartView() {
    return graph->GetChart();
}

void BarGraphBackend::setConnection(const std::shared_ptr<duckdb::Connection>& conn) {
    connection = conn;
}

void BarGraphBackend::setColor(const QColor& color) {
    if (graph) {
        graph->setColor(color);
    }
}

void BarGraphBackend::ConstructGraph() {
    layout = new QVBoxLayout(this);
    graph = std::make_unique<BarGraph>();
    layout->addWidget(graph->GetChart());
}

void BarGraphBackend::Repaint() {
    auto data = SearchByParams(lenStart, lenStop, offset);
    if (data.empty()) return;

    int maxSize = static_cast<int>(data.size());
    int maxValue = std::max_element(data.begin(), data.end(),
                    [](const auto &a, const auto &b) {
                        return a.second < b.second;
                    })->second;

    *graphData = std::move(data);
    graph->setMaxObjects(maxSize, maxValue, prevMaxSize);
    graph->Repaint();
    prevMaxSize = maxSize;
}

std::vector<std::pair<QString, int>> BarGraphBackend::SearchByParams(int start, int stop, int offset) {
    if (!connection) {
        qDebug() << "Connection is null in BarGraphBackend";
        return {};
    }

    if (start >= stop) {
        qDebug() << "Invalid start/stop range in BarGraphBackend";
        return {};
    }

    std::string startExpr = start < 0 ? "MIN(len)" : std::to_string(start);
    std::string stopExpr = stop < 0 ? "MAX(len)" : std::to_string(stop);

    try {
        std::ostringstream oss;
        oss << "WITH range_values AS (SELECT " << startExpr << " AS min_val, " << stopExpr
            << " AS max_val, " << offset << " AS step FROM packets), "
            << "ranges AS ( "
            << "SELECT generate_series AS range_start, "
            << "generate_series + (SELECT step FROM range_values) - 1 AS range_end "
            << "FROM generate_series( "
            << "(SELECT min_val FROM range_values), "
            << "(SELECT max_val FROM range_values), "
            << "(SELECT step FROM range_values))) "
            << "SELECT r.range_start, r.range_end, COUNT(p.len) AS count "
            << "FROM ranges r "
            << "LEFT JOIN packets p ON p.len BETWEEN r.range_start AND r.range_end "
            << "GROUP BY r.range_start, r.range_end "
            << "ORDER BY r.range_start;";

        auto result = connection->Query(oss.str());
        if (!result || result->HasError()) {
            qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
            return {};
        }

        std::vector<std::pair<QString, int>> values;
        values.reserve(result->RowCount());

        for (size_t i = 0; i < result->RowCount(); ++i) {
            int count = result->GetValue(2, i).GetValue<int64_t>();
            QString label = QString("%1 - %2")
                                .arg(result->GetValue(0, i).GetValue<int64_t>())
                                .arg(result->GetValue(1, i).GetValue<int64_t>());
            values.emplace_back(std::move(label), count);
        }

        return values;

    } catch (const std::exception &e) {
        qDebug() << "DuckDB exception: " << e.what();
        return {};
    }
}

void BarGraphBackend::setLen(int start, int stop, int _offset) {
    lenStart = start;
    lenStop = stop;
    offset = _offset;

}
