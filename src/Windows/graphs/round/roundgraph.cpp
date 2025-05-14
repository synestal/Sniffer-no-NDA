#include "src/Windows/graphs/round/roundgraph.h"
#include <QDebug>

/*
 * CLASS RoundGraph
 */
RoundGraph::RoundGraph(std::unordered_map<QString, int>& obj, QWidget *parent)
    : QDialog(parent), ObjectsCount(&obj) {
    ConstructGraph();
}

void RoundGraph::ConstructGraph() {
    series = new QPieSeries(this);
    for (const auto& item : *ObjectsCount) {
        series->append(item.first, item.second);
    }
    for (auto slice : series->slices()) {
        slice->setLabelVisible(true);
        slice->setLabel(QString("%1: %2").arg(slice->label()).arg(slice->value()));
    }

    chart = new QChart();
    chart->addSeries(series);
    chart->setTitle("Packet Types Distribution");
    chart->legend()->setVisible(true);

    chartView = new QChartView(chart);
    chartView->setRenderHint(QPainter::Antialiasing);
}

void RoundGraph::Repaint() {
    if (!chartView || !series || !ObjectsCount) return;

    chartView->setUpdatesEnabled(false);
    series->clear();
    for (const auto& item : *ObjectsCount) {
        if (item.second != 0)
            series->append(item.first, item.second);
    }

    for (auto slice : series->slices()) {
        slice->setLabelVisible(true);
        slice->setLabel(QString("%1: %2").arg(slice->label()).arg(slice->value()));
        slice->setLabelPosition(QPieSlice::LabelOutside);
    }

    for (int i = 0; i < series->count(); ++i) {
        QColor lighterColor = colorCurr.lighter(100 + i * 6);
        series->slices().at(i)->setColor(lighterColor);
    }

    chartView->setUpdatesEnabled(true);
    chartView->update();
}

QChartView* RoundGraph::GetChart() {
    return chartView;
}
/*
 * CLASS RoundGraphBackend
 */
RoundGraphBackend::RoundGraphBackend(QWidget *parent)
    : QDialog(parent), ObjectsCount(std::make_unique<std::unordered_map<QString, int>>()) {
    ConstructGraph();
}

RoundGraphBackend::~RoundGraphBackend() {
    delete graph;
    delete layout;
}

void RoundGraphBackend::ConstructGraph() {
    layout = new QVBoxLayout;
    graph = new RoundGraph(*ObjectsCount, this);
    layout->addWidget(graph->GetChart());
    Repaint();
}
bool RoundGraphBackend::applyChangesFromChoosing(QString query) {
    try {
        auto result = connection->Query(query.toUtf8().constData());
        if (!result || result->HasError()) {
            qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
            return false;
        }
        if (result->RowCount() == 0) return false;
        int ans = result->GetValue<int64_t>(0, 0);
        qDebug() << ans;
        queryRaw = query;
        queryIsChanged = true;
        return true;
    } catch (const std::exception& e) {
        qDebug() << e.what();
        return false;
    }
}

void RoundGraphBackend::Repaint() {
    if (!ObjectsCount) return;
    ObjectsCount->clear();
    for (const auto& pair : ethset) {
        int param = SearchByParams(13, 1, pair.first);
        ObjectsCount->emplace(pair.second, param);
    }
    if (graph) graph->Repaint();
}

int RoundGraphBackend::SearchByParams(int start, int howMany, const QString toFind) {
    if (!connection) {
        qDebug() << "Connection is null in roundGraph";
        return 0;
    }

    if (start < 0 || howMany < 0) {
        qDebug() << "Invalid parameters";
        return 0;
    }

    try {
        QString query = "";
        if (!queryIsChanged) {
            query = QString(queryRaw).arg(toFind);
        } else {
            query = queryRaw;
        }
        auto result = connection->Query(query.toUtf8().constData());

        if (!result || result->HasError()) {
            qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
            return 0;
        }

        if (result->RowCount() == 0) return 0;

        return result->GetValue<int64_t>(0, 0);
    } catch (const std::exception& e) {
        qDebug() << "DuckDB error:" << e.what();
        return 0;
    }
}

QVBoxLayout* RoundGraphBackend::GetLayout() {
    return layout;
}

QChart* RoundGraphBackend::GetCh() {
    return graph ? graph->GetChart()->chart() : nullptr;
}

QChartView* RoundGraphBackend::GetChartView() {
    return graph ? graph->GetChart() : nullptr;
}
