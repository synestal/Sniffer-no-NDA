#include "src/Windows/graphs/round/roundgraph.h"



/*
 * CLASS RoundGraph
*/
RoundGraph::RoundGraph(std::unordered_map<QString, int>& obj, QWidget *parent)
        : QDialog(parent), ObjectsCount(&obj) {
        ConstructGraph();
}

void RoundGraph::ConstructGraph() {
    series = new QPieSeries();
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
    chartView->setUpdatesEnabled(false);
    series->clear();
    for (const auto& item : *ObjectsCount) {
        if (item.second != 0) {series->append(item.first, item.second);}
    }
    for (auto slice : series->slices()) {
        slice->setLabelVisible(true);
        slice->setLabel(QString("%1: %2").arg(slice->label()).arg(slice->value()));
        slice->setLabelPosition(QPieSlice::LabelOutside);
    }
    for (int i = 0; i < series->count(); ++i) {
            QColor lighterColor = colorCurr.lighter(100 + i * 4);
            series->slices().at(i)->setColor(lighterColor);
        }
    chartView->setUpdatesEnabled(true);
    chartView->update();
}

QChart* RoundGraphBackend::GetCh() {
    return chart;
}
QChartView* RoundGraph::GetChart() {
    return chartView;
}



/*
 * CLASS RoundGraphBackend
*/
RoundGraphBackend::RoundGraphBackend(QWidget *parent)
        : QDialog(parent) {
        ObjectsCount = new std::unordered_map<QString, int>;
        ConstructGraph();
}
RoundGraphBackend::~RoundGraphBackend() {
    delete graph;
    delete layout;
    delete ObjectsCount;
}

QChartView* RoundGraphBackend::GetChartView() {
    return graph->GetChart();
}

int RoundGraphBackend::SearchByParams(int start, int howMany, const QString toFind ) {
    if (!connection) {
        qDebug() << "Connection is null in roundGraph";
        return false;
    }
    if (start < 0 || howMany < 0) {
        qDebug() << "Invalid info to search by params";
        return false;
    }
    try {
        QString query = QString("SELECT COUNT(*) FROM packets "
                                "WHERE (packet_type = '%1');")
                            .arg(toFind);
        //qDebug() << query;
        auto result = connection->Query(query.toUtf8().constData());
        if (!result || result->HasError()) {
            qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
            return false;
        }
        size_t row_count = result->RowCount();
        if (row_count == 0) {
            qDebug() << "No data returned from query";
            return false;
        }
        int returningVal = 0;
        try {
            returningVal = result->GetValue<int64_t>(0, 0);
        } catch (const std::exception& e) {
            qDebug() << "Error processing row:" << e.what();
        }
        return returningVal;
    } catch (const std::exception& e) {
        qDebug() << "DuckDB error: " << e.what();
        return -1;
    }
}

void RoundGraphBackend::ConstructGraph() {
    layout = new QVBoxLayout;
    graph = new RoundGraph(*ObjectsCount);
    Repaint();
    layout->addWidget(graph->GetChart());
}

void RoundGraphBackend::Repaint() {
    ObjectsCount->clear();
    for (const auto& pair : ethset) {
        ObjectsCount->insert(std::pair<QString, int>(pair.second, SearchByParams(13,1,pair.first)));
    }
    graph->Repaint();
}

QVBoxLayout* RoundGraphBackend::GetLayout() {
    return layout;
}
