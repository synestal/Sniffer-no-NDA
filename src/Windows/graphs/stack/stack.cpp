#include "src/Windows/graphs/stack/stack.h"

StackGraph::StackGraph(std::vector<std::pair<QBarSet*, QString>>& dta, QWidget *parent)
    : QDialog(parent), dataColumns(&dta) {
    ConstructGraph();
}

void StackGraph::ConstructGraph() {
    series = new QStackedBarSeries(this);
    for (const auto& item : *dataColumns) {
        series->append(item.first);
    }
    series->setBarWidth(1.0);
    chart = new QChart();
    chart->addSeries(series);
    chart->setTitle("Packet Types Distribution Over Time");
    chart->legend()->setVisible(true);

    axisX = new QBarCategoryAxis();
    chart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);

    axisY = new QValueAxis();
    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);

    chartView = new QChartView(chart);
    chartView->setRenderHint(QPainter::Antialiasing);
    chartView->setCacheMode(QGraphicsView::CacheBackground);
    chartView->setViewportUpdateMode(QGraphicsView::SmartViewportUpdate);
}

void StackGraph::Repaint() {
    if (!chartView || !series || !dataColumns) return;

    chartView->setUpdatesEnabled(false);
    if (axisX->count() >= 100) {
            axisX->remove(axisX->at(0)); // Remove oldest category

            // Remove oldest data point from each set
            for (const auto& item : *dataColumns) {
                if (item.first->count() > 0) {
                    item.first->remove(0);
                }
            }
        }
    QString newCategory = QString("%1").arg(currentStep);
    axisX->append(newCategory);
    chart->axes(Qt::Vertical).first()->setRange(0, CalculateMaxValue());
    ++currentStep;
    chartView->setUpdatesEnabled(true);
    chartView->update();
}
int StackGraph::CalculateMaxValue() {
    int sum = 0;
        for (const auto& item : *dataColumns) {
            if (item.first->count() > 0)
                sum += item.first->at(item.first->count() - 1);
        }
        return sum + 10;
}

QChartView* StackGraph::GetChart() {
    return chartView;
}



    StackGraphBackend::StackGraphBackend(QWidget *parent)
        : QDialog(parent), dataColumns(new std::vector<std::pair<QBarSet*, QString>>) {
        for (const auto& pair : ethset) {
            auto temp = new QBarSet(pair.second);
            dataColumns->push_back(std::pair<QBarSet*, QString>(temp, pair.second));
        }
        ConstructGraph();
    }

    StackGraphBackend::~StackGraphBackend() {
        delete graph;
        delete layout;
    }

    void StackGraphBackend::ConstructGraph() {
        layout = new QVBoxLayout;
        graph = new StackGraph(*dataColumns, this);
        layout->addWidget(graph->GetChart());
    }

    void StackGraphBackend::Repaint() {
        if (!dataColumns) return;

        auto itBar = dataColumns->begin();
        auto itEth = ethset.begin();

        for (; itBar != dataColumns->end() && itEth != ethset.end(); ++itBar, ++itEth) {
            int param = SearchByParams(13, 1, itEth->first);

            *(itBar->first) << param;
        }
        if (graph) graph->Repaint();
    }

    int StackGraphBackend::SearchByParams(int start, int howMany, const QString toFind) {
        if (!connection) {
            qDebug() << "Connection is null in stackGraph";
            return 0;
        }

        if (start < 0 || howMany < 0) {
            qDebug() << "Invalid parameters";
            return 0;
        }

        try {
            QString query = QString("SELECT COUNT(*) FROM packets WHERE (packet_type = '%1');").arg(toFind);
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

    QVBoxLayout* StackGraphBackend::GetLayout() {
        return layout;
    }

    QChart* StackGraphBackend::GetCh() {
        return graph ? graph->GetChart()->chart() : nullptr;
    }

    QChartView* StackGraphBackend::GetChartView() {
        return graph ? graph->GetChart() : nullptr;
    }


