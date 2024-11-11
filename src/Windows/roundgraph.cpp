#include "roundgraph.h"



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
    series->clear();
    for (const auto& item : *ObjectsCount) {
        series->append(item.first, item.second);
    }
    for (auto slice : series->slices()) {
        slice->setLabelVisible(true);
        slice->setLabel(QString("%1: %2").arg(slice->label()).arg(slice->value()));
    }
    chartView->repaint();
}

QChartView* RoundGraph::GetChart() {
    return chartView;
}



/*
 * CLASS RoundGraphBackend
*/
RoundGraphBackend::RoundGraphBackend(std::unordered_map<QString, int>& obj, std::vector<const struct pcap_pkthdr*>& hdr, std::vector<const uchar*>& dta, QWidget *parent)
        : QDialog(parent), ObjectsCount(&obj), header(&hdr), pkt_data(&dta) {
        ConstructGraph();
}

void RoundGraphBackend::ConstructGraph() {
    layout = new QVBoxLayout;
    graph = new RoundGraph(*ObjectsCount);
    layout->addWidget(graph->GetChart());
}

void RoundGraphBackend::Repaint() {
    functionsToDeterminePacket* determinator = new functionsToDeterminePacket(*header, *pkt_data);
    int currSize = header->size();
    for (int i = graph->maxValCounted; i < currSize; i++) {
        QString temp = "";
        determinator->determinatingPacketType(temp, (*pkt_data)[i]);
        (*ObjectsCount)[temp]++;
    }
    graph->maxValCounted = currSize;
    graph->Repaint();
    delete determinator;
}

QVBoxLayout* RoundGraphBackend::GetLayout() {
    return layout;
}
