#include "graphchoosing.h"
#include "ui_graphchoosing.h"

/*
 * Версия в разработке - синтакис, логика и поведение операторов, указателей нестабильны
 *
 * To do: переопределить класс окна и графика через кастомный
 *        переделать операцию Repaint
 *
*/




/*
 * Class GraphBackend
*/

GraphChoosing::GraphChoosing(QWidget *parent, std::vector<const struct pcap_pkthdr*>& hdr, std::vector<const uchar*>& dta) : QDialog(parent), header(&hdr), pkt_data(&dta), ui(new Ui::GraphChoosing) {
    ui->setupUi(this);
    connect(ui->actionCreatePieChart, &QAction::triggered, this, &GraphChoosing::createCircleDiagram);
    connect(ui->actionCreateLineChart, &QAction::triggered, this, &GraphChoosing::createPikeDiagram);
    resize(1920, 1080);

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &GraphChoosing::Repaint);
    updateTimer->start(200);
}

void GraphChoosing::closeEvent(QCloseEvent *event) {
    int response = QMessageBox::question(this, "Закрытие", "Вы уверены, что хотите закрыть окно?");
    if (response == QMessageBox::Yes) {
        emit closeRequested();
        event->accept();
    } else {
        event->ignore();
    }
}

void GraphChoosing::createCircleDiagram() {
    auto* chartContainer = new QWidget();
    chartContainer->setMinimumHeight(400);
    chartContainer->setMaximumHeight(400);
    auto* layout = new QHBoxLayout(chartContainer);
    std::unordered_map<QString, int>* ObjectsCircle = new std::unordered_map<QString, int>;
    RoundGraphBackend* graph = new RoundGraphBackend(*ObjectsCircle);
    graph->setConnection(connection);
    diagrams.push_back(graph);
    diagramsStorage.push_back(ObjectsCircle);
    graph->Repaint();
    layout->addWidget(graph->GetChartView());
    ui->chartsLayout->addWidget(chartContainer);
}

void GraphChoosing::createPikeDiagram() {
    auto* chartContainer = new QWidget();
    chartContainer->setMinimumHeight(400);
    chartContainer->setMaximumHeight(400);
    auto* layout = new QHBoxLayout(chartContainer);
    PikesGraphBackend* pike = new PikesGraphBackend();
    pike->setConnection(connection);
    diagrams.push_back(pike);
    pike->Repaint();
    layout->addWidget(pike->GetChartView());
    ui->chartsLayout->addWidget(chartContainer);
    //ui->MainLayout->insertLayout(0, pike->GetLayout());
}


void GraphChoosing::setSrc(std::vector<const struct pcap_pkthdr*>& inputHdr, std::vector<const uchar*>& inputDta) {
    header = &inputHdr;
    pkt_data = &inputDta;
}

void GraphChoosing::Repaint() {
    auto diagramIt = diagrams.begin();
    for (; diagramIt != diagrams.end(); ++diagramIt) {
        if (std::holds_alternative<RoundGraphBackend*>(*diagramIt)) {
            RoundGraphBackend* roundGraph = std::get<RoundGraphBackend*>(*diagramIt);
            roundGraph->Repaint();
        } else if (std::holds_alternative<PikesGraphBackend*>(*diagramIt)) {
            PikesGraphBackend* pikesGraph = std::get<PikesGraphBackend*>(*diagramIt);
            pikesGraph->Repaint();
        }
    }
}



void GraphChoosing::Cleanup() {
    for (auto& graph : diagrams) {
        if (std::holds_alternative<RoundGraphBackend*>(graph)) {
            delete std::get<RoundGraphBackend*>(graph);
        } else if (std::holds_alternative<PikesGraphBackend*>(graph)) {
            delete std::get<PikesGraphBackend*>(graph);
        }
    }
    for (auto& storage : diagramsStorage) {
        if (std::holds_alternative<std::unordered_map<QString, int>*>(storage)) {
            delete std::get<std::unordered_map<QString, int>*>(storage);
        }
    }
}
