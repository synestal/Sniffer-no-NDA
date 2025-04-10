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
    qDebug() << ui->RoundButton;
    connect(ui->RoundButton, &QPushButton::clicked, this, &GraphChoosing::createCircleDiagram);
    connect(ui->PikeButton, &QPushButton::clicked, this, &GraphChoosing::createPikeDiagram);
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
    std::unordered_map<QString, int>* ObjectsCircle = new std::unordered_map<QString, int>;
    RoundGraphBackend* graph = new RoundGraphBackend(*ObjectsCircle);
    graph->setConnection(connection);
    diagrams.push_back(graph);
    diagramsStorage.push_back(ObjectsCircle);
    ui->MainLayout->insertLayout(0, graph->GetLayout());
}

void GraphChoosing::createPikeDiagram() {
    std::array<std::array<std::array<int,60>,60>, 24>* vault = new std::array<std::array<std::array<int, 60>, 60>, 24>{};
    std::vector<int>* packetData = new std::vector<int>;
    diagramsStorage.push_back(new std::pair<std::array<std::array<std::array<int,60>,60>, 24>*, std::vector<int>*>(vault, packetData));

    PikesGraphBackend* pike = new PikesGraphBackend(*vault, *packetData, *header);
    pike->setConnection(connection);
    diagrams.push_back(pike);
    ui->MainLayout->insertLayout(0, pike->GetLayout());
}


void GraphChoosing::setSrc(std::vector<const struct pcap_pkthdr*>& inputHdr, std::vector<const uchar*>& inputDta) {
    header = &inputHdr;
    pkt_data = &inputDta;
}

void GraphChoosing::Repaint() {
    functionsToDeterminePacket* determinator = new functionsToDeterminePacket(*header, *pkt_data);

    auto diagramIt = diagrams.begin();
    auto storageIt = diagramsStorage.begin();
    for (; diagramIt != diagrams.end() && storageIt != diagramsStorage.end(); ++diagramIt, ++storageIt) {
        if (std::holds_alternative<RoundGraphBackend*>(*diagramIt)) {
            RoundGraphBackend* roundGraph = std::get<RoundGraphBackend*>(*diagramIt);
            roundGraph->Repaint();
        } else if (std::holds_alternative<PikesGraphBackend*>(*diagramIt)) {
            PikesGraphBackend* pikesGraph = std::get<PikesGraphBackend*>(*diagramIt);
            pikesGraph->Repaint();
        }
    }
    delete determinator;
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
        } else if (std::holds_alternative<std::pair<std::array<std::array<std::array<int,60>,60>, 24>*, std::vector<int>*>*>(storage)) {
            delete std::get<std::pair<std::array<std::array<std::array<int,60>,60>, 24>*, std::vector<int>*>*>(storage);
        }
    }
}
