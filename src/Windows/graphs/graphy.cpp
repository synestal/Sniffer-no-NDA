#include "src/Windows/graphs/graphy.h"



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

GraphBackend::GraphBackend(QWidget *parent, std::vector<const struct pcap_pkthdr*>& hdr, std::vector<const uchar*>& dta) : QDialog(parent), header(&hdr), pkt_data(&dta) {
    QPushButton* button1 = new QPushButton(this);
    button1->setText("Круговая");
    QPushButton* button2 = new QPushButton(this);
    button2->setText("Пиковая");
    connect(button1, &QPushButton::clicked, this, [this](){createCircleDiagram();});
    connect(button2, &QPushButton::clicked, this, [this](){createPikeDiagram();});
    layout = new QVBoxLayout;
    layout->addWidget(button1);
    layout->addWidget(button2);
    setLayout(layout);
    resize(1920, 1080);

    this->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &GraphBackend::Repaint);
    updateTimer->start(200);
}

void GraphBackend::closeEvent(QCloseEvent *event) {
    int response = QMessageBox::question(this, "Закрытие", "Вы уверены, что хотите закрыть окно?");
    if (response == QMessageBox::Yes) {
        emit closeRequested();
        event->accept();
    } else {
        event->ignore();
    }
}

void GraphBackend::createCircleDiagram() {
    std::unordered_map<QString, int>* ObjectsCircle = new std::unordered_map<QString, int>;
    RoundGraphBackend* graph = new RoundGraphBackend(*ObjectsCircle);
    diagrams.push_back(graph);
    diagramsStorage.push_back(ObjectsCircle);
    layout->insertLayout(0, graph->GetLayout());
}

void GraphBackend::createPikeDiagram() {
    PikesGraphBackend* pike = new PikesGraphBackend();
    diagrams.push_back(pike);
    layout->insertLayout(0, pike->GetLayout());
}


void GraphBackend::setSrc(std::vector<const struct pcap_pkthdr*>& inputHdr, std::vector<const uchar*>& inputDta) {
    header = &inputHdr;
    pkt_data = &inputDta;
}

void GraphBackend::Repaint() {
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



void GraphBackend::Cleanup() {
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




















