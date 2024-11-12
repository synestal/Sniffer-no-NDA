#ifndef GRAPHY_H
#define GRAPHY_H

#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QVBoxLayout>
#include <QtCharts/QChart>
#include <QDialog>
#include <QVector>
#include <QPushButton>
#include <QTimer>
#include <QMessageBox>



#include <ctime>
#include <unordered_map>


#include "src/NCard/functionstodeterminepacket.h"
#include "src/Windows/graphs/pike/pikegraph.h"
#include "src/Windows/graphs/round/roundgraph.h"




using GraphPtr = std::variant<RoundGraphBackend*, PikesGraphBackend*>;
using GraphStoragePtr = std::variant<std::unordered_map<QString, int>*, std::pair<std::array<std::array<std::array<int,60>,60>, 24>*, std::vector<int>*>*>;

class GraphBackend : public QDialog {
    Q_OBJECT

signals:
    void closeRequested();
public:
    GraphBackend(QWidget *parent, std::vector<const struct pcap_pkthdr*>& hdr, std::vector<const uchar*>& dta);
    ~GraphBackend() { Cleanup(); }
    void closeEvent(QCloseEvent *event);

    void createCircleDiagram();
    void createPikeDiagram();

    void setSrc(std::vector<const struct pcap_pkthdr*>& inputHdr, std::vector<const uchar*>& inputDta);
public slots:
    void Repaint();

private:
    void Cleanup();

    std::vector<const struct pcap_pkthdr*>*  header = nullptr;
    std::vector<const uchar*>* pkt_data = nullptr;

    std::list<GraphPtr> diagrams;
    std::list<GraphStoragePtr> diagramsStorage;

    QVBoxLayout *layout;
    QTimer *updateTimer = nullptr;
};

#endif // GRAPHY_H

