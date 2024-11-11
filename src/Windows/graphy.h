#ifndef GRAPHY_H
#define GRAPHY_H

#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QVBoxLayout>
#include <QDateTime>
#include <QtCharts/QChart>
#include <QDialog>
#include <QVector>
#include <QPushButton>
#include <QTimer>
#include <QMessageBox>



#include <ctime>
#include <unordered_map>


#include "src/NCard/functionstodeterminepacket.h"
#include "src/Windows/pikegraph.h"


class graphy : public QDialog {
    Q_OBJECT
public:
    graphy(QWidget *parent = nullptr);

    void setSrc(std::vector<const struct pcap_pkthdr*>&);
    void newChart();
    
    void Repaint();

public slots:
    void setGraphMode(int);

private:
    void addPackets();
    int getPacketsInHour(int);
    int getPacketsInMinute(int, int);
    int getPacketsInSecond(int, int, int);

    int settingsApply();

    std::vector<const struct pcap_pkthdr*>*  header = nullptr;
    std::array<std::array<std::array<int,60>,60>, 24> vault;
    QVector<int> packetData;
    QChart* chart;
    QValueAxis *axisX;
    QValueAxis *axisY;
    QChartView *chartView;
    QLineSeries* series;


    int maxSize = 0;
    int maxValue = 0;
    int timeLive = -1;


    QTimer *updateTimer = nullptr;


    enum Settings {hour, minute, second, liveH, liveM, liveS};
    Settings currentSetting = second;
};







class RoundGraph : public QDialog {
    Q_OBJECT
public:
    RoundGraph(std::unordered_map<QString, int>& obj, QWidget *parent = nullptr);

    QChartView* GetChart();
    void Repaint();
    int maxValCounted = 0; //Сколько пакетов было посчитано
private:
    void ConstructGraph();

    QChartView *chartView = nullptr;
    QChart* chart = nullptr;
    QPieSeries* series = nullptr;
    std::unordered_map<QString, int>* ObjectsCount = nullptr;
};



using GraphPtr = std::variant<RoundGraph*, PikesGraphBackend*>;
using GraphStoragePtr = std::variant<std::unordered_map<QString, int>*, std::pair<std::array<std::array<std::array<int,60>,60>, 24>, std::vector<int>>*>;

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

    //Unused
    int timeLive = -1;
    void addPackets();
    int getPacketsInHour(int);
    int getPacketsInMinute(int, int);
    int getPacketsInSecond(int, int, int);
    int settingsApply();

};

#endif // GRAPHY_H

