#ifndef GRAPHY_H
#define GRAPHY_H

#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QVBoxLayout>
#include <QDateTime>
#include <QtCharts/QChart>
#include <QDialog>
#include <QVector>
#include <QPushButton>



#include <ctime>


#include "src/NCard/functionstodeterminepacket.h"




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


    enum Settings {hour, minute, second, liveH, liveM, liveS};
    Settings currentSetting = second;
};

#endif // GRAPHY_H

