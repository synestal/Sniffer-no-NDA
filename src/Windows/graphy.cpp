#include "graphy.h"



/*
 * Версия в разработке - синтакис, логика и поведение операторов, указателей нестабильны
 *
 * To do: переопределить класс окна и графика через кастомный
 *        переделать операцию Repaint
 *
*/
graphy::graphy(QWidget *parent) : QDialog(parent) {
    chart = new QChart;
    axisX = new QValueAxis();
    axisY = new QValueAxis();
    chartView = new QChartView(chart);

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &graphy::Repaint);
    updateTimer->start(200);
};

void graphy::newChart() {
    if (header == nullptr) { return; };
    QVBoxLayout *layout = new QVBoxLayout(this);
    series = new QLineSeries();

    QPushButton* button1 = new QPushButton(this);
    button1->setText("Почасовая");
    QPushButton* button2 = new QPushButton(this);
    button2->setText("Поминутная");
    QPushButton* button3 = new QPushButton(this);
    button3->setText("Посекундная");
    QPushButton* button4 = new QPushButton(this);
    button4->setText("Почасовая - live");
    QPushButton* button5 = new QPushButton(this);
    button5->setText("Поминутная - live");
    QPushButton* button6 = new QPushButton(this);
    button6->setText("Посекундная - live");
    connect(button1, &QPushButton::clicked, this, [this](){setGraphMode(1);});
    connect(button2, &QPushButton::clicked, this, [this](){setGraphMode(2);});
    connect(button3, &QPushButton::clicked, this, [this](){setGraphMode(3);});
    connect(button4, &QPushButton::clicked, this, [this](){setGraphMode(4);});
    connect(button5, &QPushButton::clicked, this, [this](){setGraphMode(5);});
    connect(button6, &QPushButton::clicked, this, [this](){setGraphMode(6);});


    chart->addSeries(series);
    chart->setTitle("Распределение количества пакетов от времени");
    axisX->setTitleText("Время");
    chart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);
    axisY->setTitleText("Количество пакетов");
    chart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);
    chartView->setRenderHint(QPainter::Antialiasing);
    layout->addWidget(chartView);
    layout->addWidget(button1);
    layout->addWidget(button2);
    layout->addWidget(button3);
    layout->addWidget(button4);
    layout->addWidget(button5);
    layout->addWidget(button6);
    setLayout(layout);
    resize(800, 600);


}

void graphy::setGraphMode(int mode) {
    packetData.resize(0);
    timeLive = -1;
    maxValue = 0;
    switch (mode) {
    case 1:
        currentSetting = hour;
        break;
    case 2:
        currentSetting = minute;
        break;
    case 3:
        currentSetting = second;
        break;
    case 4:
        currentSetting = liveH;
        break;
    case 5:
        currentSetting = liveM;
        break;
    case 6:
        currentSetting = liveS;
        break;
    }
}

void graphy::setSrc(std::vector<const struct pcap_pkthdr*>& input) {
    header = &input;
}

void graphy::Repaint() {
    addPackets();
    int tempMax = settingsApply();
    series->clear(); // Очистить старые данные
    for (int i = 0; i < packetData.size(); ++i) {
        series->append(i, packetData[i]);
    }
    axisX->setRange(0, tempMax);
    axisY->setRange(0, maxValue);
}

int graphy::settingsApply () {
    const std::time_t t = std::time(nullptr);
    const std::tm* localTime = std::localtime(&t);
    int tempMax;

    switch (currentSetting) {
    case hour: // В сутки
        tempMax = 24;
        packetData.resize(0);
        packetData.reserve(24);
        for (int i = 0; i < 24; ++i) {
            packetData.push_back(getPacketsInHour(i));
            maxValue = packetData[i] > maxValue ? packetData[i] : maxValue;
        }
        break;
    case minute: // В час
        tempMax = 60;
        packetData.resize(0);
        packetData.reserve(60);
        for (int i = 0; i < 60; ++i) {
            packetData.push_back(getPacketsInMinute(localTime->tm_hour,i));
            maxValue = packetData[i] > maxValue ? packetData[i] : maxValue;
        }
        break;
    case second: // В минуту
        tempMax = 60;
        packetData.resize(0);
        packetData.reserve(60);
        for (int i = 0; i < 60; ++i) {
            packetData.push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,i));
            maxValue = packetData[i] > maxValue ? packetData[i] : maxValue;
        }
        break;
    case liveH:

        if (localTime->tm_hour != timeLive) {
            packetData.push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec));
            timeLive = localTime->tm_hour;
        } else {
            packetData.back() = getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec);
        }

        tempMax = packetData.size();
        maxValue = packetData.back() > maxValue ? packetData.back() : maxValue;
        break;
    case liveM:

        if (localTime->tm_min != timeLive) {
            packetData.push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec));
            timeLive = localTime->tm_min;
        } else {
            packetData.back() = getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec);
        }

        tempMax = packetData.size();
        maxValue = packetData.back() > maxValue ? packetData.back() : maxValue;
        break;
    case liveS:

        if (localTime->tm_sec != timeLive) {
            packetData.push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec));
            timeLive = localTime->tm_sec;
        } else {
            packetData.back() = getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec);
        }

        tempMax = packetData.size();
        maxValue = packetData.back() > maxValue ? packetData.back() : maxValue;

        break;
    }
    return tempMax;
}

void graphy::addPackets() {
    const int max = header->size();
    for (int i = maxSize; i < max; ++i) {
        struct tm ltime;
        const time_t local_tv_sec = (*header)[i]->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        int hh = ltime.tm_hour;
        int mm = ltime.tm_min;
        int ss = ltime.tm_sec;
        ++vault[hh][mm][ss];
    }
    maxSize = max;
}

int graphy::getPacketsInHour(int hh) {
    int temp = 0;
    for (int i = 0; i < 60; ++i) {
        temp += getPacketsInMinute(hh, i);
    }
    return temp;
}

int graphy::getPacketsInMinute(int hh, int mm) {
    int temp = 0;
    for (int i = 0; i < 60; ++i) {
        temp += getPacketsInSecond(hh, mm, i);
    }
    return temp;
}

int graphy::getPacketsInSecond(int hh, int mm, int ss) {
    return vault[hh][mm][ss];
}
























