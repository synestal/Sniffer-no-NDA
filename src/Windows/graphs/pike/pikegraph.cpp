#include "src/Windows/graphs/pike/pikegraph.h"

PikesGraphBackend::PikesGraphBackend(std::array<std::array<std::array<int,60>,60>, 24>& obj, std::vector<int>& vect, std::vector<const struct pcap_pkthdr*>& hdr, QWidget *parent)
        : QDialog(parent), vault(&obj), packetData(&vect), header(&hdr) {
        ConstructGraph();
    }

    QVBoxLayout* PikesGraphBackend::GetLayout() {
        return layout;
    }

    void PikesGraphBackend::Repaint() {
        addPackets();
        int tempMax = settingsApply();
        graph->setMaxObjects(tempMax, maxValue, prevMaxSize);
        graph->Repaint();
    }

    void PikesGraphBackend::ConstructGraph() {
        layout = new QVBoxLayout;
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

        graph = new PikesGraph(*packetData);
        layout->addWidget(graph->GetChart());
        layout->addWidget(button1);
        layout->addWidget(button2);
        layout->addWidget(button3);
        layout->addWidget(button4);
        layout->addWidget(button5);
        layout->addWidget(button6);
    }


    void PikesGraphBackend::setGraphMode(int mode) {
        packetData->resize(0);
        timeLive = -1;
        maxValue = 0;
        prevMaxSize = 0;
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

    void PikesGraphBackend::addPackets() {
        const int max = header->size();
        for (int i = maxSize; i < max; ++i) {
            struct tm ltime;
            const time_t local_tv_sec = (*header)[i]->ts.tv_sec;
            localtime_s(&ltime, &local_tv_sec);
            int hh = ltime.tm_hour;
            int mm = ltime.tm_min;
            int ss = ltime.tm_sec;
            ++(*vault)[hh][mm][ss];
        }
        maxSize = max;
    }


    int PikesGraphBackend::settingsApply () {
        const std::time_t t = std::time(nullptr);
        const std::tm* localTime = std::localtime(&t);
        int tempMax = 0;

        switch (currentSetting) {
        case hour: // В сутки
            tempMax = 24; packetData->resize(0); packetData->reserve(24);
            for (int i = 0; i < 24; ++i) {
                packetData->push_back(getPacketsInHour(i));
                maxValue = (*packetData)[i] > maxValue ? (*packetData)[i] : maxValue;
            }
            break;
        case minute: // В час
            tempMax = 60; packetData->resize(0); packetData->reserve(60);
            for (int i = 0; i < 60; ++i) {
                packetData->push_back(getPacketsInMinute(localTime->tm_hour,i));
                maxValue = (*packetData)[i] > maxValue ? (*packetData)[i] : maxValue;
            }
            break;
        case second: // В минуту
            tempMax = 60; packetData->resize(0); packetData->reserve(60);
            for (int i = 0; i < 60; ++i) {
                packetData->push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min, i));
                maxValue = (*packetData)[i] > maxValue ? (*packetData)[i] : maxValue;
            }
            break;
        case liveH:
            if (localTime->tm_hour != timeLive) {
                packetData->push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec));
                timeLive = localTime->tm_hour;
            } else {
                packetData->back() = getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec);
            }
            tempMax = packetData->size();
            prevMaxSize = tempMax;
            maxValue = packetData->back() > maxValue ? packetData->back() : maxValue;
            break;
        case liveM:
            if (localTime->tm_min != timeLive) {
                packetData->push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec));
                timeLive = localTime->tm_min;
            } else {
                packetData->back() = getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec);
            }
            tempMax = packetData->size();
            prevMaxSize = tempMax;
            maxValue = packetData->back() > maxValue ? packetData->back() : maxValue;
            break;
        case liveS:
            if (localTime->tm_sec != timeLive) {
                packetData->push_back(getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec));
                timeLive = localTime->tm_sec;
            } else {
                packetData->back() = getPacketsInSecond(localTime->tm_hour,localTime->tm_min,localTime->tm_sec);
            }
            tempMax = packetData->size();
            prevMaxSize = tempMax;
            maxValue = packetData->back() > maxValue ? packetData->back() : maxValue;
            break;
        }
        return tempMax;
    }

    int PikesGraphBackend::getPacketsInHour(int hh) {
        int temp = 0;
        for (int i = 0; i < 60; ++i) {
            temp += getPacketsInMinute(hh, i);
        }
        return temp;
    }

    int PikesGraphBackend::getPacketsInMinute(int hh, int mm) {
        int temp = 0;
        for (int i = 0; i < 60; ++i) {
            temp += getPacketsInSecond(hh, mm, i);
        }
        return temp;
    }

    int PikesGraphBackend::getPacketsInSecond(int hh, int mm, int ss) {
        return (*vault)[hh][mm][ss];
    }


