#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include <QMainWindow>
#include <QDialog>
#include <QThread>
#include <QStringListModel>
#include <QStandardItemModel>
#include <QPushButton>
#include <QTimer>
#include <QScrollBar>
#include <QList>
#include <QStandardItem>
#include <QApplication>


#include <iostream>
#include <algorithm>
#include <vector>
#include <Winsock2.h>
#include <memory>


#include "src/NCard/ncardauth.h"
#include "pcap.h"


#include "packages/service_pcap/misc.h"
#include "src/NCard/sniffermonitoring.h"
#include "src/NCard/functionstodeterminepacket.h"
#include "src/Windows/graphs/graphy.h"
#include "src/Windows/resoursesview.h"
#include "duckdb.hpp"

#include "src/Windows/graphs/graphchoosing.h"




QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE


class PacketModel : public QAbstractTableModel {
    Q_OBJECT
public:
    PacketModel(QObject *parent = nullptr) : QAbstractTableModel(parent) {}

    void setPacketStorage(const std::vector<packet_info> &storage) {
        PacketsStorage = &storage;
    }
    void setStartEnd(int strt) {
        startRow = strt;
        endRow = strt;
    }
    void setDisplayRange(int startIndex, int endIndex) {
        beginResetModel();
        startRow = startIndex;
        endRow = endIndex;
        emit dataChanged(index(startRow, 0), index(endRow - 1, columnCount() - 1));
        endResetModel();
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override {
        return PacketsStorage ? (endRow - startRow) : 0;
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override {
        return 6;
    }

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override {
        if (!index.isValid() || !PacketsStorage) {
            return QVariant();
        }

        if (startRow + index.row() >= PacketsStorage->size()) {
            return QVariant();
        }

        const auto &packet = PacketsStorage->at(startRow + index.row());
        if (role == Qt::DisplayRole) {
                switch (index.column()) {
                    case 0: return packet.index;
                    case 1: return packet.timeInfo;
                    case 2: return packet.lenInfo;
                    case 3: return packet.srcInfo;
                    case 4: return packet.destInfo;
                    case 5: return packet.packetType;
                    default: return QVariant();
                }
            } else if (role == Qt::BackgroundRole) {
                if (packet.packetType ==        "IPv4 - TCP") {
                    return QBrush(QColor(0, 255, 0));
                } else if (packet.packetType == "IPv4 - UDP") {
                    return QBrush(QColor(50, 150, 50));
                } else if (packet.packetType == "IPv4 - ICMP") {
                    return QBrush(QColor(100, 255, 100));
                } else if (packet.packetType == "IPv4 - IGMP") {
                    return QBrush(QColor(200, 255, 200));
                } else if (packet.packetType == "IPv4 - Unknown") { // Not done
                    return QBrush(QColor(220, 255, 220));
                } else if (packet.packetType == "IPv6 - TCP") {
                    return QBrush(QColor(255, 0, 0));
                } else if (packet.packetType == "IPv6 - UDP") {
                    return QBrush(QColor(150, 50, 50));
                } else if (packet.packetType == "IPv6 - ICMP") {
                    return QBrush(QColor(255, 100, 100));
                } else if (packet.packetType == "IPv6 - IGMP") {
                    return QBrush(QColor(255, 200, 200));
                } else if (packet.packetType == "IPv6 - Unknown") { // Not done
                    return QBrush(QColor(255, 220, 220));
                } else if (packet.packetType == "ARP") {
                    return QBrush(QColor(0, 0, 255));
                } else if (packet.packetType == "RARP") {
                    return QBrush(QColor(50, 50, 255));
                } else if (packet.packetType == "IPX") {
                    return QBrush(QColor(100, 100, 255));
                } else if (packet.packetType == "MPLS Unicast") {
                    return QBrush(QColor(150, 150, 255));
                } else if (packet.packetType == "MPLS Multicast") {
                    return QBrush(QColor(200, 200, 255));
                } else if (packet.packetType == "PPPoE Discovery") {
                    return QBrush(QColor(100, 100, 100));
                } else if (packet.packetType == "PPPoE Session") {
                    return QBrush(QColor(150, 150, 150));
                } else {
                    return QBrush(Qt::darkGreen);
                }
            }
        return QVariant();

    }

    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override {
        if (role == Qt::DisplayRole) {
            if (orientation == Qt::Horizontal) {
                switch (section) {
                    case 0: return QString("Индекс");
                    case 1: return QString("Время");
                    case 2: return QString("Длина");
                    case 3: return QString("Отправитель");
                    case 4: return QString("Получатель");
                    case 5: return QString("Тип пакета");
                    default: return QVariant();
                }
            }
        }
        return QVariant();
    }

private:
    const std::vector<packet_info> *PacketsStorage = nullptr;
    int startRow = 0;
    int endRow = 0;
};


                        /////////////////
                        //END OF CLASS//
                        ////////////////


class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void handlePacketCapturedUchar(int num, std::shared_ptr<duckdb::Connection>);

    void onRowClicked(const QModelIndex&);
    void AnalysisButtonClicked();
    void ResoursesButtonClicked();

    void updateOnScrollEvent(int);  // Обновление параметров при ручной прокрутке
    void updateByTimer();           // Обновление параметров каждые n мс

private:
    void AuthTable();
    void StartSniffing(QString);
    void ResumeSniffing();
    void StopSniffing();
    void PauseSniffing();

    void UpdateTableWiew(int, int); // Обновление таблицы
    int maxScrollValue = 0;         // Первый элемент из диапазона на вывод - unstable
    int currScrollValue = 0;        // Положение ползунка - unstable

    QTimer *updateTimer;

    // Сниффинг
    std::unique_ptr<SnifferMonitoring> sniffer = nullptr;
    QString currentDevice;

    // Контейнеры пакетов
    int sizeCurr = 0;
    int capCurr = 0;

    // Таблица и описание пакета
    std::vector<packet_info> TableStorage;
    PacketModel* model = nullptr;
    std::unique_ptr<QStandardItemModel> modelDescr = nullptr;
    int rowCount = 15;

    // Ресурсы для кнопок
    std::unique_ptr<GraphChoosing> graph = nullptr;
    std::unique_ptr<ResoursesView> resourse = nullptr;

    // Переопределенные события
    void resizeEvent(QResizeEvent*) override;
    void wheelEvent(QWheelEvent *event) override;

    std::shared_ptr<duckdb::Connection> connection = nullptr;

    std::vector<const struct pcap_pkthdr*> header;
    std::vector<const uchar*> pkt_data;
    bool selectPacketInfoFromDB(int, int, std::vector<const struct pcap_pkthdr*>*, std::vector<const uchar*>*);

    Ui::MainWindow *ui;
};


#endif
