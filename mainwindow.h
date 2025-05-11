#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include <QMainWindow>
#include <QPalette>
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
#include <QColor>


#include <iostream>
#include <algorithm>
#include <vector>
#include <Winsock2.h>
#include <memory>


#include "src/NCard/ncardauth.h"
#include "pcap.h"


#include "packages/service_pcap/misc.h"
#include "src/NCard/sniffermonitoring.h"
#include "src/Windows/resoursesview.h"
#include "duckdb.hpp"

#include "src/Windows/graphs/graphchoosing.h"




QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE


class PacketModel : public QAbstractTableModel {
    Q_OBJECT
public:
    PacketModel(QObject *parent = nullptr) : QAbstractTableModel(parent) {
        ipv4TcpColor = QColor(0, 255, 0);
        ipv4UdpColor = QColor(50, 150, 50);
        ipv4IcmpColor = QColor(100, 255, 100);
        ipv4IgmpColor = QColor(200, 255, 200);
        ipv4UnknownColor = QColor(220, 255, 220);
        ipv6TcpColor = QColor(255, 0, 0);
        ipv6UdpColor = QColor(150, 50, 50);
        ipv6IcmpColor = QColor(255, 100, 100);
        ipv6IgmpColor = QColor(255, 200, 200);
        ipv6UnknownColor = QColor(255, 220, 220);
        arpColor = QColor(0, 0, 255);
        rarpColor = QColor(50, 50, 255);
        ipxColor = QColor(100, 100, 255);
        mplsUnicastColor = QColor(150, 150, 255);
        mplsMulticastColor = QColor(200, 200, 255);
        pppoeDiscoveryColor = QColor(100, 100, 100);
        pppoeSessionColor = QColor(150, 150, 150);
        defaultColor = Qt::darkGreen;
    }

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

    void setColor(QString protocol, QColor color) {
        if (protocol == "IPv4 - TCP") {
            ipv4TcpColor = color;
        } else if (protocol == "IPv4 - UDP") {
            ipv4UdpColor = color;
        } else if (protocol == "IPv4 - ICMP") {
            ipv4IcmpColor = color;
        } else if (protocol == "IPv4 - IGMP") {
            ipv4IgmpColor = color;
        } else if (protocol == "IPv4 - Unknown") {
            ipv4UnknownColor = color;
        } else if (protocol == "IPv6 - TCP") {
            ipv6TcpColor = color;
        } else if (protocol == "IPv6 - UDP") {
            ipv6UdpColor = color;
        } else if (protocol == "IPv6 - ICMP") {
            ipv6IcmpColor = color;
        } else if (protocol == "IPv6 - IGMP") {
            ipv6IgmpColor = color;
        } else if (protocol == "IPv6 - Unknown") {
            ipv6UnknownColor = color;
        } else if (protocol == "ARP") {
            arpColor = color;
        } else if (protocol == "RARP") {
            rarpColor = color;
        } else if (protocol == "IPX") {
            ipxColor = color;
        } else if (protocol == "MPLS Unicast") {
            mplsUnicastColor = color;
        } else if (protocol == "MPLS Multicast") {
            mplsMulticastColor = color;
        } else if (protocol == "PPPoE Discovery") {
            pppoeDiscoveryColor = color;
        } else if (protocol == "PPPoE Session") {
            pppoeSessionColor = color;
        } else {
            defaultColor = color;
        }
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override {
        return PacketsStorage ? (endRow - startRow) : 0;
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override {
        return 6;
    }

    QColor ipv4TcpColor;
    QColor ipv4UdpColor;
    QColor ipv4IcmpColor;
    QColor ipv4IgmpColor;
    QColor ipv4UnknownColor;
    QColor ipv6TcpColor;
    QColor ipv6UdpColor;
    QColor ipv6IcmpColor;
    QColor ipv6IgmpColor;
    QColor ipv6UnknownColor;
    QColor arpColor;
    QColor rarpColor;
    QColor ipxColor;
    QColor mplsUnicastColor;
    QColor mplsMulticastColor;
    QColor pppoeDiscoveryColor;
    QColor pppoeSessionColor;
    QColor defaultColor;

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
                if (packet.packetType == "IPv4 - TCP") {
                    return QBrush(ipv4TcpColor);
                } else if (packet.packetType == "IPv4 - UDP") {
                    return QBrush(ipv4UdpColor);
                } else if (packet.packetType == "IPv4 - ICMP") {
                    return QBrush(ipv4IcmpColor);
                } else if (packet.packetType == "IPv4 - IGMP") {
                    return QBrush(ipv4IgmpColor);
                } else if (packet.packetType == "IPv4 - Unknown") { // Not done
                    return QBrush(ipv4UnknownColor);
                } else if (packet.packetType == "IPv6 - TCP") {
                    return QBrush(ipv6TcpColor);
                } else if (packet.packetType == "IPv6 - UDP") {
                    return QBrush(ipv6UdpColor);
                } else if (packet.packetType == "IPv6 - ICMP") {
                    return QBrush(ipv6IcmpColor);
                } else if (packet.packetType == "IPv6 - IGMP") {
                    return QBrush(ipv6IgmpColor);
                } else if (packet.packetType == "IPv6 - Unknown") { // Not done
                    return QBrush(ipv6UnknownColor);
                } else if (packet.packetType == "ARP") {
                    return QBrush(arpColor);
                } else if (packet.packetType == "RARP") {
                    return QBrush(rarpColor);
                } else if (packet.packetType == "IPX") {
                    return QBrush(ipxColor);
                } else if (packet.packetType == "MPLS Unicast") {
                    return QBrush(mplsUnicastColor);
                } else if (packet.packetType == "MPLS Multicast") {
                    return QBrush(mplsMulticastColor);
                } else if (packet.packetType == "PPPoE Discovery") {
                    return QBrush(pppoeDiscoveryColor);
                } else if (packet.packetType == "PPPoE Session") {
                    return QBrush(pppoeSessionColor);
                } else {
                    return QBrush(defaultColor);
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

    QString processBlob(duckdb::Value packet_type_str, QString param) {
        QString bytes = "";
        try {
            auto blob = packet_type_str.GetValueUnsafe<std::string>();
            if (param == "data") {
                bytes = "Тело " + QString::number(blob.size()) + " байт:\n";
            }
            int position = -1;
            for (char c : blob) {
                position++;

                if (param == "data") {
                    bytes += QString::number(static_cast<uint8_t>(c), 16).toUpper().rightJustified(2, '0');;
                } else {
                    bytes += QString::number(static_cast<uint8_t>(c));
                }

                if (param == "time" && position != blob.size() - 1) {
                    bytes += ".";
                }
                if (param == "data" && position != blob.size() - 1) {
                    bytes += " ";
                }
                if (param == "data" && position != blob.size() - 1  && position != 0 && position % 16 == 0) {
                    bytes += "\n";
                }
            }
            if (param == "data") {
                if(position == -1) {
                    bytes = "В пакете нет тела";
                }
                //qDebug() << bytes;
            }
        } catch (const std::exception& e) {
            qDebug() << "Error processBlob:" << QString::fromStdString(packet_type_str.GetValueUnsafe<std::string>()) << e.what();
        }
        return bytes;
    }

    void UpdateTableWiew(int, int); // Обновление таблицы
    int maxScrollValue = 0;         // Первый элемент из диапазона на вывод - unstable
    int currScrollValue = 0;        // Положение ползунка - unstable

    QTimer *updateTimer;

    void setDarkTheme();
    void setWhiteTheme();
    void aboutApp();
    void TutorialButtonClicked();
    void changeRowsColour();
    void SettingsButtonClicked();

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

    bool selectPacketInfoFromDB(int, int, std::vector<packet_info>&);

    Ui::MainWindow *ui;
};


#endif
