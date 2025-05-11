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
#include <QFileDialog>
#include <QScopedPointer>

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
    explicit PacketModel(QObject *parent = nullptr);

    void setPacketStorage(const std::vector<packet_info> &storage);
    void setStartEnd(int strt);
    void setDisplayRange(int startIndex, int endIndex);
    void setColor(const QString &protocol, const QColor &color);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

private:
    const std::vector<packet_info> *PacketsStorage = nullptr;
    int startRow = 0;
    int endRow = 0;

    // Color configurations for different packet types
    QHash<QString, QColor> packetColors;
    QColor defaultColor;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void handlePacketCapturedUchar(int num, std::shared_ptr<duckdb::Connection>);
    void onRowClicked(const QModelIndex&);
    void AnalysisButtonClicked();
    void ResoursesButtonClicked();
    void updateOnScrollEvent(int);
    void updateByTimer();

private:
    void AuthTable();
    void StartSniffing(const QString &device);
    void ResumeSniffing();
    void StopSniffing();
    void PauseSniffing();

    QString processBlob(duckdb::Value packet_type_str, const QString &param);
    void UpdateTableWiew(int startRow, int endRow);

    int maxScrollValue = 0;
    int currScrollValue = 0;

    QScopedPointer<QTimer> updateTimer;

    void setDarkTheme();
    void setWhiteTheme();
    void aboutApp();
    void TutorialButtonClicked();
    void changeRowsColour();
    void SettingsButtonClicked();
    void openDB();
    void saveDB();

    bool flagFilenameChanged = false;

    // Sniffer
    std::unique_ptr<SnifferMonitoring> sniffer;
    std::string filename = "-packets.db";
    QString currentDevice;

    // Packet containers
    int sizeCurr = 0;
    int capCurr = 0;

    // Table and packet description
    std::vector<packet_info> TableStorage;
    std::unique_ptr<PacketModel> model;
    std::unique_ptr<QStandardItemModel> modelDescr;
    int rowCount = 15;

    // Resources for buttons
    std::unique_ptr<GraphChoosing> graph;
    std::unique_ptr<ResoursesView> resourse;

    // Overridden events
    void resizeEvent(QResizeEvent*) override;
    void wheelEvent(QWheelEvent *event) override;

    std::shared_ptr<duckdb::Connection> connection;

    bool selectPacketInfoFromDB(int startRow, int endRow, std::vector<packet_info>& uiMass);

    QScopedPointer<Ui::MainWindow> ui;
};

#endif
