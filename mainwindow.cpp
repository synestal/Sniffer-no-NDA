#include "mainwindow.h"
#include "ui_mainwindow.h"
/*
 *  Альфа-версия (стабильная)
 *
 *
 *
 *
*/
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    connect(ui->comboBox_7, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) { // Выпадающий список устройства
        switch(index) {
        case 1:
            AuthTable(); break;
        case 2:
            if (currentDevice != "") { ResumeSniffing(); }; break;
        case 3:
            PauseSniffing(); break;
        case 4:
            StopSniffing(); break;
        }
        ui->comboBox_7->setCurrentIndex(0);
    });

    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::AnalysisButtonClicked);
    connect(ui->ResoursesButton, &QPushButton::clicked, this, &MainWindow::ResoursesButtonClicked);
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateByTimer);
    updateTimer->start(200);
}

void MainWindow::AuthTable() {
    auto auth = std::make_unique<NCardAuth>();
    QVector<QPair<QString, QString>> devices;
    devices = auth->GetDevices();

    auto model = new QStandardItemModel(this);
    model->setColumnCount(2);
    model->setHeaderData(0, Qt::Horizontal, "Название");
    model->setHeaderData(1, Qt::Horizontal, "Описание");

    for (const QPair<QString, QString>& device : devices) {
        QStandardItem *itemFirst = new QStandardItem(device.first);
        QStandardItem *itemSecond = new QStandardItem(device.second);

        itemFirst->setFlags(itemFirst->flags() & ~Qt::ItemIsEditable);
        itemSecond->setFlags(itemSecond->flags() & ~Qt::ItemIsEditable);

        QList<QStandardItem*> rowItems;
        rowItems.append(itemFirst);
        rowItems.append(itemSecond);
        model->appendRow(rowItems);
    }

    auto tempWindow = new QDialog(this);
    auto authtable = new QTableView;
    authtable->setModel(model);
    authtable->horizontalHeader()->setStretchLastSection(true);
    authtable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

    auto layout = new QVBoxLayout;
    layout->addWidget(authtable);
    tempWindow->setLayout(layout);
    tempWindow->setWindowTitle("Таблица устройств");
    tempWindow->resize(800, 600);

    connect(authtable, &QTableView::doubleClicked, this, [=](const QModelIndex &index){
        if (index.isValid()) {
            int row = index.row();
            QString deviceName = model->item(row, 0)->text();
            StartSniffing(deviceName);
            tempWindow->close();
        }
        else {
            qDebug() << "Выбран невалидный индекс устройства";
            QMessageBox::warning(this, "Ошибка", "Выбрано некорректное устройство");
        }
    });

    tempWindow->show();
}

void MainWindow::StartSniffing(QString device) {
    StopSniffing();
    sniffer = std::make_unique<SnifferMonitoring>(device, this);
    if (!model) {
        model = new PacketModel(this);
    }

    model->setPacketStorage(TableStorage);
    ui->tableView_2->setModel(model);
    connect(sniffer.get(), &SnifferMonitoring::packetCapturedUchar, this, &MainWindow::handlePacketCapturedUchar);
    sniffer->start();
    currentDevice = device;
    ui->verticalScrollBar->setRange(0, INT_MAX);
    ui->verticalScrollBar->setValue(INT_MAX);
    connect(ui->verticalScrollBar, &QScrollBar::valueChanged, this, &MainWindow::updateOnScrollEvent);

    for(int i = 0; i < 6; ++i) {
        ui->tableView_2->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
    }
    ui->tableView_2->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    connect(ui->tableView_2, &QTableView::pressed, this, &MainWindow::onRowClicked);
}

void MainWindow::updateOnScrollEvent(int scrollPosition) {
    if (maxScrollValue <= 0) {
        return; // Предотвращение деления на ноль
    }

    int startRow = maxScrollValue * (static_cast<double>(scrollPosition) / static_cast<double>(INT_MAX));
    currScrollValue = startRow;
    int endRow = startRow + rowCount < static_cast<int>(sizeCurr) ? startRow + rowCount : static_cast<int>(sizeCurr);

    UpdateTableWiew(startRow, endRow);
}

void MainWindow::updateByTimer() {
    if(sniffer == nullptr) { return; }

    if (ui->verticalScrollBar->value() != INT_MAX) {
        if (maxScrollValue <= 0) {
            return; // Предотвращение деления на ноль
        }

        int temp = INT_MAX * (static_cast<double>(currScrollValue) / static_cast<double>(maxScrollValue));
        if ((maxScrollValue * (static_cast<double>(temp) / static_cast<double>(INT_MAX))) != currScrollValue) {
            ++temp;
        }
        ui->verticalScrollBar->setValue(temp);
        return;
    }

    int startRow = maxScrollValue;
    currScrollValue = startRow;
    int endRow = startRow + rowCount < static_cast<int>(sizeCurr) ? startRow + rowCount : static_cast<int>(sizeCurr);
    UpdateTableWiew(startRow, endRow);
}

void MainWindow::UpdateTableWiew(int startRow, int endRow) {
    if (!connection) {
        qDebug() << "Connection is null in UpdateTableWiew";
        return;
    }
    if (startRow < 0 || endRow < startRow) {
        qDebug() << "Invalid range: startRow=" << startRow << ", endRow=" << endRow;
        return;
    }
    TableStorage.clear();
    TableStorage.resize(rowCount);
    bool success = selectPacketInfoFromDB(startRow, endRow, TableStorage);
    if (!success) {
        qDebug() << "Failed to retrieve packet data or no data available";
        return;
    }
    //for (size_t i = 0; i < pkt_data.size(); ++i) {
    //    QByteArray arr(reinterpret_cast<const char*>(pkt_data[i]), header[i]->caplen);
    //    qDebug() << "Packet" << i << ":" << arr.toHex(' ');
    //}

    if (model) {
        model->setDisplayRange(0, endRow - startRow);
    } else {
        qDebug() << "Model is null in UpdateTableWiew";
    }
}

void MainWindow::handlePacketCapturedUchar(int num, std::shared_ptr<duckdb::Connection> conn) {
    maxScrollValue = static_cast<int>(num) < rowCount ? 0 : static_cast<int>(num) - rowCount;
    sizeCurr = num;
    connection = conn;
}

void MainWindow::ResumeSniffing() {
    if (sniffer == nullptr) {
        qDebug() << "Attempt to resume null sniffer";
        return;
    }
    sniffer->start();
}

void MainWindow::StopSniffing() {
    if (sniffer != nullptr) {
        sniffer->terminate();
    }
    currentDevice = "";
}

void MainWindow::PauseSniffing() {
    if (sniffer != nullptr) {
        sniffer->stopSniffing();
    }
}

void MainWindow::onRowClicked(const QModelIndex &index) {
    if (!index.isValid()) {
        qDebug() << "Invalid index in onRowClicked";
        return;
    }
    int row = index.row();
    QList<QString> payloadData = TableStorage[row].data.split('\n', Qt::SkipEmptyParts);
    modelDescr = std::make_unique<QStandardItemModel>(this);
    modelDescr->setColumnCount(1);
    ui->tableView_3->setModel(modelDescr.get());
    ui->tableView_3->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableView_3->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    for (const QString &data : payloadData) {
        QList<QStandardItem*> rowItems;
        QStandardItem *item = new QStandardItem(data);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        rowItems.append(item);
        modelDescr->setHeaderData(0, Qt::Horizontal, "Номер " + QString::number(row + currScrollValue));
        modelDescr->appendRow(rowItems);
    }
}

void MainWindow::AnalysisButtonClicked() {
    if(sniffer == nullptr) {
        qDebug() << "Sniffer is null in AnalysisButtonClicked";
        return;
    }
    graph = std::make_unique<GraphChoosing>(this);
    qDebug() << "Out of constructor";
    graph->setConnection(connection);
    connect(graph.get(), &GraphChoosing::closeRequested, this, [=]() {graph = nullptr;});
    graph->show();
}

void MainWindow::ResoursesButtonClicked() {
    resourse = std::make_unique<ResoursesView>();
    resourse->UpdateData();
    resourse->show();
}

void MainWindow::wheelEvent(QWheelEvent *event) {
    if (maxScrollValue <= 0) {
        return;
    }
    int temp = INT_MAX * (static_cast<double>(currScrollValue) / static_cast<double>(maxScrollValue));
    if ((maxScrollValue * (static_cast<double>(temp) / static_cast<double>(INT_MAX))) != currScrollValue && temp != INT_MAX) {
        ++temp;
    }
    int val = static_cast<int>(static_cast<double>(INT_MAX) / static_cast<double>(maxScrollValue) * 5.0);
    if (event->angleDelta().y() < 0) {
        ui->verticalScrollBar->setValue(temp - INT_MAX + val > 0 ? INT_MAX : temp + val);
    } else {
        ui->verticalScrollBar->setValue(temp - val > 0 ? temp - val : 0);
    }
}

void MainWindow::resizeEvent(QResizeEvent *event) {
    int visibleHeight = ui->tableView_2->viewport()->height();
    int rowHeight = ui->tableView_2->verticalHeader()->defaultSectionSize();
    if (rowHeight <= 0) {
        rowHeight = 1;
    }
    if (model) {
        rowCount = visibleHeight / rowHeight;
    }
    QMainWindow::resizeEvent(event);
}

bool MainWindow::selectPacketInfoFromDB(int startRow, int endRow, std::vector<packet_info>& uiMass) {
    if (!connection) {
        qDebug() << "Connection is null in selectPacketInfoFromDB";
        return false;
    }

    try {
        std::string query = "SELECT * FROM packets "
                            "LIMIT " + std::to_string(endRow - startRow) +
                            " OFFSET " + std::to_string(startRow);

        auto result = connection->Query(query);

        if (!result || result->HasError()) {
            qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
            return false;
        }

        size_t row_count = result->RowCount();

        if (row_count == 0) {
            qDebug() << "No data returned from query";
            return false;
        }

        // Индексы на основе структуры таблицы
        const int TS_INDEX = 0;
        const int CAPLEN_INDEX = 1;
        const int LEN_INDEX = 2;
        const int PACKET_TYPE_INDEX = 3;
        const int IPV4_SRC_IP_INDEX = 16;
        const int IPV4_DST_IP_INDEX = 17;
        const int IPV6_SRC_IP_INDEX = 23;
        const int IPV6_DST_IP_INDEX = 24;
        const int TCP_SRC_PORT_INDEX = 25;
        const int TCP_DST_PORT_INDEX = 26;
        const int UDP_SRC_PORT_INDEX = 34;
        const int UDP_DST_PORT_INDEX = 35;
        const int ARP_SRC_IP_INDEX = 48;
        const int ARP_DST_IP_INDEX = 50;
        const int DATA_INDEX = 51;

        for (size_t i = 0; i < row_count; ++i) {
            try {
                QString ts = QDateTime::fromSecsSinceEpoch(result->GetValue<int64_t>(TS_INDEX, i)).toString("yyyy:MM:dd:hh:mm:ss");
                auto caplen = result->GetValue<int16_t>(CAPLEN_INDEX, i);
                auto len = result->GetValue<int16_t>(LEN_INDEX, i);
                auto packetType = processBlob(result->GetValue(PACKET_TYPE_INDEX, i), "");

                struct {
                    QString src;
                    QString dst;
                } addressInfo;
                // Заполняем src и dst в зависимости от типа пакета
                if (packetType == "806" || packetType == "8017" || packetType == "801" || packetType == "802") {
                    try {
                        QString ipv4_src_ip = processBlob(result->GetValue(IPV4_SRC_IP_INDEX, i), "time");
                        QString ipv4_dst_ip = processBlob(result->GetValue(IPV4_DST_IP_INDEX, i), "time");
                        addressInfo.src = ipv4_src_ip;
                        addressInfo.dst = ipv4_dst_ip;
                        // Попробуем добавить порты TCP/UDP
                        try {
                            QString tcp_src_port = processBlob(result->GetValue(TCP_SRC_PORT_INDEX, i), "");
                            QString tcp_dst_port = processBlob(result->GetValue(TCP_DST_PORT_INDEX, i), "");
                            if (!tcp_src_port.isEmpty()) addressInfo.src += ":" + tcp_src_port;
                            if (!tcp_dst_port.isEmpty()) addressInfo.dst += ":" + tcp_dst_port;
                        } catch (...) {}
                        try {
                            QString udp_src_port = processBlob(result->GetValue(UDP_SRC_PORT_INDEX, i), "");
                            QString udp_dst_port = processBlob(result->GetValue(UDP_DST_PORT_INDEX, i), "");
                            if (!udp_src_port.isEmpty() && addressInfo.src.indexOf(':') == -1)
                                addressInfo.src += ":" + udp_src_port;
                            if (!udp_dst_port.isEmpty() && addressInfo.dst.indexOf(':') == -1)
                                addressInfo.dst += ":" + udp_dst_port;
                        } catch (...) {}
                    } catch (const std::exception& e) {
                        qDebug() << "Error getting IPv4 addresses:" << e.what();
                        addressInfo.src = "";
                        addressInfo.dst = "";
                    }
                } else if (packetType == "86DD6" || packetType == "86DD17" || packetType == "86DD58") {
                    try {
                        QString ipv6_src_ip = processBlob(result->GetValue(IPV6_SRC_IP_INDEX, i), "time");
                        QString ipv6_dst_ip = processBlob(result->GetValue(IPV6_DST_IP_INDEX, i), "time");
                        addressInfo.src = ipv6_src_ip;
                        addressInfo.dst = ipv6_dst_ip;
                        // Попробуем добавить порты TCP/UDP
                        try {
                            QString tcp_src_port = processBlob(result->GetValue(TCP_SRC_PORT_INDEX, i), "");
                            QString tcp_dst_port = processBlob(result->GetValue(TCP_DST_PORT_INDEX, i), "");
                            if (!tcp_src_port.isEmpty()) addressInfo.src += ":" + tcp_src_port;
                            if (!tcp_dst_port.isEmpty()) addressInfo.dst += ":" + tcp_dst_port;
                        } catch (...) {}
                        try {
                            QString udp_src_port = processBlob(result->GetValue(UDP_SRC_PORT_INDEX, i), "");
                            QString udp_dst_port = processBlob(result->GetValue(UDP_DST_PORT_INDEX, i), "");
                            if (!udp_src_port.isEmpty() && addressInfo.src.indexOf(':') == -1)
                                addressInfo.src += ":" + udp_src_port;
                            if (!udp_dst_port.isEmpty() && addressInfo.dst.indexOf(':') == -1)
                                addressInfo.dst += ":" + udp_dst_port;
                        } catch (...) {}
                    } catch (const std::exception& e) {
                        qDebug() << "Error getting IPv6 addresses:" << e.what();
                        addressInfo.src = "";
                        addressInfo.dst = "";
                    }
                } else if (packetType == "86") {
                    try {
                        QString arp_src_ip = processBlob(result->GetValue(ARP_SRC_IP_INDEX, i), "time");
                        QString arp_dst_ip = processBlob(result->GetValue(ARP_DST_IP_INDEX, i), "time");
                        addressInfo.src = arp_src_ip;
                        addressInfo.dst = arp_dst_ip;
                    } catch (const std::exception& e) {
                        qDebug() << "Error getting ARP addresses:" << e.what();
                        addressInfo.src = "";
                        addressInfo.dst = "";
                    }
                } else {
                    // Если тип пакета не ipv4/ipv6/arp, оставляем поля пустыми
                    addressInfo.src = "";
                    addressInfo.dst = "";
                }
                if (caplen <= 0) {
                    qDebug() << "Row" << i << ": Invalid caplen value:" << caplen;
                    continue;
                }
                auto* hdr = new pcap_pkthdr;
                hdr->ts.tv_sec = 0;
                hdr->ts.tv_usec = 0;
                hdr->caplen = caplen;
                hdr->len = len;
                uiMass[i].index = QString::number(startRow + i);
                uiMass[i].timeInfo = ts;
                uiMass[i].lenInfo = QString::number(caplen);
                uiMass[i].srcInfo = addressInfo.src;
                uiMass[i].destInfo = addressInfo.dst;

                if (packetType == "806") {
                    packetType = "IPv4 - TCP";
                } else if (packetType == "8017") {
                    packetType = "IPv4 - UDP";
                } else if (packetType == "801") {
                    packetType = "IPv4 - ICMP";
                } else if (packetType == "802") {
                    packetType = "IPv4 - IGMP";
                } else if (packetType == "86DD6") {
                    packetType = "IPv6 - TCP";
                } else if (packetType == "86DD17") {
                    packetType = "IPv6 - UDP";
                } else if (packetType == "86DD58") {
                    packetType = "IPv6 - ICMPv6";
                } else if (packetType == "86") {
                    packetType = "ARP";
                } else if (packetType == "8035") {
                    packetType = "RARP";
                } else if (packetType == "8137") {
                    packetType = "IPX";
                } else if (packetType == "8847") {
                    packetType = "MPLS Unicast";
                } else if (packetType == "8848") {
                    packetType = "MPLS Multicast";
                } else if (packetType == "8863") {
                    packetType = "PPPoE Discovery";
                } else if (packetType == "8864") {
                    packetType = "PPPoE Session";
                } else {
                    packetType = "Unknown: 0x" + packetType;
                }
                uiMass[i].packetType = packetType;
                uiMass[i].data = processBlob(result->GetValue(DATA_INDEX, i), "data");
            } catch (const std::exception& e) {
                qDebug() << "Error processing row" << i << ":" << e.what();
                continue;
            }
        }
        return true;
    } catch (const std::exception& e) {
        qDebug() << "DuckDB error: " << e.what();
        return false;
    }
}

MainWindow::~MainWindow() {
    StopSniffing();
    delete ui;
}
