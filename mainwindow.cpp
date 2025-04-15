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
    for (auto h : header) {
        delete h;
    }
    for (auto p : pkt_data) {
        delete[] p;
    }
    header.clear();
    pkt_data.clear();
    bool success = selectPacketInfoFromDB(startRow, endRow, &header, &pkt_data);
    if (!success || header.empty() || pkt_data.empty()) {
        qDebug() << "Failed to retrieve packet data or no data available";
        return;
    }
    //for (size_t i = 0; i < pkt_data.size(); ++i) {
    //    QByteArray arr(reinterpret_cast<const char*>(pkt_data[i]), header[i]->caplen);
    //    qDebug() << "Packet" << i << ":" << arr.toHex(' ');
    //}
    std::unique_ptr<functionsToDeterminePacket> determinator =
        std::make_unique<functionsToDeterminePacket>(header, pkt_data);
    determinator->mainhandler(TableStorage, startRow, endRow);

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
    if (row < 0 || row >= static_cast<int>(header.size()) || row >= static_cast<int>(pkt_data.size())) {
        qDebug() << "Row index out of bounds: " << row << ", header size: " << header.size()
                 << ", pkt_data size: " << pkt_data.size();
        return;
    }
    auto determinator = std::make_unique<functionsToDeterminePacket>(header, pkt_data);
    QList<QString> payloadData = determinator->headerDataGetter(header[row], pkt_data[row]);
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
    graph = std::make_unique<GraphChoosing>(this, header, pkt_data);
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

bool MainWindow::selectPacketInfoFromDB(int startRow, int endRow, std::vector<const struct pcap_pkthdr*>* header, std::vector<const uchar*>* pkt_data) {
    if (!connection) {
        qDebug() << "Connection is null in selectPacketInfoFromDB";
        return false;
    }
    if (!header || !pkt_data) {
        qDebug() << "Invalid header or pkt_data pointers";
        return false;
    }
    try {
        std::string query = "SELECT ts, caplen, len, data FROM packets "
                            "LIMIT " + std::to_string(endRow - startRow) +
                            " OFFSET " + std::to_string(startRow);
        //qDebug() << QString::fromStdString(query);
        auto result = connection->Query(query);
        if (!result || result->HasError()) {
            qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
            return false;
        }
        size_t row_count = result->RowCount();
        //qDebug() << "Rows returned:" << row_count;
        if (row_count == 0) {
            qDebug() << "No data returned from query";
            return false;
        }
        for (size_t i = 0; i < row_count; ++i) {
            try {
                auto ts = result->GetValue<int64_t>(0, i);
                auto caplen = result->GetValue<int16_t>(1, i);
                auto len = result->GetValue<int16_t>(2, i);

                if (caplen <= 0) {
                    qDebug() << "Row" << i << ": Invalid caplen value:" << caplen;
                    continue;
                }
                const duckdb::Value& blob_val = result->GetValue(3, i);
                if (blob_val.IsNull()) {
                    qDebug() << "Row" << i << ": BLOB is null, skipping.";
                    continue;
                }
                auto blob = blob_val.GetValueUnsafe<duckdb::string_t>();
                if (blob.GetSize() < static_cast<size_t>(caplen)) {
                    qDebug() << "Row" << i << ": BLOB size" << blob.GetSize()
                             << "is less than caplen" << caplen << ", skipping.";
                    continue;
                }
                auto* hdr = new pcap_pkthdr;
                hdr->ts.tv_sec = ts;
                hdr->ts.tv_usec = 0;
                hdr->caplen = caplen;
                hdr->len = len;
                auto* pkt = new uchar[caplen];
                memcpy(pkt, blob.GetData(), caplen);
                header->push_back(hdr);
                pkt_data->push_back(pkt);
                //qDebug() << "Row" << i << ": Packet inserted, caplen:" << caplen;
            } catch (const std::exception& e) {
                qDebug() << "Error processing row" << i << ":" << e.what();
                continue;
            }
        }
        return !header->empty();
    } catch (const std::exception& e) {
        qDebug() << "DuckDB error: " << e.what();
        return false;
    }
}

MainWindow::~MainWindow() {
    StopSniffing();
    for (auto h : header) {
        delete h;
    }
    for (auto p : pkt_data) {
        delete[] p;
    }
    delete ui;
}
