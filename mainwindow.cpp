#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QColorDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QHeaderView>
#include <QRegularExpression>
#include <QWheelEvent>
#include <limits>
#include <sstream>

/*
 *  Improved version with memory leak fixes
 *  and performance optimizations
 */

// PacketModel Implementation
PacketModel::PacketModel(QObject *parent) : QAbstractTableModel(parent) {
    // Initialize with default colors
    packetColors = {
        {"IPv4 - TCP", QColor(0, 255, 0)},
        {"IPv4 - UDP", QColor(50, 150, 50)},
        {"IPv4 - ICMP", QColor(100, 255, 100)},
        {"IPv4 - IGMP", QColor(200, 255, 200)},
        {"IPv4 - Unknown", QColor(220, 255, 220)},
        {"IPv6 - TCP", QColor(255, 0, 0)},
        {"IPv6 - UDP", QColor(150, 50, 50)},
        {"IPv6 - ICMP", QColor(255, 100, 100)},
        {"IPv6 - IGMP", QColor(255, 200, 200)},
        {"IPv6 - Unknown", QColor(255, 220, 220)},
        {"ARP", QColor(0, 0, 255)},
        {"RARP", QColor(50, 50, 255)},
        {"IPX", QColor(100, 100, 255)},
        {"MPLS Unicast", QColor(150, 150, 255)},
        {"MPLS Multicast", QColor(200, 200, 255)},
        {"PPPoE Discovery", QColor(100, 100, 100)},
        {"PPPoE Session", QColor(150, 150, 150)}
    };

    defaultColor = Qt::darkGreen;
}

void PacketModel::setPacketStorage(const std::vector<packet_info> &storage) {
    PacketsStorage = &storage;
}

void PacketModel::setStartEnd(int strt) {
    startRow = strt;
    endRow = strt;
}

void PacketModel::setDisplayRange(int startIndex, int endIndex) {
    beginResetModel();
    startRow = startIndex;
    endRow = endIndex;
    emit dataChanged(index(startRow, 0), index(endRow - 1, columnCount() - 1));
    endResetModel();
}

void PacketModel::setColor(const QString &protocol, const QColor &color) {
    if (packetColors.contains(protocol)) {
        packetColors[protocol] = color;
    } else {
        defaultColor = color;
    }
}

int PacketModel::rowCount(const QModelIndex &parent) const {
    return PacketsStorage ? (endRow - startRow) : 0;
}

int PacketModel::columnCount(const QModelIndex &parent) const {
    return 6;
}

QVariant PacketModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || !PacketsStorage || startRow + index.row() >= PacketsStorage->size()) {
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
        if (packetColors.contains(packet.packetType)) {
            return QBrush(packetColors[packet.packetType]);
        }
        return QBrush(defaultColor);
    }
    return QVariant();
}

QVariant PacketModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        static const QStringList headers = {"Индекс", "Время", "Длина", "Отправитель", "Получатель", "Тип пакета"};
        if (section >= 0 && section < headers.size()) {
            return headers[section];
        }
    }
    return QVariant();
}

// MainWindow Implementation
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    setWhiteTheme();
    ui->setupUi(this);

    // Connect UI signals
    connect(ui->comboBox_7, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        flagFilenameChanged = false;
        switch(index) {
            case 1: AuthTable(); break;
            case 2: if (!currentDevice.isEmpty()) { ResumeSniffing(); } break;
            case 3: PauseSniffing(); break;
            case 4: StopSniffing(); break;
        }
        ui->comboBox_7->setCurrentIndex(0);
    });

    connect(ui->comboBox_8, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        switch(index) {
            case 1: setWhiteTheme(); break;
            case 2: setDarkTheme(); break;
        }
        ui->comboBox_8->setCurrentIndex(0);
    });

    connect(ui->comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (index == 1) {
            aboutApp();
        }
        ui->comboBox->setCurrentIndex(0);
    });

    connect(ui->comboBox_6, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        if (index == 1) {
            changeRowsColour();
        }
        ui->comboBox_6->setCurrentIndex(0);
    });

    connect(ui->comboBox_3, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        switch(index) {
            case 1: openDB(); break;
            case 2: saveDB(); break;
        }
        ui->comboBox_3->setCurrentIndex(0);
    });

    connect(ui->pushButton_2, &QPushButton::clicked, this, &MainWindow::AnalysisButtonClicked);
    connect(ui->pushButton_7, &QPushButton::clicked, this, &MainWindow::TutorialButtonClicked);
    connect(ui->pushButton_6, &QPushButton::clicked, this, &MainWindow::SettingsButtonClicked);
    connect(ui->ResoursesButton, &QPushButton::clicked, this, &MainWindow::ResoursesButtonClicked);

    updateTimer.reset(new QTimer(this));
    connect(updateTimer.data(), &QTimer::timeout, this, &MainWindow::updateByTimer);
    updateTimer->start(200);
}

void MainWindow::openDB() {
    QString fileName = QFileDialog::getOpenFileName(
        this,
        tr("Open Database File"),
        QDir::homePath(),
        tr("Database Files (*.db)")
    );

    if (!fileName.isEmpty()) {
        qDebug() << "Selected database file:" << fileName;
        filename = fileName.toStdString();
        flagFilenameChanged = true;
        AuthTable();
    } else {
        qDebug() << "No file selected";
    }
}

void MainWindow::saveDB() {
    StopSniffing();
    flagFilenameChanged = false;
}

void MainWindow::SettingsButtonClicked() {
    QDialog* settingsWindow = new QDialog(this);
    settingsWindow->setWindowTitle("Параметры программы");
    settingsWindow->resize(300, 200);
    settingsWindow->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinimizeButtonHint);

    QVBoxLayout *mainLayout = new QVBoxLayout(settingsWindow);
    QHBoxLayout *inputLayout = new QHBoxLayout();

    QLineEdit *memoryLimitInput = new QLineEdit(settingsWindow);
    memoryLimitInput->setPlaceholderText("Введите лимит памяти (MB)");

    QPushButton *applyButton = new QPushButton("Применить", settingsWindow);

    inputLayout->addWidget(memoryLimitInput);
    inputLayout->addWidget(applyButton);
    mainLayout->addLayout(inputLayout);

    connect(applyButton, &QPushButton::clicked, this, [=]() {
        bool ok;
        int memoryMB = memoryLimitInput->text().toInt(&ok);
        if (!ok || memoryMB <= 10) {
            QMessageBox::warning(settingsWindow,
                               "Ошибка",
                               "Значение должно быть числом больше 10 MB");
            return;
        }

        if (connection) {
            std::ostringstream oss;
            oss << "PRAGMA memory_limit='" << memoryMB << "MB';";
            std::string query = oss.str();

            connection->Query(query);
            QMessageBox::information(settingsWindow,
                                   "Успех",
                                   "Лимит памяти успешно изменен");
        } else {
            QMessageBox::critical(settingsWindow,
                                "Ошибка",
                                "Нет подключения к базе данных");
        }
    });
    settingsWindow->setAttribute(Qt::WA_DeleteOnClose);
    settingsWindow->show();
}

void MainWindow::changeRowsColour() {
    QDialog* colorWindow = new QDialog(this);
        colorWindow->setWindowTitle("Смена цвета");
        colorWindow->resize(300, 200);
        colorWindow->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinimizeButtonHint);

        QVBoxLayout *layout = new QVBoxLayout(colorWindow);

        QComboBox *protocolCombo = new QComboBox(colorWindow);
        protocolCombo->addItems({
            "IPv4 - TCP", "IPv4 - UDP", "IPv4 - ICMP", "IPv4 - IGMP", "IPv4 - Unknown",
            "IPv6 - TCP", "IPv6 - UDP", "IPv6 - ICMP", "IPv6 - IGMP", "IPv6 - Unknown",
            "ARP", "RARP", "IPX", "MPLS Unicast", "MPLS Multicast",
            "PPPoE Discovery", "PPPoE Session"
        });

        QPushButton *colorButton = new QPushButton("Выбрать цвет", colorWindow);

        connect(colorButton, &QPushButton::clicked, this, [=]() {
            QColorDialog colorDialog(colorWindow);
            colorDialog.setOption(QColorDialog::DontUseNativeDialog);
            colorDialog.setCurrentColor(Qt::red);

            connect(&colorDialog, &QColorDialog::colorSelected, this, [=](const QColor &color) {
                if (model) {
                    model->setColor(protocolCombo->currentText(), color);
                }
            });

            colorDialog.exec();
        });

        layout->addWidget(new QLabel("Выберите протокол:", colorWindow));
        layout->addWidget(protocolCombo);
        layout->addSpacing(20);
        layout->addWidget(colorButton);

        colorWindow->setAttribute(Qt::WA_DeleteOnClose);
        colorWindow->show();
}

void MainWindow::TutorialButtonClicked() {
    QMessageBox::information(this, "Руководство",
                           "Руководство по эксплуатации можно найти на сайте https://www.winpcap.org/install/\n"
                           "Для получения дополнительной информации, обратитесь по почтовому адресу kostryukov.duxa@gmail.com");
}

void MainWindow::aboutApp() {
    QMessageBox::information(this, "О программе",
                           "Создатель: Кострюков Андрей\n"
                           "Email: kostryukov.duxa@gmail.com\n"
                           "Год: 2025");
}

void MainWindow::setWhiteTheme() {
    QPalette lightPalette;
    lightPalette.setColor(QPalette::Window, Qt::white);
    lightPalette.setColor(QPalette::WindowText, Qt::black);
    lightPalette.setColor(QPalette::Base, Qt::white);
    lightPalette.setColor(QPalette::AlternateBase, QColor(240, 240, 240));
    lightPalette.setColor(QPalette::ToolTipBase, Qt::black);
    lightPalette.setColor(QPalette::ToolTipText, Qt::black);
    lightPalette.setColor(QPalette::Text, Qt::black);
    lightPalette.setColor(QPalette::Button, QColor(240, 240, 240));
    lightPalette.setColor(QPalette::ButtonText, Qt::black);

    qApp->setStyle("Fusion");
    qApp->setPalette(lightPalette);
}

void MainWindow::setDarkTheme() {
    QPalette darkPalette;
    darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::WindowText, Qt::white);
    darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
    darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
    darkPalette.setColor(QPalette::ToolTipText, Qt::white);
    darkPalette.setColor(QPalette::Text, Qt::white);
    darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
    darkPalette.setColor(QPalette::ButtonText, Qt::white);

    qApp->setStyle("Fusion");
    qApp->setPalette(darkPalette);
}

void MainWindow::AuthTable() {
    auto auth = std::make_unique<NCardAuth>();
    QVector<QPair<QString, QString>> devices = auth->GetDevices();

    QDialog dialog(this);
    dialog.setWindowTitle("Таблица устройств");
    dialog.resize(800, 600);
    QVBoxLayout layout(&dialog);
    QTableView authtable(&dialog);

    QStandardItemModel model(&dialog);
    model.setColumnCount(2);
    model.setHeaderData(0, Qt::Horizontal, "Название");
    model.setHeaderData(1, Qt::Horizontal, "Описание");

    for (const QPair<QString, QString>& device : devices) {
        QStandardItem *itemFirst = new QStandardItem(device.first);
        QStandardItem *itemSecond = new QStandardItem(device.second);

        itemFirst->setFlags(itemFirst->flags() & ~Qt::ItemIsEditable);
        itemSecond->setFlags(itemSecond->flags() & ~Qt::ItemIsEditable);

        model.appendRow({itemFirst, itemSecond});
    }

    authtable.setModel(&model);
    authtable.horizontalHeader()->setStretchLastSection(true);
    authtable.horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

    layout.addWidget(&authtable);

    connect(&authtable, &QTableView::doubleClicked, this, [=, &dialog, &model](const QModelIndex &index){
        if (index.isValid()) {
            int row = index.row();
            QString deviceName = model.item(row, 0)->text();
            StartSniffing(deviceName);
            dialog.accept();
        } else {
            qDebug() << "Выбран невалидный индекс устройства";
            QMessageBox::warning(this, "Ошибка", "Выбрано некорректное устройство");
        }
    });
    dialog.exec();
}

QString MainWindow::processBlob(duckdb::Value packet_type_str, const QString &param) {
    QString bytes;
    try {
        auto blob = packet_type_str.GetValueUnsafe<std::string>();
        if (param == "data") {
            bytes = "Тело " + QString::number(blob.size()) + " байт:\n";
        }

        int position = -1;
        for (char c : blob) {
            position++;

            if (param == "data") {
                bytes += QString::number(static_cast<uint8_t>(c), 16).toUpper().rightJustified(2, '0');
            } else {
                bytes += QString::number(static_cast<uint8_t>(c));
            }

            if (param == "time" && position != blob.size() - 1) {
                bytes += ".";
            }
            if (param == "data" && position != blob.size() - 1) {
                bytes += " ";
            }
            if (param == "data" && position != blob.size() - 1 && position != 0 && position % 16 == 0) {
                bytes += "\n";
            }
        }

        if (param == "data" && position == -1) {
            bytes = "В пакете нет тела";
        }
    } catch (const std::exception& e) {
        qDebug() << "Error processBlob:" << QString::fromStdString(packet_type_str.GetValueUnsafe<std::string>()) << e.what();
    }
    return bytes;
}

void MainWindow::StartSniffing(const QString &device) {
    StopSniffing();

    if (!flagFilenameChanged) {
        QString sanitizedDevice = device;
        sanitizedDevice.replace(QRegularExpression("[^a-zA-Z0-9]"), "-");

        QString timeStr = QDateTime::currentDateTime().toLocalTime().toString("yyyy-MM-dd-hh-mm-ss");
        filename = sanitizedDevice.toStdString() + timeStr.toStdString() + "-packets.db";
    }

    qDebug() << QString::fromStdString(filename);

    sniffer = std::make_unique<SnifferMonitoring>(device, filename, this);
    model = std::make_unique<PacketModel>(this);

    model->setPacketStorage(TableStorage);
    ui->tableView_2->setModel(model.get());

    connect(sniffer.get(), &SnifferMonitoring::packetCapturedUchar, this, &MainWindow::handlePacketCapturedUchar);

    try {
        sniffer->start();
    } catch (const std::exception& e) {
        qDebug() << "Error starting sniffer:" << e.what();
    }

    currentDevice = device;
    ui->verticalScrollBar->setRange(0, std::numeric_limits<int>::max());
    ui->verticalScrollBar->setValue(std::numeric_limits<int>::max());

    connect(ui->verticalScrollBar, &QScrollBar::valueChanged, this, &MainWindow::updateOnScrollEvent);

    for(int i = 0; i < 6; ++i) {
        ui->tableView_2->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
    }

    ui->tableView_2->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    connect(ui->tableView_2, &QTableView::pressed, this, &MainWindow::onRowClicked);
}

void MainWindow::updateOnScrollEvent(int scrollPosition) {
    if (maxScrollValue <= 0) {
        return; // Prevent division by zero
    }

    double ratio = static_cast<double>(scrollPosition) / std::numeric_limits<int>::max();
    int startRow = static_cast<int>(maxScrollValue * ratio);
    currScrollValue = startRow;

    int endRow = std::min(startRow + rowCount, static_cast<int>(sizeCurr));
    UpdateTableWiew(startRow, endRow);
}

void MainWindow::updateByTimer() {
    if(!sniffer) {
        return;
    }

    if (ui->verticalScrollBar->value() != std::numeric_limits<int>::max()) {
        if (maxScrollValue <= 0) {
            return; // Prevent division by zero
        }

        double ratio = static_cast<double>(currScrollValue) / maxScrollValue;
        int scrollValue = static_cast<int>(std::numeric_limits<int>::max() * ratio);

        // Ensure we're at the correct position
        double checkRatio = static_cast<double>(scrollValue) / std::numeric_limits<int>::max();
        if (static_cast<int>(maxScrollValue * checkRatio) != currScrollValue) {
            ++scrollValue;
        }

        ui->verticalScrollBar->setValue(scrollValue);
        return;
    }

    int startRow = maxScrollValue;
    currScrollValue = startRow;
    int endRow = std::min(startRow + rowCount, static_cast<int>(sizeCurr));
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
    if (currentDevice.isEmpty()) {
        qDebug() << "Cannot resume sniffing: no device selected";
        return;
    }

    if (!sniffer) {
        sniffer = std::make_unique<SnifferMonitoring>(currentDevice, filename, this);
    }

    sniffer->start();
}

void MainWindow::StopSniffing() {
    if (sniffer) {
        sniffer->stopSniffing();
        sniffer.reset();
    }
    currentDevice.clear();
}

void MainWindow::PauseSniffing() {
    if (sniffer) {
        sniffer->stopSniffing();
        sniffer.reset();
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
        QStandardItem *item = new QStandardItem(data);  // Memory leak here - items are not properly managed
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
}
