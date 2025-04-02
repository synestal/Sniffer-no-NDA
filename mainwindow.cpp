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
        else { // ДОПИСАТЬ ЧТО БУДЕТ ЕСЛИ ИНДЕКС НЕ ВАЛИДЕН
            std::terminate();
        }
    });

    tempWindow->show();
}

void MainWindow::StartSniffing(QString device) {
    StopSniffing();
    sniffer = std::make_unique<SnifferMonitoring>(device, this);
    if (!model) { model = new PacketModel(this);};

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
    int startRow = maxScrollValue * (static_cast<double>(scrollPosition) / static_cast<double>(INT_MAX));
    currScrollValue = startRow;
    int endRow = startRow + rowCount < static_cast<int>(header.size()) ? startRow + rowCount : static_cast<int>(header.size());

    UpdateTableWiew(startRow, endRow);
}
void MainWindow::updateByTimer() {
    if(sniffer == nullptr) { return; };
    if (ui->verticalScrollBar->value() != INT_MAX) {
            int temp = INT_MAX * (static_cast<double>(currScrollValue) / static_cast<double>(maxScrollValue));
            if (maxScrollValue * (static_cast<double>(temp) / static_cast<double>(INT_MAX) != currScrollValue)) {++temp;}
            ui->verticalScrollBar->setValue(temp);
            return;
        }
    int startRow = maxScrollValue;
    currScrollValue = startRow;
    int endRow = startRow + rowCount < static_cast<int>(header.size()) ? startRow + rowCount : static_cast<int>(header.size());
    UpdateTableWiew(startRow, endRow);
}

void MainWindow::UpdateTableWiew(int startRow, int endRow) {
    TableStorage.resize(rowCount);
    functionsToDeterminePacket* determinator = new functionsToDeterminePacket(header, pkt_data);
    determinator->mainhandler(TableStorage, startRow, endRow);
    model->setDisplayRange(0, endRow - startRow);
    delete determinator;
}

void MainWindow::handlePacketCapturedUchar(const struct pcap_pkthdr* hdr, const u_char* dta) {
   header.push_back(hdr);
   pkt_data.push_back(dta);
   maxScrollValue = static_cast<int>(header.size()) < rowCount ? 0 : static_cast<int>(header.size()) - rowCount;

   sizeCurr += sizeof(struct pcap_pkthdr) + hdr->caplen;
}

void MainWindow::ResumeSniffing() {
    if (sniffer == nullptr) {
        return;
    }
    sniffer->start();
}
void MainWindow::StopSniffing() {
    if (sniffer != nullptr) { sniffer->terminate(); }
    currentDevice = "";
}
void MainWindow::PauseSniffing() {
    if (sniffer != nullptr) { sniffer->stopSniffing(); };
}

void MainWindow::onRowClicked(const QModelIndex &index) {
    int row = index.row() + currScrollValue;
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
        modelDescr->setHeaderData(0, Qt::Horizontal, "Номер " + QString::number(row));
        modelDescr->appendRow(rowItems);
    }
}
void MainWindow::AnalysisButtonClicked() {
    if(sniffer == nullptr) { return; };

    graph = std::make_unique<GraphChoosing>(this, header, pkt_data);
    qDebug() << "Out of constructor";
    connect(graph.get(), &GraphChoosing::closeRequested, this, [=]() {graph = nullptr;});
    graph->show();
}

void MainWindow::ResoursesButtonClicked() {
    resourse = std::make_unique<ResoursesView>();
    resourse->setSrc(header, sizeCurr);

    resourse->UpdateData();
    resourse->show();
}

void MainWindow::wheelEvent(QWheelEvent *event) { // Иногда крутит на 5, иногда на 4. Хочу оставить это фишкой, нежели фиксить (Вычислять округление от деления)
    int temp = INT_MAX * (static_cast<double>(currScrollValue) / static_cast<double>(maxScrollValue));
    if (maxScrollValue * (static_cast<double>(temp) / static_cast<double>(INT_MAX) != currScrollValue) && temp != INT_MAX) {++temp;} // Текущее положение
    int val = static_cast<double>(INT_MAX) / static_cast<double>(maxScrollValue) * 5.0;
    if (event->angleDelta().y() < 0) {
        ui->verticalScrollBar->setValue(temp - INT_MAX + val > 0 ? INT_MAX : temp + val);
    } else {
        ui->verticalScrollBar->setValue(temp - val > 0 ? temp - val : 0);
    }
}

void MainWindow::resizeEvent(QResizeEvent *event) {
    int visibleHeight = ui->tableView_2->viewport()->height();
    int rowHeight = ui->tableView_2->verticalHeader()->defaultSectionSize();

    if (model) { rowCount = visibleHeight / rowHeight; };

    QMainWindow::resizeEvent(event);
}

MainWindow::~MainWindow() {
    delete ui;
}
