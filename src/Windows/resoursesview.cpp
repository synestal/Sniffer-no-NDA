#include "resoursesview.h"
#include "ui_resoursesview.h"

ResoursesView::ResoursesView(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ResoursesView)
{
    ui->setupUi(this);

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &ResoursesView::UpdateData);
    updateTimer->start(200);
}

void ResoursesView::setSrc(std::vector<const struct pcap_pkthdr*>& input, int& inputVal) {
    header = &input;
    sizeCurr = &inputVal;
}

void ResoursesView::UpdateData() {
    QProcess process1;
    #ifdef Q_OS_WIN
        process1.start("tasklist", QStringList() << "/FI" << "IMAGENAME eq TestDiploma.exe" << "/FO" << "CSV");
        process1.waitForFinished();

        QString output1 = process1.readAllStandardOutput().trimmed();
        if (!output1.isEmpty()) {
            QStringList lines = output1.split("\n");
            if (lines.size() > 1) {
                QStringList columns = lines[1].split(",");
                if (columns.size() >= 5) {
                    output1 = columns[4].trimmed();
                }
            }
        }
    #elif defined(Q_OS_LINUX)
        process1.start("ps", QStringList() << "-o" << "rss=" << "-p" << QString::number(getpid()));
        process1.waitForFinished();
        QString output1 = process1.readAllStandardOutput().trimmed();
    #endif
    ui->label_21->setText(output1);

    size_t header_meta_size = header->capacity() * sizeof(const struct pcap_pkthdr*);


    ui->label_23->setText(QString::number(0 / (1024 * 1024))); // Заменить 0 на val1
    ui->label_24->setText(QString::number((*sizeCurr + header_meta_size) / (1024 * 1024)));
    ui->label_25->setText(QString::number((0 + *sizeCurr + header_meta_size) / (1024 * 1024)));
}


ResoursesView::~ResoursesView()
{
    qDebug() << "destr";
    delete ui;
}
