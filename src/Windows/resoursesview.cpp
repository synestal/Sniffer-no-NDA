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

void ResoursesView::UpdateData() {
    QProcess process1;
    #ifdef Q_OS_WIN
        process1.start("tasklist", QStringList() << "/FI" << "IMAGENAME eq TestDiploma.exe" << "/FO" << "CSV");
        process1.waitForFinished();

        QString output1 = QString::fromUtf8(process1.readAllStandardOutput().trimmed());
            if (!output1.isEmpty()) {
                QStringList lines = output1.split("\n");
                if (lines.size() > 1) {
                    QStringList columns = lines[1].split(",");
                    if (columns.size() >= 5) {
                        output1 = columns[4].remove('"').remove(QRegularExpression("[^0-9]")).trimmed();
                    }
                }
            }
    #elif defined(Q_OS_LINUX) // Доделать
        process1.start("ps", QStringList() << "-o" << "rss=" << "-p" << QString::number(getpid()));
        process1.waitForFinished();
        QString output1 = process1.readAllStandardOutput().trimmed();
    #endif
    bool ok;
    int output1Int = output1.toInt(&ok);
    if (ok) {
        ui->label_21->setText(QString::number(output1Int / 1024) + " Мб");
    } else {
        ui->label_21->setText(output1 + " Кб");
    }

    ui->label_25->setText(QString::number((0 + output1Int * 1024 + 0) / (1024 * 1024)) + " Мб");
}


ResoursesView::~ResoursesView()
{
    qDebug() << "destr";
    delete ui;
}
