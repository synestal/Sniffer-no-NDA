#include "resoursesview.h"
#include "ui_resoursesview.h"

ResoursesView::ResoursesView(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ResoursesView)
{
    ui->setupUi(this);
}

void ResoursesView::UpdateData(int val1, int val2) {
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


    ui->label_23->setText(QString::number(val1 / (1024 * 1024)));
    ui->label_24->setText(QString::number(val2 / (1024 * 1024)));
    ui->label_25->setText(QString::number((val1 + val2) / (1024 * 1024)));
}


ResoursesView::~ResoursesView()
{
    qDebug() << "destr";
    delete ui;
}
