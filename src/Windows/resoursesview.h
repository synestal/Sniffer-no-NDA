#ifndef RESOURSESVIEW_H
#define RESOURSESVIEW_H

#include <QDialog>
#include <QProcess>
#include <QTimer>

namespace Ui {
class ResoursesView;
}

class ResoursesView : public QDialog
{
    Q_OBJECT

public:
    explicit ResoursesView(QWidget *parent = nullptr);
    ~ResoursesView();

    void setSrc(std::vector<const struct pcap_pkthdr*>&, int&);

    void UpdateData();

private:
    Ui::ResoursesView *ui;
    int* sizeCurr = nullptr;
    std::vector<const struct pcap_pkthdr*>*  header = nullptr;
    QTimer* updateTimer = nullptr;
};

#endif // RESOURSESVIEW_H
