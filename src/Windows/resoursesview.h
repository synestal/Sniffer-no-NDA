#ifndef RESOURSESVIEW_H
#define RESOURSESVIEW_H

#include <QDialog>
#include <QProcess>
#include <QTimer>
#include <QRegularExpression>

namespace Ui {
class ResoursesView;
}

class ResoursesView : public QDialog
{
    Q_OBJECT

public:
    explicit ResoursesView(QWidget *parent = nullptr);
    ~ResoursesView();

    void UpdateData();

private:
    Ui::ResoursesView *ui;
    QTimer* updateTimer = nullptr;
};

#endif // RESOURSESVIEW_H
