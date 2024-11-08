#ifndef RESOURSESVIEW_H
#define RESOURSESVIEW_H

#include <QDialog>
#include <QProcess>

namespace Ui {
class ResoursesView;
}

class ResoursesView : public QDialog
{
    Q_OBJECT

public:
    explicit ResoursesView(QWidget *parent = nullptr);
    ~ResoursesView();

    void UpdateData(int, int);

private:
    Ui::ResoursesView *ui;
};

#endif // RESOURSESVIEW_H
