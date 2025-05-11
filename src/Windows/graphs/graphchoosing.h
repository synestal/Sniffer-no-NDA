#ifndef GRAPHCHOOSING_H
#define GRAPHCHOOSING_H

#include <QtCharts/QChartView>
#include <QtCharts/QPieSeries>
#include <QtCharts/QPieSlice>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QtCharts/QChart>
#include <QDialog>
#include <QVector>
#include <QPushButton>
#include <QTimer>
#include <QMessageBox>
#include <QColorDialog>



#include <ctime>
#include <unordered_map>
#include <variant>

#include "src/Windows/graphs/pike/pikegraph.h"
#include "src/Windows/graphs/round/roundgraph.h"
#include "src/Windows/graphs/bar/bar.h"
#include "src/Windows/graphs/stack/stack.h"
#include "duckdb.hpp"

using GraphVariant = std::variant<RoundGraphBackend*, PikesGraphBackend*, BarGraphBackend*>;

namespace Ui {
class GraphChoosing;
}

class GraphChoosing : public QDialog {
    Q_OBJECT

signals:
    void closeRequested();
public:
    explicit GraphChoosing(QWidget *parent);
    ~GraphChoosing() { Cleanup(); }
    void closeEvent(QCloseEvent *event);

    void setConnection(std::shared_ptr<duckdb::Connection> conn) {
        connection = conn;
    }

public slots:
    void Repaint();
    void createDiagram(QString);

private:
    void Cleanup();

    std::list<GraphVariant> diagrams;


    std::shared_ptr<duckdb::Connection> connection = nullptr;
    GraphVariant createGraphVariant(const QString&);
    QTimer *updateTimer = nullptr;
    Ui::GraphChoosing *ui;
};

#endif // GRAPHCHOOSING_H

