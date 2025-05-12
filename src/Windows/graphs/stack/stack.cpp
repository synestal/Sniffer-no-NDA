#include "src/Windows/graphs/stack/stack.h"

StackGraphBackend::PikesGraphBackend(QWidget *parent)
        : QDialog(parent) {
        ConstructGraph();
        graph->setGraphData(GraphData);
    }

    QVBoxLayout* StackGraphBackend::GetLayout() {
        return layout;
    }

    void StackGraphBackend::Repaint() {
        int tempMax = GraphData->size();
        int maxValue = 0;
        GraphData->clear();
        switch (currentSetting) {
        case hour:
            *GraphData = SearchByParams(3600, 59, static_cast<int>(std::time(nullptr)) - 60*60*24, static_cast<int>(std::time(nullptr)));
            break;
        case minute:
            *GraphData = SearchByParams(60, 59, static_cast<int>(std::time(nullptr)) - 60*60, static_cast<int>(std::time(nullptr)));
            break;
        case second:
            *GraphData = SearchByParams(1, 59, static_cast<int>(std::time(nullptr)) - 60, static_cast<int>(std::time(nullptr)));
            break;
        case liveH:
            *GraphData = SearchByParams(3600, 59, static_cast<int>(std::time(nullptr)) - 60*60*24, static_cast<int>(std::time(nullptr)));
            break;
        case liveM:
            *GraphData = SearchByParams(60, 59, static_cast<int>(std::time(nullptr)) - 60*60, static_cast<int>(std::time(nullptr)));
            break;
        case liveS:
            *GraphData = SearchByParams(1, 59, static_cast<int>(std::time(nullptr)) - 60, static_cast<int>(std::time(nullptr)));
            break;
        }
        for (auto i : *GraphData) {
            maxValue = maxValue < i.second ? i.second : maxValue;
        }
        graph->setMaxObjects(tempMax, maxValue, prevMaxSize);
        graph->Repaint();
    }

    void StackGraphBackend::ConstructGraph() {
        layout = new QVBoxLayout;
        QPushButton* button1 = new QPushButton(this);
        button1->setText("Почасовая");
        QPushButton* button2 = new QPushButton(this);
        button2->setText("Поминутная");
        QPushButton* button3 = new QPushButton(this);
        button3->setText("Посекундная");
        QPushButton* button4 = new QPushButton(this);
        button4->setText("Почасовая - live");
        QPushButton* button5 = new QPushButton(this);
        button5->setText("Поминутная - live");
        QPushButton* button6 = new QPushButton(this);
        button6->setText("Посекундная - live");
        connect(button1, &QPushButton::clicked, this, [this](){setGraphMode(1);});
        connect(button2, &QPushButton::clicked, this, [this](){setGraphMode(2);});
        connect(button3, &QPushButton::clicked, this, [this](){setGraphMode(3);});
        connect(button4, &QPushButton::clicked, this, [this](){setGraphMode(4);});
        connect(button5, &QPushButton::clicked, this, [this](){setGraphMode(5);});
        connect(button6, &QPushButton::clicked, this, [this](){setGraphMode(6);});
        setGraphMode(3);
        graph = new PikesGraph();
        layout->addWidget(graph->GetChart());
        layout->addWidget(button1);
        layout->addWidget(button2);
        layout->addWidget(button3);
        layout->addWidget(button4);
        layout->addWidget(button5);
        layout->addWidget(button6);
    }


    void StackGraphBackend::setGraphMode(int mode) {
        timeLive = -1;
        maxValue = 0;
        prevMaxSize = 0;
        switch (mode) {
        case 1:
            currentSetting = hour;
            break;
        case 2:
            currentSetting = minute;
            break;
        case 3:
            currentSetting = second;
            break;
        case 4:
            currentSetting = liveH;
            break;
        case 5:
            currentSetting = liveM;
            break;
        case 6:
            currentSetting = liveS;
            break;
        }
    }

    std::vector<std::pair<QString, int>> StackGraphBackend::SearchByParams(int delitel, int offset, int start, int stop) {
        if (!connection) {
            qDebug() << "Connection is null in roundGraph";
            return std::vector<std::pair<QString, int>>{};
        }
        if (delitel < 0 || offset < 0) {
            qDebug() << "Invalid info to search by params";
            return std::vector<std::pair<QString, int>>{};
        }
        try {
            std::ostringstream oss;
            oss << "SELECT ts AS unix_time, COUNT(*) AS count FROM packets "
                << "WHERE ts >= " << start << " AND ts < " << stop
                << " GROUP BY unix_time ORDER BY unix_time;";
            std::string query = oss.str();

            auto result = connection->Query(query);
            if (!result || result->HasError()) {
                qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
                return std::vector<std::pair<QString, int>>{};
            }
            size_t row_count = result->RowCount();
            if (row_count == 0) {
                qDebug() << "No data returned from query";
                return std::vector<std::pair<QString, int>>{};
            }
            std::vector<std::pair<QString, int>> returningVal; returningVal.reserve(row_count);
            try {
                for (int i = 0; i < row_count; i++) {
                    QString str = QDateTime::fromSecsSinceEpoch(result->GetValue(0, i).GetValue<int64_t>()).toString("yyyy:MM:dd:hh:mm:ss");
                    int cnt = result->GetValue<int8_t>(1, i);
                    returningVal.push_back(std::pair<QString, int>(str, cnt));
                }
            } catch (const std::exception& e) {
                qDebug() << "Error processing row:" << e.what();
            }
            return returningVal;
        } catch (const std::exception& e) {
            qDebug() << "DuckDB error: " << e.what();
            return std::vector<std::pair<QString, int>>{};
        }
    }


