#include "src/Windows/graphs/pike/pikegraph.h"

PikesGraphBackend::PikesGraphBackend(QWidget *parent)
        : QDialog(parent) {
        ConstructGraph();
        graph->setGraphData(GraphData);
    }

    QVBoxLayout* PikesGraphBackend::GetLayout() {
        return layout;
    }

    void PikesGraphBackend::Repaint() {
        int tempMax = GraphData->size();
        int maxValue = 0;
        GraphData->clear();
        switch (currentSetting) {
        case hour:
            *GraphData = SearchByParams(3600, 59);
            break;
        case minute:
            *GraphData = SearchByParams(60, 59);
            break;
        case second:
            *GraphData = SearchByParams(1, 59);
            break;
        case liveH:
            *GraphData = SearchByParams(3600, 59);
            break;
        case liveM:
            *GraphData = SearchByParams(60, 59);
            break;
        case liveS:
            *GraphData = SearchByParams(1, 59);
            break;
        }
        for (auto i : *GraphData) {
            maxValue = maxValue < i.second ? i.second : maxValue;
        }
        graph->setMaxObjects(tempMax, maxValue, prevMaxSize);
        graph->Repaint();
    }

    void PikesGraphBackend::ConstructGraph() {
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


    void PikesGraphBackend::setGraphMode(int mode) {
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

    std::vector<std::pair<std::string, int>> PikesGraphBackend::SearchByParams(int delitel, int offset ) {
        qDebug() << "here";
        if (!connection) {
            qDebug() << "Connection is null in roundGraph";
            return std::vector<std::pair<std::string, int>>{};
        }
        if (delitel < 0 || offset < 0) {
            qDebug() << "Invalid info to search by params";
            return std::vector<std::pair<std::string, int>>{};
        }
        try {
            std::string query = "WITH extracted AS (SELECT CAST(ts / " +   std::to_string(delitel) + " AS INTEGER) AS minute_ts FROM packets), " +
                  "latest AS (SELECT MAX(minute_ts) AS latest_minute FROM extracted) " +
                  "SELECT minute_ts, STRFTIME(TO_TIMESTAMP(minute_ts * " + std::to_string(delitel) + "), '%Y-%m-%d %H:%M') AS minute_str, " +
                  "COUNT(*) AS packet_count FROM extracted, latest " +
                  "WHERE minute_ts BETWEEN latest_minute - " + std::to_string(offset) + " AND latest_minute " +
                  "GROUP BY minute_ts ORDER BY minute_ts;";
            auto result = connection->Query(query);
            if (!result || result->HasError()) {
                qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
                return std::vector<std::pair<std::string, int>>{};
            }
            size_t row_count = result->RowCount();
            if (row_count == 0) {
                qDebug() << "No data returned from query";
                return std::vector<std::pair<std::string, int>>{};
            }
            std::vector<std::pair<std::string, int>> returningVal;
            try {
                for (int i = 0; i < row_count; i++) {
                    std::string str = result->GetValue(1, i).GetValue<std::string>();
                    int cnt = result->GetValue<int64_t>(2, i);
                    returningVal.push_back(std::pair<std::string, int>(str, cnt));
                }
            } catch (const std::exception& e) {
                qDebug() << "Error processing row:" << e.what();
            }
            return returningVal;
        } catch (const std::exception& e) {
            qDebug() << "DuckDB error: " << e.what();
            return std::vector<std::pair<std::string, int>>{};
        }
    }


