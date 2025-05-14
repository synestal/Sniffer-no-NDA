#include "src/Windows/graphs/pike/pikegraph.h"

PikesGraphBackend::PikesGraphBackend(QWidget *parent)
        : QDialog(parent) {
        ConstructGraph();
        graph->setGraphData(GraphData);
    }
PikesGraphBackend::~PikesGraphBackend() {
    delete graph;
    delete layout;
    delete GraphData;
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

    void PikesGraphBackend::ConstructGraph() {
        layout = new QVBoxLayout;
        setGraphMode(3);
        graph = new PikesGraph();
        layout->addWidget(graph->GetChart());
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
    bool PikesGraphBackend::applyChangesFromChoosing(QString query) {
        try {
            auto result = connection->Query(query.toUtf8().constData());
            if (!result || result->HasError()) {
                qDebug() << "DuckDB query error:" << (result ? QString::fromStdString(result->GetError()) : "No result");
                return false;
            }
            if (result->RowCount() == 0) return false;
            QString str = QDateTime::fromSecsSinceEpoch(result->GetValue(0, 0).GetValue<int64_t>()).toString("yyyy:MM:dd:hh:mm:ss");
            int cnt = result->GetValue<int8_t>(1, 0);
            qDebug() << str << cnt;
            queryRaw = query;
            queryIsChanged = true;
            return true;
        } catch (const std::exception& e) {
            qDebug() << e.what();
            return false;
        }
    }

    std::vector<std::pair<QString, int>> PikesGraphBackend::SearchByParams(int delitel, int offset, int start, int stop) {
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


            std::string query = "";
            if (!queryIsChanged) {
                query = oss.str();
            } else {
                query = queryRaw.QString::toStdString();
            }

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

    void PikesGraphBackend::setGrid(bool state) {
        graph->setGrid(state);
    }


