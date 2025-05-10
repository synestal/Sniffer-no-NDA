#include "src/Windows/graphs/bar/bar.h"


BarGraphBackend::BarGraphBackend(QWidget *parent)
        : QDialog(parent) {
        ConstructGraph();
        graph->setGraphData(GraphData);
    }


BarGraphBackend::~BarGraphBackend() {
    delete graph;
    delete layout;
    delete GraphData;
}

    QVBoxLayout* BarGraphBackend::GetLayout() {
        return layout;
    }

    void BarGraphBackend::Repaint() {
        int tempMax = GraphData->size();
        int maxValue = 0;
        for (auto i : *GraphData) {
            maxValue = maxValue < i.second ? i.second : maxValue;
        }
        GraphData->clear();
        *GraphData = SearchByParams(start, stop, offset);
        graph->setMaxObjects(tempMax, maxValue, prevMaxSize);
        graph->Repaint();
    }

    void BarGraphBackend::ConstructGraph() {
        layout = new QVBoxLayout;
        graph = new BarGraph();
        layout->addWidget(graph->GetChart());
    }

    std::vector<std::pair<QString, int>> BarGraphBackend::SearchByParams(int start, int stop, int offset) {
        if (!connection) {
            qDebug() << "Connection is null in roundGraph";
            return std::vector<std::pair<QString, int>>{};
        }
        if (start >= stop) {
            qDebug() << "start stop values error roundGraph";
            return std::vector<std::pair<QString, int>>{};
        }
        std::string stopOverloaded = "";
        std::string startOverloaded = "";
        if (stop < 0) {
            stopOverloaded = "MAX(len)";
        } else {
            stopOverloaded = std::to_string(stop);
        }
        if (start < 0) {
            startOverloaded = "MIN(len)";
        } else {
            startOverloaded = std::to_string(start);
        }
        try {
            std::ostringstream oss;
            oss << "WITH range_values AS (SELECT " << startOverloaded << " AS min_val, " << stopOverloaded << " AS max_val, "<< offset << " AS step FROM packets), " <<
            "ranges AS ( " <<
              "SELECT " <<
                "generate_series AS range_start, " <<
                "generate_series + (SELECT step FROM range_values) - 1 AS range_end " <<
              "FROM generate_series( " <<
                "(SELECT min_val FROM range_values), " <<
                "(SELECT max_val FROM range_values), " <<
                "(SELECT step FROM range_values) " <<
              ") " <<
            ") " <<
            "SELECT " <<
              "r.range_start, " <<
              "r.range_end, " <<
              "COUNT(p.len) AS count " <<
            "FROM ranges r " <<
            "LEFT JOIN packets p ON p.len BETWEEN r.range_start AND r.range_end " <<
            "GROUP BY r.range_start, r.range_end " <<
            "ORDER BY r.range_start;";
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
                    int str = result->GetValue(2, i).GetValue<int64_t>();
                    returningVal.push_back(std::pair<QString, int>(QString::number(result->GetValue(0, i).GetValue<int64_t>()) + " - " + QString::number(result->GetValue(1, i).GetValue<int64_t>()), str));
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

