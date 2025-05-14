#include "graphchoosing.h"
#include "ui_graphchoosing.h"


GraphChoosing::GraphChoosing(QWidget *parent) : QDialog(parent), ui(new Ui::GraphChoosing) {
    ui->setupUi(this);
    connect(ui->actionCreatePieChart, &QAction::triggered, this, [this](){this->createDiagram("circle");});
    connect(ui->actionCreateLineChart, &QAction::triggered, this, [this](){this->createDiagram("pike");});
    connect(ui->actionCreateBarChart, &QAction::triggered, this, [this](){this->createDiagram("bar");});
    connect(ui->actionCreateStackChart, &QAction::triggered, this, [this](){this->createDiagram("stack");});
    ui->verticalLayout->removeWidget(ui->chartGroupBox1);
    ui->chartGroupBox1->hide();
    resize(1920, 1080);
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &GraphChoosing::Repaint);
    updateTimer->start(200);
}

void GraphChoosing::closeEvent(QCloseEvent *event) {
    int response = QMessageBox::question(this, "Закрытие", "Вы уверены, что хотите закрыть окно?");
    if (response == QMessageBox::Yes) {
        emit closeRequested();
        event->accept();
    } else {
        event->ignore();
    }
}

GraphVariant GraphChoosing::createGraphVariant(const QString& type) {
    if (type == "circle") {
        return new RoundGraphBackend();
    } else if (type == "pike") {
        return new PikesGraphBackend();
    } else if (type == "bar") {
        return new BarGraphBackend();
    } else if (type == "stack") {
        return new StackGraphBackend();
    }
    throw std::runtime_error("Unknown graph type");
}

void GraphChoosing::createDiagram(QString type) {
    auto* chartGroupBox = new QGroupBox(QString("График %1").arg(ui->chartsLayout->count()));
    chartGroupBox->setMinimumHeight(400);
    chartGroupBox->setMaximumHeight(400);
    auto* mainLayout = new QHBoxLayout(chartGroupBox);
    GraphVariant graphVariant = createGraphVariant(type);
    diagrams.push_back(graphVariant);
    std::visit([&](auto&& graph) {
        graph->setConnection(connection);
        graph->Repaint();
        mainLayout->addWidget(graph->GetChartView());
        }, graphVariant);
    auto* settingsGroupBox = new QGroupBox("Настройки");
    auto* settingsLayout = new QVBoxLayout(settingsGroupBox);
    if (std::holds_alternative<BarGraphBackend*>(graphVariant)) {
        QLineEdit *lineEdit = new QLineEdit(this);
        lineEdit->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        lineEdit->setPlaceholderText("-2,-1,1000");
        settingsLayout->addWidget(lineEdit);
        connect(lineEdit, &QLineEdit::returnPressed, [=]() {
            QString text = lineEdit->text();
            QStringList parts = text.split(",");
            if (parts.size() != 3) {
                qDebug() << "Ошибка: неверный формат строки";
                return;
            }
            bool ok1, ok2, ok3;
            int num1 = parts[0].toInt(&ok1);
            int num2 = parts[1].toInt(&ok2);
            int num3 = parts[2].toInt(&ok3);
            if (!ok1 || !ok2 || !ok3) {
                qDebug() << "Ошибка: не все части являются числами";
                return;
            }
            std::visit([&](auto&& graph) {
                graph->setLen(num1, num2, num3);
                }, graphVariant);
        });
    }
    auto* sqlButton = new QPushButton("Редактирование запроса");
    connect(sqlButton, &QPushButton::clicked, this, [=]() {
        QDialog* settingsWindow = new QDialog(this);
        settingsWindow->setWindowTitle("Параметры программы");
        settingsWindow->resize(300, 200);
        settingsWindow->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint | Qt::WindowMinimizeButtonHint);

        QVBoxLayout *mainLayout = new QVBoxLayout(settingsWindow);
        QHBoxLayout *inputLayout = new QHBoxLayout();

        QLineEdit *memoryLimitInput = new QLineEdit(settingsWindow);
        memoryLimitInput->setPlaceholderText("Введите ваш запрос для работы графика");

        QPushButton *applyButton = new QPushButton("Применить", settingsWindow);

        inputLayout->addWidget(memoryLimitInput);
        inputLayout->addWidget(applyButton);
        mainLayout->addLayout(inputLayout);

        connect(applyButton, &QPushButton::clicked, this, [=]() {
            QString inputText = memoryLimitInput->text();
            if (connection) {
                QString query = inputText;

                try {
                    std::visit([&](auto&& graph) {
                        if (!graph->applyChangesFromChoosing(query)) {
                            QMessageBox::critical(settingsWindow,
                                                "Ошибка",
                                                "Не правильный формат запроса");
                        } else {
                            QMessageBox::information(settingsWindow,
                                               "Успех",
                                               "Успешно изменено");
                        }
                        }, graphVariant);

                } catch  (const std::exception& e){
                    QMessageBox::critical(settingsWindow,
                                        "Ошибка",
                                        "Не правильный формат запроса", e.what());
                }
            }
        });
        settingsWindow->setAttribute(Qt::WA_DeleteOnClose);
        settingsWindow->show();
    });


    if (!std::holds_alternative<StackGraphBackend*>(graphVariant)) {
        auto* colorButton = new QPushButton("Цвет линии");
        settingsLayout->addWidget(colorButton);
        std::visit([&](auto&& graph) {
            connect(colorButton, &QPushButton::clicked, [this, graph]() {
                QColor color = QColorDialog::getColor(Qt::red, this, "Выберите цвет линии");
                if (color.isValid()) {
                    graph->setColor(color);
                }
            });
            }, graphVariant);
    }
    settingsLayout->addStretch();
    mainLayout->addWidget(settingsGroupBox);
    settingsLayout->addWidget(sqlButton);
    ui->chartsLayout->insertWidget(ui->chartsLayout->count() - 1, chartGroupBox);

    if (!std::holds_alternative<RoundGraphBackend*>(graphVariant)) {
        std::visit([&](auto&& graph) {
            auto* gridCheckBox = new QCheckBox("Показать сетку");
            gridCheckBox->setChecked(true);
            settingsLayout->addWidget(gridCheckBox);
            connect(gridCheckBox, &QCheckBox::stateChanged, [graph](int state) {
                graph->setGrid(state == Qt::Checked);
            });
        }, graphVariant);
    }
}

void GraphChoosing::Repaint() {
    auto diagramIt = diagrams.begin();
    for (; diagramIt != diagrams.end(); ++diagramIt) {
        if (std::holds_alternative<RoundGraphBackend*>(*diagramIt)) {
            RoundGraphBackend* roundGraph = std::get<RoundGraphBackend*>(*diagramIt);
            roundGraph->Repaint();
        } else if (std::holds_alternative<PikesGraphBackend*>(*diagramIt)) {
            PikesGraphBackend* pikesGraph = std::get<PikesGraphBackend*>(*diagramIt);
            pikesGraph->Repaint();
        } else if (std::holds_alternative<BarGraphBackend*>(*diagramIt)) {
            BarGraphBackend* barGraph = std::get<BarGraphBackend*>(*diagramIt);
            barGraph->Repaint();
        } else if (std::holds_alternative<StackGraphBackend*>(*diagramIt)) {
            StackGraphBackend* stackGraph = std::get<StackGraphBackend*>(*diagramIt);
            stackGraph->Repaint();
        }
    }
}



void GraphChoosing::Cleanup() {
    for (auto& graph : diagrams) {
        if (std::holds_alternative<RoundGraphBackend*>(graph)) {
            delete std::get<RoundGraphBackend*>(graph);
        } else if (std::holds_alternative<PikesGraphBackend*>(graph)) {
            delete std::get<PikesGraphBackend*>(graph);
        } else if (std::holds_alternative<BarGraphBackend*>(graph)) {
            delete std::get<BarGraphBackend*>(graph);
        }
    }
}
