#include "graphchoosing.h"
#include "ui_graphchoosing.h"


GraphChoosing::GraphChoosing(QWidget *parent) : QDialog(parent), ui(new Ui::GraphChoosing) {
    ui->setupUi(this);
    connect(ui->actionCreatePieChart, &QAction::triggered, this, [this](){this->createDiagram("circle");});
    connect(ui->actionCreateLineChart, &QAction::triggered, this, [this](){this->createDiagram("pike");});
    connect(ui->actionCreateBarChart, &QAction::triggered, this, [this](){this->createDiagram("bar");});
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
    auto* typeComboBox = new QComboBox();
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
    typeComboBox->addItems({"Круговая", "Линейная", "Столбчатая", "Точечная"});
    settingsLayout->addWidget(typeComboBox);
    auto* gridCheckBox = new QCheckBox("Показать сетку");
    settingsLayout->addWidget(gridCheckBox);
    auto* colorButton = new QPushButton("Цвет линии");
    settingsLayout->addWidget(colorButton);
    settingsLayout->addStretch();
    mainLayout->addWidget(settingsGroupBox);
    ui->chartsLayout->insertWidget(ui->chartsLayout->count() - 1, chartGroupBox);

    std::visit([&](auto&& graph) {
        connect(colorButton, &QPushButton::clicked, [this, graph]() {
            QColor color = QColorDialog::getColor(Qt::red, this, "Выберите цвет линии");
            if (color.isValid()) {
                graph->setColor(color);
            }
        });
        }, graphVariant);
    /*

    connect(gridCheckBox, &QCheckBox::stateChanged, [graph](int state) {
        graph->SetGridVisible(state == Qt::Checked);
    });

    connect(typeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [this, graph](int index) {
                // Здесь логика изменения типа графика
                // Вам нужно реализовать этот метод в RoundGraphBackend
                graph->ChangeChartType(index);
            }); */
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
