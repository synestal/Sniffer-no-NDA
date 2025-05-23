QT += core gui charts
DEFINES += NOMINMAX

QMAKE_CXXFLAGS += /wd4100

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17console
CONFIG -= app_bundle
SOURCES += \
    src/NCard/DuckDBInsertThread.cpp \
    src/Windows/graphs/bar/bar.cpp \
    src/Windows/graphs/graphchoosing.cpp \
    main.cpp \
    mainwindow.cpp \
    packages/service_pcap/misc.cpp \
    src/NCard/ncardauth.cpp \
    src/Windows/graphs/pike/pikegraph.cpp \
    #src/Windows/graphs/stack/stack.cpp \
    src/Windows/resoursesview.cpp \
    src/NCard/sniffermonitoring.cpp \
    src/Windows/graphs/round/roundgraph.cpp

HEADERS += \
    src/NCard/DuckDBInsertThread.h \
    src/NCard/DuckDBInsertThread.h \
    src/NCard/DuckDBMaintenanceThread.h \
    src/Windows/graphs/bar/bar.h \
    src/Windows/graphs/graphchoosing.h \
    mainwindow.h \
    src/NCard/ncardauth.h \
    src/Windows/graphs/pike/pikegraph.h \
    #src/Windows/graphs/stack/stack.h \
    src/Windows/resoursesview.h \
    src/NCard/sniffermonitoring.h \
    packages/service_pcap/misc.h \
    packages/structs/typesAndStructs.h \
    src/Windows/graphs/round/roundgraph.h

FORMS += \
    mainwindow.ui \
    src/Windows/graphs/graphchoosing.ui \
    src/Windows/resoursesview.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target


# Пути к заголовочным файлам
INCLUDEPATH += \
    # libs\PcapPlusPlus-master\builded\include\pcapplusplus \
    # libs/PcapPlusPlus-master/builded/include \
    libs/npcap-sdk-1.13/Include
    C:/Windows/System32/Npcap

# Пути к библиотекам
LIBS += \
    # -L$$PWD/libs/PcapPlusPlus-master/builded/lib -lPcap++ -lCommon++ -lPacket++ \
    -L$$PWD/libs/npcap-sdk-1.13/Lib/x64 -lPacket -lwpcap \
    -LC:/Windows/System32/Npcap -lPacket -lwpcap \

LIBS += -liphlpapi
LIBS += -lws2_32


INCLUDEPATH += $$PWD/libs/duckdb
LIBS += -L$$PWD/libs/duckdb -lduckdb


# Пути для зависимостей
DEPENDPATH += \
    libs/PcapPlusPlus-master/builded/include/pcapplusplus \
    libs/PcapPlusPlus-master/builded/include \
    libs/npcap-sdk-1.13/Include \
