QT += core gui charts
DEFINES += NOMINMAX

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17
SOURCES += \
    src/NCard/functionstodeterminepacket.cpp \
    src/Windows/graphs/graphchoosing.cpp \
    src/Windows/graphs/graphy.cpp \
    main.cpp \
    mainwindow.cpp \
    packages/service_pcap/misc.cpp \
    src/NCard/ncardauth.cpp \
    src/Windows/graphs/pike/pikegraph.cpp \
    src/Windows/resoursesview.cpp \
    src/NCard/sniffermonitoring.cpp \
    src/Windows/graphs/round/roundgraph.cpp

HEADERS += \
    src/NCard/functionstodeterminepacket.h \
    src/Windows/graphs/graphchoosing.h \
    src/Windows/graphs/graphy.h \
    mainwindow.h \
    src/NCard/ncardauth.h \
    src/Windows/graphs/pike/pikegraph.h \
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

INCLUDEPATH += $$PWD/libs/clickhouse-cpp

# Пути к библиотекам
LIBS += \
    # -L$$PWD/libs/PcapPlusPlus-master/builded/lib -lPcap++ -lCommon++ -lPacket++ \
    -L$$PWD/libs/npcap-sdk-1.13/Lib/x64 -lPacket -lwpcap \
    -LC:/Windows/System32/Npcap -lPacket -lwpcap \

LIBS += -liphlpapi
LIBS += -lws2_32

INCLUDEPATH += $$PWD/libs/abseil-cpp
INCLUDEPATH += $$PWD/libs/cityhash/src
LIBS += -L$$PWD/libs/abseil-cpp/build/absl/base/Debug -labsl_base
LIBS += -L$$PWD/libs/abseil-cpp/build/absl/numeric/Debug -labsl_int128
LIBS += -L$$PWD/libs/abseil-cpp/build/absl/container/Debug -labsl_raw_hash_set

LIBS += -L$$PWD/libs/clickhouse-cpp/build/clickhouse/Debug -lclickhouse-cpp-lib

SOURCES += $$PWD/libs/cityhash/src/city.cc
HEADERS += $$PWD/libs/cityhash/src/city.h

INCLUDEPATH += $$PWD/libs/lz4/lib

SOURCES += $$PWD/libs/lz4/lib/lz4.c
INCLUDEPATH += $$PWD/libs/lz4/lib

LIBS += "$$PWD/libs/zstd/build/VS2010/bin/x64_Debug/libzstd.lib"
QMAKE_RPATHDIR += "$$PWD/libs/zstd/build/VS2010/bin/x64_Debug"
INCLUDEPATH += $$PWD/libs/zstd/lib


# Пути для зависимостей
DEPENDPATH += \
    libs/PcapPlusPlus-master/builded/include/pcapplusplus \
    libs/PcapPlusPlus-master/builded/include \
    libs/npcap-sdk-1.13/Include \
    $$PWD/libs/clickhouse-cpp \
