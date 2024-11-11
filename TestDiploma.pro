QT += core gui charts
DEFINES += NOMINMAX

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17
SOURCES += \
    src/NCard/functionstodeterminepacket.cpp \
    src/Windows/graphy.cpp \
    main.cpp \
    mainwindow.cpp \
    packages/service_pcap/misc.cpp \
    src/NCard/ncardauth.cpp \
    src/Windows/pikegraph.cpp \
    src/Windows/resoursesview.cpp \
    src/NCard/sniffermonitoring.cpp \
    src/Windows/roundgraph.cpp

HEADERS += \
    src/NCard/functionstodeterminepacket.h \
    src/Windows/graphy.h \
    mainwindow.h \
    src/NCard/ncardauth.h \
    src/Windows/pikegraph.h \
    src/Windows/resoursesview.h \
    src/NCard/sniffermonitoring.h \
    packages/service_pcap/misc.h \
    packages/structs/typesAndStructs.h \
    src/Windows/roundgraph.h

FORMS += \
    mainwindow.ui \
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

# Пути для зависимостей
DEPENDPATH += \
    libs/PcapPlusPlus-master/builded/include/pcapplusplus \
    libs/PcapPlusPlus-master/builded/include \
    libs/npcap-sdk-1.13/Include
