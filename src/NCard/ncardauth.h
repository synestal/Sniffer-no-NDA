#ifndef NCARDAUTH_H
#define NCARDAUTH_H


#include <QString>
#include <QPair>
#include <QVector>
#include <QDebug>


#include <iostream>


#include "pcap.h"

class NCardAuth
{
public:
    NCardAuth();
    QVector<QPair<QString, QString>> GetDevices();
private:
    QVector<QPair<QString, QString>> devices;
};

#endif // NCARDAUTH_H
