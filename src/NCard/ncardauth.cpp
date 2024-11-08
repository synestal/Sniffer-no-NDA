#include "ncardauth.h"




/*
 * Стабильная версия
 *
 *
 *
 *
 *
 *
*/
NCardAuth::NCardAuth() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    for(d = alldevs; d != NULL; d = d->next) {
        QPair<QString, QString> tempDev;
        tempDev.first = d->name;
        if (d->description) {
            tempDev.second = static_cast<QString>(d->description);
        } else {
            tempDev.second = "Нет описания устройства";
        }
        ++i;
        devices.push_back(tempDev);
    }

    if (i == 0) {
        QPair<QString, QString> tempDev;
        tempDev.first = "Не найдено ни одного устройства.";
        tempDev.second = "Убедитесь, что установлено обеспечение Npcap";
        devices.push_back(tempDev);
        return;
    }

    pcap_freealldevs(alldevs);
}

QVector<QPair<QString, QString>> NCardAuth::GetDevices() {
    return(devices);
}
