#include "ncardauth.h"

NCardAuth::NCardAuth() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
        qCritical("Ошибка в pcap_findalldevs_ex: %s", errbuf);
        return;
    }
    int i = 0;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        QString name = QString::fromUtf8(d->name);
        QString description = d->description
                              ? QString::fromUtf8(d->description)
                              : QStringLiteral("Нет описания устройства");
        devices.append(qMakePair(name, description));
        ++i;
    }
    if (i == 0) {
        devices.append(qMakePair(QStringLiteral("Не найдено ни одного устройства."),
                                 QStringLiteral("Убедитесь, что установлено обеспечение Npcap")));
    }
    pcap_freealldevs(alldevs);
}

QVector<QPair<QString, QString>> NCardAuth::GetDevices() {
    return devices;
}
