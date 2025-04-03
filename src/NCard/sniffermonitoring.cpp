#include "sniffermonitoring.h"



/*
 * Бета-версия (стабильная)
 *
 *
 *
*/
void SnifferMonitoring::packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    SnifferMonitoring *sniffer = reinterpret_cast<SnifferMonitoring*>(param);

    if (!sniffer) { return; }

    pcap_pkthdr *headerCopy = new pcap_pkthdr(*header);
    u_char *pktDataCopy = new u_char[header->len];
    std::memcpy(pktDataCopy, pkt_data, header->len);

    clickhouse::Block block;

    // Создаём колонки и сразу добавляем данные
    auto col_ts = std::make_shared<clickhouse::ColumnDateTime>();
    auto col_caplen = std::make_shared<clickhouse::ColumnUInt32>();
    auto col_len = std::make_shared<clickhouse::ColumnUInt32>();
    auto col_data = std::make_shared<clickhouse::ColumnString>();

    col_ts->Append(header->ts.tv_sec);
    col_caplen->Append(header->caplen);
    col_len->Append(header->len);
    col_data->Append(std::string(reinterpret_cast<const char *>(pkt_data), header->caplen));

    // Теперь добавляем заполненные колонки в блок
    block.AppendColumn("ts", col_ts);
    block.AppendColumn("caplen", col_caplen);
    block.AppendColumn("len", col_len);
    block.AppendColumn("data", col_data);

    // Вставляем в ClickHouse
    try {
        qDebug() << "Inserting packet data into ClickHouse...";
        sniffer->client.Insert("packets", block);
        qDebug() << "Insert successful!";
    } catch (const std::exception &e) {
        qDebug() << "ClickHouse insert failed:" << e.what();
    }

    emit sniffer->packetCapturedUchar(headerCopy, pktDataCopy);
}
