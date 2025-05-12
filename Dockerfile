# Используем официальный образ ClickHouse
FROM yandex/clickhouse-server:latest

# Устанавливаем дополнительные зависимости, если нужно
# RUN apt-get update && apt-get install -y <пакеты>

# Копируем конфигурационные файлы (если у тебя есть кастомные конфигурации)
# COPY ./config /etc/clickhouse-server/

# Открываем порты для подключения
EXPOSE 9000 8123

# Копируем начальную SQL-базу данных, если нужно
# COPY ./initial_data.sql /docker-entrypoint-initdb.d/

# Команда по умолчанию, запускающая ClickHouse
CMD ["clickhouse-server", "--config-file", "/etc/clickhouse-server/config.xml"]