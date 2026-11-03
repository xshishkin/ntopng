# FreeFlow

Полностью бесплатный сетевой монитор трафика (аналог ntopng Community),
написанный с нуля на Python. **Никаких лицензий, платных версий и ограничений —
все функции доступны всегда.**

Архитектура и терминология вдохновлены открытым проектом ntopng (GPLv3):
5-tuple потоки, нормализация направления, портовые таблицы сервисов,
извлечение hostname из DNS/SNI/HTTP Host — как в `src/Flow.cpp`,
`src/Host.cpp`, но реализация независимая и свободная.

## Возможности

| Функция | Реализация |
|---|---|
| Захват с живого интерфейса | scapy `AsyncSniffer` (нужен root/CAP_NET_RAW) |
| Анализ pcap-файлов | scapy `PcapReader` |
| Агрегация в потоки (5-tuple) | `app/engine.py` |
| Статистика по хостам | входящие/исходящие байты, пакеты, протоколы |
| Определение протоколов | портовая таблица + HTTP Host + TLS SNI + DNS (`app/classify.py`) |
| График bytes/sec | timeseries в памяти, canvas-график в UI |
| REST API | `/api/v1/status`, `/stats/flows`, `/stats/hosts`, `/stats/protocols` (как у ntopng) |
| Веб-интерфейс | тёмная тема в стиле ntopng (Bootstrap-free, чистый JS) |

## Установка и запуск

```bash
pip install fastapi uvicorn scapy
cd freeflow
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8300
```

Откройте http://localhost:8300

- **Capture interface** — живой захват с выбранного интерфейса
  (запускать от root или с `CAP_NET_RAW`).
- **Load pcap** — анализ файла pcap на сервере, например
  `{"path": "/tmp/test.pcap"}` через UI или API.

## API примеры

```bash
curl localhost:8300/api/v1/status
curl -X POST localhost:8300/api/v1/start/pcap \
     -H 'Content-Type: application/json' -d '{"path":"/tmp/test.pcap"}'
curl 'localhost:8300/api/v1/stats/flows?search=github'
```

## Лицензия

MIT / Public Domain по выбору — используйте свободно. Проект не содержит
и не копирует проприетарный код ntopng Pro/Enterprise.
