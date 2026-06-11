# ⚡ node-accelerator

[![ci](https://github.com/jestivald/node-accelerator/actions/workflows/ci.yml/badge.svg)](https://github.com/jestivald/node-accelerator/actions/workflows/ci.yml)

Оптимизация, диагностика и защита VPN-ноды (Remnawave / Xray / VLESS-Reality, xHTTP, Hysteria2/TUIC).
Три модуля, все идемпотентны, всё откатывается одной командой.

> **Поддержка:** Debian 11/12/13, Ubuntu 20.04–24.04. Тестируется на нодах с `network_mode: host`.

---

## Что внутри

### ⚡ Оптимизатор (`scripts/optimize.sh`)
Снимает потолок по юзерам и выжимает скорость:

- **XanMod-ядро (BBRv3)** — авто-выбор сборки по psABI-уровню CPU (`x64v3/v2/v1`),
  авто-skip на контейнерах (OpenVZ/LXC делят ядро хоста) и не-x86_64.
- **sysctl**: BBR + `fq`, буферы до 64 МБ, `somaxconn=65535`, conntrack (ёмкость масштабируется от RAM ноды), syncookies, anti-spoof (`rp_filter=2`).
- **RPS/RFS/XPS** — раскидывает обработку пакетов по всем ядрам. На virtio/single-queue VPS
  иначе весь RX-softirq висит на cpu0 — это и есть реальный потолок PPS.
- **nofile/nproc → 1 048 576**, swap, journald-cap, THP=never, governor=performance, NIC tune, irqbalance.

### 🛡 Защита (`scripts/protect.sh`)
`nftables`-движок в **своей** таблице `inet na_filter` (не `flush ruleset` — сосуществует с CrowdSec и Docker):

- **AntiScan** — SYN на несервисный порт → автобан.
- **flag-drop** — XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST и прочие скан-пакеты.
- **anti-spoofing** — bogon/RFC1918/CGNAT источники на WAN (v4 **и** v6 bogon).
- **SYN-flood / UDP-flood** — **per-IP** rate-limit (масштабируется по числу клиентов, а не глобальный потолок).
- **connect-flood SSH** — >6 новых/мин с IP → бан 24ч.
- **per-IP connlimit** (`ct count`) — кап одновременных коннектов с одного адреса.
- **ICMP rate-limit** (пинг жив, флуд режется).
- **CrowdSec + `crowdsec-firewall-bouncer-nftables`** — поведенческий IPS + community-блоклист.
- Полный **IPv6-паритет**, **rate-limit на логи**, **авто-whitelist твоего SSH-IP** + **сейфти-таймер** от самоблокировки.

### 🩺 Диагностика (`scripts/diagnose.sh`)
Read-only отчёт: ядро/BBR, sysctl, лимиты, conntrack, NIC/RPS, swap/THP/governor, firewall, CrowdSec, порты, RTT — с итогом ✔/▲/✘ и рекомендациями.

---

## Установка

```bash
# меню
sudo bash install.sh

# по модулям
sudo bash install.sh optimize     # ⚡ XanMod+BBRv3 + тюнинг
sudo bash install.sh protect      # 🛡 nftables + CrowdSec
sudo bash install.sh diagnose     # 🩺 read-only
sudo bash install.sh all          # всё подряд

# неинтерактивно
sudo SSH_PORT=22 TCP_PORTS=443,2087 UDP_PORTS=443 NODE_PORT=2222 \
     WHITELIST="1.2.3.4,2001:db8::1" REMNAWAVE_NONINTERACTIVE=1 \
     bash scripts/protect.sh
```

```bash
# curl|bash:
curl -fsSL https://raw.githubusercontent.com/jestivald/node-accelerator/main/install.sh | sudo bash -s all

# прод-режим: пиньте тег через NA_REF — компрометация ветки main тогда не утечёт
# сразу на весь флот (скрипты тянутся из того же тега):
export NA_REF=v2.1
curl -fsSL "https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF/install.sh" | sudo -E bash -s all
```

> После установки **XanMod нужна перезагрузка** (`reboot`), чтобы BBRv3 заработал. Проверка: `uname -r` содержит `xanmod`.

---

## Параметры `protect.sh` (ENV)

| Переменная | По умолч. | Что |
|---|---|---|
| `SSH_PORT` | авто-детект | порт SSH |
| `TCP_PORTS` / `UDP_PORTS` | `443,2087` | сервисные порты |
| `NODE_PORT` | `2222` | порт node-agent |
| `WHITELIST` | _пусто_ | IP/CIDR (v4+v6) панели/мониторинга — никогда не банятся |
| `SYN_RATE`/`SYN_BURST` | `100`/`200` | **per-IP** новых TCP-конн./сек на порт |
| `UDP_RATE`/`UDP_BURST` | `200`/`400` | **per-IP** UDP пакетов/сек |
| `CONN_LIMIT` | `600` | макс. одновременных конн. с одного IP |
| `SSH_RATE`/`SSH_BURST` | `6`/`5` | новых SSH/мин до бана |
| `SSH_BAN_TIME`/`PORTSCAN_BAN_TIME` | `24h`/`1h` | сроки бана |
| `ENABLE_PORTSCAN_BAN` | `1` | автобан за скан закрытых портов |
| `ENABLE_CROWDSEC` | `1` | ставить CrowdSec + bouncer |
| `ENABLE_SYNPROXY` | `0` | nft synproxy на сервисные порты (advanced) |
| `CROWDSEC_ENROLL_KEY` | _пусто_ | enroll в CrowdSec Console |
| `SAFETY_DELAY` | `300` | сек до авто-сброса правил, если не подтвердить SSH |
| `DRY_RUN` | `0` | `1` — только сгенерировать + `nft -c`, не применять |

`optimize.sh`: `ENABLE_XANMOD=1`, `XANMOD_FLAVOR=lts|main|edge|rt`, `XANMOD_PKG=...`, `REMNAWAVE_SWAP_SIZE=2G`.
`XANMOD_PROBE=1` — проверить, что репозиторий+ключ+сборка ядра резолвятся на этой ОС, **без установки** (для CI и быстрой проверки совместимости).

---

## Проверка и эксплуатация

```bash
na-fw-status                 # текущие баны, счётчики, метрики CrowdSec
na-fw-top-talkers            # топ источников по сервисным портам
nft list table inet na_filter
cscli decisions list
sudo bash scripts/diagnose.sh
```

> **Нода за реверс-прокси / балансировщиком / CDN?** Тогда весь трафик приходит с
> небольшого набора upstream-адресов, и per-IP лимиты (`CONN_LIMIT`/`SYN_RATE`) начнут их
> резать. Посмотри кандидатов через `na-fw-top-talkers` и занеси upstream-диапазоны в
> `WHITELIST=` — whitelist стоит выше всех лимитов.

## Откат

```bash
sudo bash install.sh rollback all        # protect + optimize
sudo bash install.sh rollback protect    # снять firewall (CrowdSec остаётся; NA_PURGE_CROWDSEC=1 чтобы удалить)
sudo bash install.sh rollback optimize   # снять тюнинг (XanMod остаётся; NA_REMOVE_XANMOD=1 + загрузка со стока чтобы удалить)
```

Бэкапы оригиналов — в `/var/backups/node-accelerator/<timestamp>/`.

---

## Почему так (отличия от старого toolkit)

- **Порядок правил исправлен.** В старом `protect.sh` глобальный `syn … accept 1000/s` стоял выше
  пер-портовых правил и `accept` затенял весь port-allow-list, SSH-бан и portscan-детект. Здесь
  SYN-rate **per-IP** внутри каждого сервисного порта, несервисные SYN падают в автобан.
- **Лимиты per-IP, а не глобальные** — один атакующий ограничен, а агрегат масштабируется по числу клиентов.
- **Не `flush ruleset`.** Управляем только `inet na_filter` — CrowdSec-bouncer (`ip crowdsec`, priority −10)
  и Docker-NAT остаются нетронутыми (старый flush ломал Docker-сеть).
- **IPv6-паритет** — autoban/whitelist/scan-детект **и v6-bogon anti-spoof** (раньше v6-сканеры/брут не банились вообще).
- **Логи под rate-limit** — флуд сканов больше не забивает journald/диск.
- **autoban с `size`-капом** — спуф-флудом чистого SYN нельзя раздуть set в памяти ядра.
- **conntrack-ёмкость от RAM** — мелкая VPS под флудом не упирается в OOM ядра.
- **Ключ XanMod по полному отпечатку** + keyserver-фоллбэк при CF-403 (Hetzner/GCP) + поддержка Ubuntu 22.04 (jammy→bookworm).
- **CI** — `shellcheck` + smoke-матрица (Debian/Ubuntu): генерация nftables и резолв XanMod проверяются на каждый PR.

---

MIT. Гарантий нет — это инфраструктурные скрипты, читай перед запуском на проде.
