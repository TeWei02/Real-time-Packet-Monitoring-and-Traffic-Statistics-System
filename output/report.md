# 即時封包監測與流量統計系統 — 分析報告

> **Real-time Packet Monitoring and Traffic Statistics System – Analysis Report**
>
> Generated: 2026-04-04 18:28:59

---

## 1. 執行摘要 (Executive Summary)

本次分析共擷取 **200** 個封包，傳輸總量為 **10.3 KB**，
分析持續時間約 **59.64 秒**，平均每秒封包數（PPS）為 **3.35 pkt/s**。

---

## 2. 關鍵統計指標 (Key Metrics)

| 指標 | 數值 |
|------|------|
| 總封包數 (Total Packets) | 200 |
| 總傳輸量 (Total Bytes) | 10.3 KB |
| 平均封包大小 (Avg Packet Size) | 52.63 bytes |
| 分析持續時間 (Duration) | 59.64 s |
| 平均 PPS | 3.35 pkt/s |
| 尖峰 PPS (Peak PPS) | 4 pkt/s |
| 尖峰時間點 (Peak Time) | `2026-04-04 18:27:58` |

---

## 3. 協定分布 (Protocol Distribution)

| Protocol | Packets | Share |
|--- | --- | ---|
| TCP | 81 | 40.5% |
| UDP | 56 | 28.0% |
| DNS | 41 | 20.5% |
| ICMP | 22 | 11.0% |

> 詳細圓餅圖請參閱：`output/protocol_distribution.png`

---

## 4. Top Source IPs

| Source IP | Packets |
|--- | ---|
| 10.0.0.5 | 80 |
| 192.168.1.10 | 72 |
| 192.168.1.20 | 48 |

---

## 5. Top Destination IPs

| Destination IP | Packets |
|--- | ---|
| 8.8.8.8 | 101 |
| 1.1.1.1 | 38 |
| 172.217.0.1 | 32 |
| 192.168.1.20 | 29 |

---

## 6. Top Source Ports

| Port | Service | Packets |
|--- | --- | ---|
| 7325 | 7325 | 1 |
| 41862 | 41862 | 1 |
| 24589 | 24589 | 1 |
| 25418 | 25418 | 1 |
| 40751 | 40751 | 1 |
| 31331 | 31331 | 1 |
| 21765 | 21765 | 1 |
| 46311 | 46311 | 1 |

---

## 7. Top Destination Ports

| Port | Service | Packets |
|--- | --- | ---|
| 53 | DNS | 61 |
| 80 | HTTP | 24 |
| 8080 | HTTP-alt | 21 |
| 443 | HTTPS | 19 |
| 5353 | 5353 | 19 |
| 22 | SSH | 17 |
| 123 | 123 | 17 |

---

## 8. DNS 查詢 (DNS Queries)

| Query | Count |
|--- | ---|
| openai.com | 18 |
| google.com | 10 |
| example.com | 7 |
| github.com | 6 |

---

## 9. 技術說明 (Technical Notes)

- 封包解析採用 **Scapy** 進行 protocol dissection，支援 Ethernet / IPv4 / TCP / UDP / ICMP / DNS / HTTP。
- 統計彙整使用 **pandas** 進行 flow-level statistics 計算。
- 終端機儀表板透過 **Rich** 實現 real-time packet inspection 顯示。
- 圖表輸出採用 **Matplotlib**，適合嵌入書面報告。
- 系統設計採 lightweight network observability 原則，模組化可擴充。

---

## 10. 可延伸方向 (Future Work)

1. 整合 **Elasticsearch + Kibana** 建立長期 traffic profiling 儲存與查詢介面。
2. 加入 **異常流量偵測**（IP flood / port scan detection）。
3. 支援 **IPv6** 封包解析。
4. 加入 Web UI（Flask / FastAPI）以實現瀏覽器端即時監測。
5. 與 **Zeek / Suricata** 整合進行 deep packet inspection。

---

*此報告由 packet-monitor 自動產生。*
