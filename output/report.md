# 即時封包監測與流量統計系統 — 分析報告

> **Real-time Packet Monitoring and Traffic Statistics System – Analysis Report**
>
> Generated: 2026-04-04 18:30:45

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
| OTHER | 200 | 100.0% |

> 詳細圓餅圖請參閱：`output/protocol_distribution.png`

---

## 4. Top Source IPs

_No data_

---

## 5. Top Destination IPs

_No data_

---

## 6. Top Source Ports

_No data_

---

## 7. Top Destination Ports

_No data_

---

## 8. DNS 查詢 (DNS Queries)

_No DNS queries detected._

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
