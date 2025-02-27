# Automating Threat Hunting Using MSTICPy

## Overview
This project focuses on automating threat hunting using MSTICPy, a Python cybersecurity library. The automation processes logs from multiple sources (Splunk, local storage, etc.), integrates threat intelligence, automates IoC matching,correlates threats, and generates actionable reports.

## Features
- **Real-time & Non-Real-time Threat Hunting**: Automates log processing for continuous monitoring.
- **Integration with Splunk & Local Logs**: Supports multiple log sources.
- **Threat Intelligence Enrichment**: Matches indicators of compromise (IoCs) with external threat feeds.
- **Log Correlation & Analysis**: Detects suspicious patterns across different log sources.
- **Visualization in Grafana**: Displays threat data with real-time dashboards.
- **Automated Alerts**: Sends notifications upon detecting anomalies.

## Prerequisites
- Python 3.8+
- Jupyter Notebook
- MSTICPy 
- Splunk (for real-time log ingestion)
- PostgreSQL (For log storage)
- Grafana (For visualization)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/mekaizen/threat_hunting.git
   cd threat-hunting
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```


## Usage
### 1. Data Ingestion
- **From Splunk**:
  ```python
  from msticpy.data import SplunkSpl
  spl = SplunkSpl()  # Configure Splunk connection
  data = spl.query("search index=threat_logs | table _time, src_ip, dest_ip, user")
  ```
- **From Local Logs (CSV, JSON, Log files)**:
  ```python
  import pandas as pd
  df = pd.read_csv("http_logs.csv")
  ```

### 2. Threat Intelligence Lookup
```python
from msticpy.sectools.tilookup import TILookup
ti_lookup = TILookup()
ti_results = ti_lookup.lookup_iocs(df["ip_address"].tolist(), providers=["OTX", "VirusTotal"])
```

### 3. Log Correlation & Alerting
```python
suspicious_events = df[(df["severity"] == "High") & (df["ip_address"].isin(ti_results.keys()))]
if not suspicious_events.empty:
    print("Alert: Suspicious activity detected!")
```

### 4. Visualization with Grafana 
Export processed logs to PostgreSQL and visualize in Grafana.

```

![Malicious URL](https://github.com/mekaizen/threat_hunting/blob/main/images/Malicious%20URL.png)

```

## Automation
Schedule threat hunting using cron jobs or a task scheduler:
```sh
*/5 * * * * python threat_hunting_script.py  # Runs every 5 minutes
```

## Future Enhancements
- Integration with ElasticSearch/Kibana
- Machine learning-based anomaly detection
- Advanced threat correlation with MITRE ATT&CK

## License
MIT License



