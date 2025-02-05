# Minemeld-to-Wazuh Integration

This project provides an integration between **Minemeld** and **Wazuh**, allowing you to leverage Minemeld threat intelligence feeds within the Wazuh security monitoring platform.

## 📌 Features
- Fetches threat intelligence feeds from **Minemeld**.
- Converts and integrates feeds into **Wazuh**.
- Automates the process of updating Wazuh with threat indicators.
- Supports **IP addresses, domains, and URLs** as threat intelligence indicators.

## 📂 Repository Structure
```
📦 Minemeld-to-Wazuh-integration
├── 📜 config.ini        # Configuration file for the integration
├── 📜 minemeld_to_wazuh.py  # Main script to fetch and push indicators
├── 📜 requirements.txt  # Python dependencies
├── 📜 README.md         # Documentation
└── 📜 LICENSE           # License file
```

## 🔧 Requirements
- Python 3.x
- Minemeld instance with active threat feeds
- Wazuh installed and configured
- `requests` and `json` Python libraries

## ⚙️ Configuration (`config.ini`)
The integration is configured using a **config.ini** file. Below is a breakdown of each section:

### `[WAZUH]` – Wazuh API Configuration
| Key              | Description                                                 |
|-----------------|-------------------------------------------------------------|
| `API_URL`       | URL of your Wazuh API (e.g., `https://wazuh-server:55000`) |
| `API_USER`      | Username for accessing the Wazuh API                        |
| `API_PASS`      | Password for the Wazuh API user                             |
| `CDB_SIZE_LIMIT` | Maximum size limit (in bytes) for the custom database      |

**Example Wazuh Configuration:**
```ini
[WAZUH]
API_URL = https://your-wazuh-server:55000
API_USER = wazuh_admin
API_PASS = yourpassword
CDB_SIZE_LIMIT = 2097152
```

---

### `[MINEMELD]` – Minemeld API Configuration
| Key           | Description                                                        |
|--------------|--------------------------------------------------------------------|
| `API_URL`    | URL of your Minemeld server (e.g., `https://minemeld-server`)    |
| `FEED_NAMES` | Comma-separated list of Minemeld feeds to fetch indicators from |

**Example Minemeld Configuration:**
```ini
[MINEMELD]
API_URL = https://your-minemeld-server
FEED_NAMES = malicious_ips, phishing_domains, malware_urls
```

---

## 🚀 Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/Potass1umN1trate/Minemeld-to-Wazuh-integration.git
   cd Minemeld-to-Wazuh-integration
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the integration**:
   - Edit `config.ini` and provide:
     - Minemeld API URL & feed names
     - Wazuh API credentials
     - Custom database size limit (if needed)

4. **Run the script**:
   ```bash
   python minemeld_to_wazuh.py
   ```

## 🔄 Automation
To automate the process, you can schedule the script using **cron** (Linux/macOS) or **Task Scheduler** (Windows).

Example cron job to run every hour:
```bash
0 * * * * /usr/bin/python3 /path/to/minemeld_to_wazuh.py
```

## 🛠 Troubleshooting
- Ensure Minemeld and Wazuh are running.
- Check API credentials in `config.ini`.
- Verify that the required Python libraries are installed.

## 📜 License
This project is licensed under the **MIT License**. See the `LICENSE` file for more details.

## 📧 Support
For issues or feature requests, please open an **Issue** in the [GitHub repository](https://github.com/Potass1umN1trate/Minemeld-to-Wazuh-integration/issues).
