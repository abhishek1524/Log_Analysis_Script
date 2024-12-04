# Log Analysis Script

An efficient Python-based log analysis tool that processes and extracts key insights from log files. This script is designed to help monitor server logs by providing detailed statistics on requests per IP address, the most frequently accessed endpoints, and detecting suspicious activity based on failed login attempts. Results are saved in a CSV format for easy analysis and reporting.

---

## 🚀 Features

- **Request Tracking**: Counts requests made by each unique IP address.
- **Endpoint Analysis**: Identifies the most frequently accessed endpoint in the logs.
- **Suspicious Activity Detection**: Flags IP addresses with excessive failed login attempts.
- **CSV Report Generation**: All results are saved in a CSV file for future reference and easy sharing.

---

## 🔧 Requirements

- Python 3.10.6

### To install dependencies, use the following command:

```bash
pip install -r requirements.txt
