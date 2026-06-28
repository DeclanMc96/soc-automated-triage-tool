# SOC Automated Triage Tool

A Python-based command-line tool for automating the enrichment of IP address indicators of compromise (IOCs) during security incident triage. It queries **AbuseIPDB** and **VirusTotal** simultaneously and compiles the results into a structured threat intelligence report.

---

## Features

- Queries AbuseIPDB for abuse confidence score, usage type, and report history
- Queries VirusTotal for multi-engine malicious detection rates, ASN owner, and country
- Automatically saves a structured triage report to disk per IOC
- Secure API key management via `.env` file
- Graceful error handling for network failures and missing data

---

## Requirements

- Python 3.7+
- A free or paid [AbuseIPDB](https://www.abuseipdb.com/) API key
- A free or paid [VirusTotal](https://www.virustotal.com/) API key

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/your-username/soc-triage-tool.git
cd soc-triage-tool
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Configure your API keys**

Create a `.env` file in the root of the project:

```bash
touch .env
```

Add your API keys to the file:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

> ⚠️ Never commit your `.env` file to version control. Ensure `.env` is listed in your `.gitignore`.

---

## Usage

Run the tool from the terminal with the `-i` flag followed by the IP address you want to investigate:

```bash
python triage.py -i 8.8.8.8
```

### Example Output

```
--------------------------------------------------
[*] Initialising SOC Triage for IOC: 8.8.8.8
[*] Gathering threat intelligence...
--------------------------------------------------

========================================
SOC AUTOMATED TRIAGE REPORT FOR: 8.8.8.8
========================================

--- ABUSEIPDB RESULTS ---
Abuse Score:     0%
Whitelisted:     True
Usage Type:      Data Center/Web Hosting/Transit
Total Reports:   0

--- VIRUSTOTAL RESULTS ---
Detections:      0 / 94 engines
Owner:           Google LLC
Country Code:    US

[+] Automated triage complete. Report saved to: triage_report_8.8.8.8.txt
```

The tool also saves a `.txt` report file named `triage_report_<IP>.txt` in the current working directory.

---

## Project Structure

```
soc-triage-tool/
├── triage.py           # Main script
├── .env                # API keys (not committed)
├── .gitignore          # Excludes .env and report files
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## Dependencies

| Package      | Purpose                              |
|--------------|--------------------------------------|
| `requests`   | HTTP requests to AbuseIPDB and VirusTotal APIs |
| `python-dotenv` | Loads API keys securely from `.env` |

Install all dependencies with:

```bash
pip install requests python-dotenv
```

Or generate a `requirements.txt`:

```bash
pip freeze > requirements.txt
```

---

## Roadmap

- [ ] Input validation for IP address format
- [ ] HTTP error handling for rate limits and auth failures (429, 401)
- [ ] Timestamps on generated reports
- [ ] Batch mode — accept a file of multiple IOCs via `-f` flag
- [ ] Colour-coded terminal output using `colorama`
- [ ] Severity verdict (`LOW / MEDIUM / HIGH`) based on combined score thresholds
- [ ] Support for URL and file hash lookups via VirusTotal

---

## Disclaimer

This tool is intended for defensive security and educational purposes only. Ensure you comply with the terms of service of AbuseIPDB and VirusTotal when using their APIs.

---

## Author 
## Author 

**Declan McGrath-Hughes**  
Built to automate IP reputation lookups during SOC triage workflows.  
[LinkedIn] www.linkedin.com/in/declan-mcgrath-hughes-18a05a2b5 | [GitHub][(https://github.com/your-username)] https://github.com/DeclanMc96
