# Domain Scanner

**Domain Scanner** is a command-line tool for analyzing domains.  
It performs WHOIS and IP lookups, scans SSL certificates, discovers subdomains, and searches for email addresses.

---

## Features

- **WHOIS and IP Lookup**  
  Retrieves domain owner, registrar, creation/expiration dates, and geolocation for name servers using `whoisdomain` and `ipinfo.io`.

- **SSL Certificate Scan**  
  Extracts certificate details such as subject, issuer, and validity period.

- **Subdomain Scan**  
  Finds subdomains using a wordlist with multi-threaded scanning.

- **Email Search (Hunter.io)**  
  Queries the [Hunter.io](https://hunter.io/) API to find email addresses associated with the target domain.

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/domain-scanner.git
cd domain-scanner
pip install -r requirements.txt
```

Or install manually:

```bash
pip install requests whoisdomain python-dotenv
```

---

## 🚀 Usage

Run the tool with a domain:

```bash
python main.py <domain>
```

This runs **all available scans** by default.

### Run Specific Scans

```bash
python main.py example.com --whois --ssl
```

Available options:

- `--whois` → Perform WHOIS and IP lookup  
- `--ssl` → Scan SSL certificate  
- `--subdomains` → Run subdomain scan  
- `--hunter` → Search for emails via Hunter.io  

### Extra Options

- `-w, --wordlist` → Custom wordlist for subdomain scan  
- `-t, --threads` → Threads for subdomain scan (default: 50)  
- `--ipinfo-key` → API key for [ipinfo.io](https://ipinfo.io)  
- `--hunter-key` → API key for [hunter.io](https://hunter.io)  
- `--config` → Path to `.env` configuration file  
- `--output` → Save output to a text file  

Example:

```bash
python main.py example.com --subdomains -w wordlist.txt -t 100 --output results.txt
```

---

## ⚙️ Configuration

You can configure the tool via a `.env` file.  
A sample `config.env` is provided in the `config/` directory.

Available keys:

```ini
IPINFO_API_KEY=your_ipinfo_key_here
HUNTER_API_KEY=your_hunter_key_here
WORDLIST_PATH=subdomains.txt
THREADS=50
```

---

## 📂 Project Structure

```
.
├── main.py                # Entry point
├── scanners/              # Individual scanners (whois, ssl, hunter, subdomains)
├── utils/                 # Helper functions
├── config/                # Sample configuration files
└── README.md
```

---

## 📜 License

This project is licensed under the MIT License.  
See the [LICENSE.md](LICENSE.md) file for details.

---

## 🔮 Roadmap / Future Work

- [ ] Add DNS records scan (MX, TXT, A, CNAME).  
- [ ] Support asynchronous subdomain scanning for performance.  
- [ ] Add Shodan integration for host intelligence.  
- [ ] Export results to JSON/CSV.  

---

## 🤝 Contributing

Pull requests are welcome!  
For major changes, please open an issue first to discuss what you would like to change.

---

## ⚠️ Disclaimer

This tool is for **educational and security research purposes only**.  
Do not use it on domains you do not own or have permission to test.
