# CTF Reconnaissance Script

A comprehensive, optimized Bash script for automated reconnaissance in CTF environments (HackTheBox, TryHackMe, etc.). Features intelligent web fuzzing with FFUF auto-calibration, recursive directory scanning, and organized output structure.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

## 🎯 Features

- **Fast Port Discovery**: Ultra-fast port scanning with RustScan (optional) or comprehensive Nmap
- **Service Enumeration**: Detailed service version detection and vulnerability identification
- **Optimized Web Fuzzing**:
  - FFUF with auto-calibration to eliminate false positives
  - Recursive directory scanning (configurable depth)
  - Single efficient scan vs. multiple redundant scans
- **Targeted Directory Discovery**: Dirsearch for quick wins on HTTP services
- **Intelligent Pattern Matching**: 35+ high-value target patterns (admin, API, config, etc.)
- **Organized Output**: Clean directory structure with human-readable summaries
- **Interactive Setup**: CTF name input for organized result management

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/XploitMonk0x01/recon-script.git
cd recon-script

# Make executable
chmod +x recon-script.sh

# Run the script
./recon-script.sh <target_ip>
```

**Example:**

```bash
./recon-script.sh 10.10.10.10
```

The script will:

1. Prompt for CTF/Room name (e.g., "HackTheBox-Shocker")
2. Perform comprehensive reconnaissance
3. Generate organized results in `CTF_NAME/` directory

## 📋 Requirements

### Required Tools

- `nmap` - Network scanning and service detection
- `gobuster` - Quick directory baseline scanning
- `ffuf` - Primary web fuzzing tool
- `curl` - Web connectivity testing
- `dirsearch` - Targeted web directory discovery

### Optional Tools (Recommended)

- `rustscan` - Ultra-fast port discovery (5-10x faster than nmap)
- `httpx` - HTTP probe and analysis
- `jq` - JSON parsing for enhanced output formatting

### Wordlists

The script uses the following wordlists (in priority order):

- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- `/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt`
- `/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt`

## 🔧 Installation

### Ubuntu/Debian

```bash
# Install required tools
sudo apt update
sudo apt install -y nmap gobuster ffuf curl

# Install dirsearch
pip3 install dirsearch

# Install optional tools
sudo apt install -y jq httpx-toolkit

# Install RustScan (optional but recommended)
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb

# Install SecLists wordlists
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
```

### Kali Linux

```bash
# Most tools are pre-installed, just ensure they're updated
sudo apt update
sudo apt install -y nmap gobuster ffuf dirsearch jq

# Install RustScan if not present
cargo install rustscan
```

## 📖 Usage

### Basic Usage

```bash
./recon-script.sh <target_ip>
```

### Workflow

```
┌─────────────────────────────────────────────────────┐
│  1. Interactive CTF Name Input                      │
│     Example: HackTheBox-Shocker                     │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  2. Fast Port Discovery                             │
│     RustScan: 1-65535 in seconds                    │
│     or Nmap: Comprehensive discovery                │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  3. Service Enumeration                             │
│     Nmap: -sC -sV -A on discovered ports            │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  4. Targeted Web Scanning                           │
│     Dirsearch: Quick wins on HTTP services          │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  5. Optimized Web Fuzzing                           │
│     • Gobuster: Quick baseline (common.txt)         │
│     • FFUF: Primary scan with auto-calibration      │
│     • FFUF: Recursive directory scanning            │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  6. Results Processing & Report Generation          │
│     Human-readable summaries and findings           │
└─────────────────────────────────────────────────────┘
```

## 📁 Output Structure

```
CTF_NAME/
├── rustscan/
│   └── rustscan_<ip>_<timestamp>.txt
├── nmap/
│   ├── nmap_quick_<timestamp>.txt
│   ├── nmap_detailed_<timestamp>.txt
│   └── nmap_detailed_<timestamp>.xml
├── dirsearch/
│   ├── dirsearch_<port>_<timestamp>.txt
│   ├── dirsearch_<port>_<timestamp>.json
│   └── dirsearch_summary.txt              ← Priority findings
├── web/
│   └── port_<port>/
│       ├── fuzzing.log                    ← Scan progress
│       ├── gobuster_quick.txt             ← Baseline scan
│       ├── ffuf_results.json              ← Primary FFUF scan
│       ├── ffuf_recursive.json            ← Recursive findings
│       ├── recursive_fuzzing.log          ← Recursive progress
│       └── interesting_findings.txt       ← ⭐ Human-readable summary
├── notes/
│   └── notes.md                           ← Template for manual notes
└── REPORT.md                              ← Final comprehensive report
```

## 🎨 Key Features Explained

### Auto-Calibration (FFUF)

Automatically filters out false positives by analyzing response patterns:

```bash
# Without auto-calibration:
http://target/search?q=admin    [200] [4523B]  ← Real
http://target/search?q=test     [200] [4523B]  ← False positive
http://target/search?q=random   [200] [4523B]  ← False positive

# With auto-calibration (-ac):
http://target/search?q=admin    [200] [4523B]  ← Real
# False positives automatically filtered!
```

### Recursive Fuzzing

Automatically discovers and scans subdirectories:

```bash
# Initial scan finds:
http://target/admin  [301]
http://target/api    [200]

# Recursive scan automatically runs:
ffuf -u http://target/admin/FUZZ  → finds: config.php, users, dashboard
ffuf -u http://target/api/FUZZ    → finds: v1, swagger, docs
```

### High-Value Target Detection

Searches for 35+ patterns including:

- **Admin panels**: admin, dashboard, console, panel, control
- **Authentication**: login, signin, signup, register, auth
- **Configuration**: config, settings, .env
- **APIs**: api, rest, graphql, swagger, docs
- **CMS**: wp-admin, phpmyadmin, adminer
- **Sensitive**: backup, secret, private, internal, password, token

## ⚙️ Configuration

Edit these variables at the top of the script to customize:

```bash
# Recursive Fuzzing
RECURSIVE_DEPTH=2              # Number of directories to scan recursively
RECURSIVE_TIMEOUT=300          # Timeout per recursive scan (seconds)

# FFUF Configuration
FFUF_THREADS=30                # Concurrent threads
FFUF_EXTENSIONS="html,php,txt,js,css,json,xml,bak,old,zip,tar,gz"

# Dirsearch Configuration
DIRSEARCH_THREADS=50
DIRSEARCH_TIMEOUT=10

# Timeouts
DEFAULT_TIMEOUT=10
MAX_FUZZ_TIME=900              # Maximum fuzzing time (15 minutes)
```

## 📊 Performance Comparison

| Metric           | Before Optimization | After Optimization | Improvement          |
| ---------------- | ------------------- | ------------------ | -------------------- |
| Scan Time        | ~36 minutes         | ~16 minutes        | **55% faster** ⚡    |
| False Positives  | ~30%                | <5%                | **6x reduction** ✨  |
| Output Size      | ~500KB              | ~150KB             | **70% smaller** 📉   |
| Unique Findings  | ~50 paths           | ~65 paths          | **30% more** 🎯      |
| Pattern Coverage | 9 patterns          | 35+ patterns       | **3.8x coverage** 🔍 |

## 💡 Tips & Best Practices

### Review Priority Files First

1. **`interesting_findings.txt`** - Start here for quick overview
2. **`dirsearch_summary.txt`** - Quick wins from targeted scanning
3. **`REPORT.md`** - Comprehensive summary with useful commands

### Useful Commands

```bash
# Find all admin-related paths
grep -i "admin" CTF_NAME/web/port_*/interesting_findings.txt

# Find all 200 status codes
grep "\[HTTP 200\]" CTF_NAME/web/port_*/interesting_findings.txt

# Search for high-value targets
grep -E "(admin|api|config|dashboard)" CTF_NAME/web/port_*/interesting_findings.txt

# Monitor scan progress
tail -f CTF_NAME/web/port_80/fuzzing.log
```

### For Faster Scans

```bash
FFUF_THREADS=50
RECURSIVE_DEPTH=1
RECURSIVE_TIMEOUT=120
```

### For More Thorough Scans

```bash
FFUF_THREADS=20
RECURSIVE_DEPTH=5
RECURSIVE_TIMEOUT=600
```

## 🐛 Troubleshooting

### No Recursive Scan Results?

Check the recursive log:

```bash
cat CTF_NAME/web/port_80/recursive_fuzzing.log
```

**Common causes:**

- No directories found in initial scan
- No redirects (301/302) discovered
- `jq` not installed (uses fallback)

**Solution:** Install `jq` for better directory detection:

```bash
sudo apt install jq
```

### Too Many False Positives?

Auto-calibration should handle this, but verify:

```bash
# Check response sizes
jq '.results[] | .length' CTF_NAME/web/port_80/ffuf_results.json | sort -u
```

If you see many identical sizes, the target may have WAF or rate limiting.

### Scan Taking Too Long?

Reduce timeouts and depth:

```bash
RECURSIVE_TIMEOUT=180
RECURSIVE_DEPTH=1
MAX_FUZZ_TIME=600
```

Or kill manually:

```bash
pkill -f "ffuf.*FUZZ"
```

## 📚 Additional Documentation

- **[OPTIMIZATION_SUMMARY.md](OPTIMIZATION_SUMMARY.md)** - Technical details of optimizations
- **[BEFORE_AFTER.md](BEFORE_AFTER.md)** - Visual comparison with examples
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick reference guide for features

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational purposes and ethical hacking only. Always ensure you have proper authorization before scanning any target. Unauthorized access to computer systems is illegal.

## 🙏 Acknowledgments

- **RustScan** - Fast port scanning
- **FFUF** - Powerful web fuzzing
- **Dirsearch** - Web directory discovery
- **SecLists** - Comprehensive wordlists
- **danielmiessler** - SecLists creator
- CTF community for testing and feedback

## 📧 Contact

- GitHub: [@XploitMonk0x01](https://github.com/XploitMonk0x01)
- Repository: [recon-script](https://github.com/XploitMonk0x01/recon-script)

---

**Happy Hacking! 🎯🔓**

_Made with ❤️ for the CTF community_
