

<div align="center">

```
                        ╔═══════════════════════════════════════════════════════════════════╗
                        ║                                                                   ║
                        ║                     ⚡ LINUX ARC REACTOR ⚡                      ║
                        ║       Modern Tools to Complement Your Linux Distribution          ║
                        ║                                                                   ║
                        ║          Automated Installation of 50+ Security Tools             ║
                        ║                                                                   ║
                        ╚═══════════════════════════════════════════════════════════════════╝
```

[![Bash](https://img.shields.io/badge/Bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Enhance your security arsenal** - Automated installation of modern security tools for any Linux distribution.

[Installation](#-installation-instructions) • [Tools](#-complete-tool-list) • [Usage](#-tool-usage-examples) • [Troubleshooting](#-troubleshooting)

</div>

---

## 📋 Overview

The **Linux Security Tools Installer** is a comprehensive Bash script that automates the installation of 50+ cutting-edge security testing, bug bounty hunting, and penetration testing tools. Designed to complement existing tools and bring the latest security innovations to any Linux distribution.

### ✨ Key Features

- 🚀 **One-Click Installation**: Install 50+ tools with a single command
- 🔧 **Automatic Configuration**: Sets up PATH, downloads dependencies, builds from source
- 📦 **Multi-Distro Support**: Works on Ubuntu, Debian, Fedora, Arch Linux, and Kali
- 📝 **Comprehensive Logging**: Track installation progress and errors
- 🛡️ **Production-Ready**: Installs enterprise-grade security tools
- ⚡ **Latest Versions**: Get cutting-edge tools from GitHub releases

### 🎯 Use Cases

- **Bug Bounty Hunting**: Modern reconnaissance and vulnerability scanning tools
- **Penetration Testing**: Advanced exploitation and fuzzing frameworks
- **Cloud Security**: AWS, Azure, GCP security auditing tools
- **Container Security**: Kubernetes and Docker security testing
- **Mobile Security**: Android reverse engineering and analysis tools
- **DevSecOps**: Supply chain and dependency security tools

### 💡 Perfect For

- **Kali Linux Users**: Get the latest tools not in Kali's default repositories
- **Ubuntu/Debian Users**: Build a comprehensive security toolkit
- **Bug Bounty Hunters**: Access to modern reconnaissance tools
- **Security Researchers**: Latest exploitation and fuzzing frameworks
- **DevSecOps Teams**: Cloud and container security tools

---

## 💻 System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| **Operating System** | Ubuntu 20.04, Debian 11, Kali 2022.x | Ubuntu 22.04, Debian 12, Kali 2024.x |
| **Architecture** | x86_64 (64-bit) | x86_64 (64-bit) |
| **Kernel** | 5.4+ | 5.15+ |
| **RAM** | 4GB | 8GB |
| **Disk Space** | 15GB free | 30GB free |
| **Internet** | Stable connection | High-speed connection |
| **Privileges** | Non-root with sudo | Non-root with sudo |

### 📌 Supported Distributions

**Fully Tested** ✅:
- **Kali Linux** 2022.x, 2023.x, 2024.x (adds latest tools not in repos)
- **Ubuntu** 20.04 LTS, 22.04 LTS, 23.04, 24.04 LTS
- **Debian** 11 (Bullseye), 12 (Bookworm)
- **Fedora** 35, 36, 37, 38, 39
- **RHEL** 8, 9
- **CentOS Stream** 8, 9

**Community Tested** ⚠️:
- Arch Linux
- Manjaro Linux
- Pop!_OS
- Linux Mint
- Parrot Security OS

### 🔍 What This Script Adds

**For Kali Linux Users**:
- ✅ Latest ProjectDiscovery tools (Nuclei, Subfinder, Httpx, Katana, etc.)
- ✅ Modern Go-based security tools
- ✅ Cloud security tools (Prowler, ScoutSuite, Trivy)
- ✅ Container security tools (Grype, kube-bench, kube-hunter)
- ✅ Advanced fuzzing frameworks (AFL++, Honggfuzz)
- ✅ Latest Android analysis tools

**For Other Distributions**:
- ✅ Complete security toolkit from scratch
- ✅ All the tools above plus dependencies

---

## 📚 Complete Tool List

### Go Security Tools (26 tools)

#### ProjectDiscovery Suite (8)
| Tool | Description | GitHub Stars | Use Case |
|------|-------------|--------------|----------|
| nuclei | Vulnerability scanner | 17k+ | Automated vulnerability detection |
| subfinder | Subdomain discovery | 8k+ | Passive subdomain enumeration |
| httpx | HTTP toolkit | 6k+ | Probing live hosts |
| katana | Web crawler | 7k+ | Crawling modern web apps |
| naabu | Port scanner | 4k+ | Fast port scanning |
| dnsx | DNS toolkit | 1k+ | DNS queries and validation |
| notify | Notifications | 1k+ | Multi-channel alerts |
| interactsh | OOB interaction | 3k+ | Out-of-band testing |

#### Subdomain Enumeration (3)
| Tool | Description | Use Case |
|------|-------------|----------|
| amass | OWASP subdomain enum | Comprehensive subdomain discovery |
| assetfinder | Asset discovery | Find related domains |
| subjack | Subdomain takeover | Detect takeover vulnerabilities |

#### Web Crawling (4)
| Tool | Description | Use Case |
|------|-------------|----------|
| gospider | Web spider | Fast crawling |
| hakrawler | Web crawler | Simple crawling |
| gau | URL fetcher | Aggregate URLs from archives |
| waybackurls | Archive URLs | Wayback Machine URL extraction |

#### Directory Discovery (3)
| Tool | Description | Use Case |
|------|-------------|----------|
| ffuf | Web fuzzer | Fast directory/parameter fuzzing |
| gobuster | Brute-forcer | Directory/DNS enumeration |
| feroxbuster | Recursive discovery | Rust-based directory discovery |

#### Web Security (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| dalfox | XSS scanner | Parameter analysis and XSS detection |

#### API Testing (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| kiterunner | API endpoint discovery | Find hidden API endpoints |

#### Cloud Security (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| s3scanner | S3 bucket scanner | Find misconfigured S3 buckets |
| cloudbrute | Cloud enum | Cloud infrastructure enumeration |

#### Container Security (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| grype | Container scanner | Container/filesystem vulnerability scanning |

#### Exploitation (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| sliver | C2 framework | Command and control (BishopFox) |
| merlin | C2 framework | Go-based C2 |

---

### Python Security Tools (24 tools)

#### Subdomain Enumeration (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| sublist3r | Subdomain enum | Fast subdomain enumeration |

#### Web Security (3)
| Tool | Description | Use Case |
|------|-------------|----------|
| arjun | Parameter discovery | Find hidden HTTP parameters |
| xsstrike | XSS scanner | Advanced XSS detection |
| dirsearch | Directory scanner | Web path scanning |

#### GraphQL Testing (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| graphqlmap | GraphQL testing | GraphQL endpoint testing |
| crackql | GraphQL brute-force | GraphQL password attacks |

#### Injection Testing (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| nosqlmap | NoSQL exploitation | NoSQL injection attacks |

#### SSRF Testing (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| ssrfmap | SSRF exploitation | Server-side request forgery |

#### CORS Testing (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| corsy | CORS scanner | CORS misconfiguration detection |

#### JavaScript Analysis (4)
| Tool | Description | Use Case |
|------|-------------|----------|
| linkfinder | Endpoint discovery | Find endpoints in JS files |
| secretfinder | Secret finder | Find secrets in JS files |
| subdomainizer | Subdomain finder | Extract subdomains from JS |
| retire | Vulnerability scanner | JS library vulnerability detection |

#### Cloud Security (3)
| Tool | Description | Use Case |
|------|-------------|----------|
| prowler | Cloud assessment | AWS/Azure/GCP security auditing |
| scoutsuite | Multi-cloud auditing | Cloud security assessment |
| pacu | AWS exploitation | AWS penetration testing framework |

#### Dependency Security (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| safety | Dependency checker | Python dependency vulnerabilities |

#### OSINT (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| recon-ng | Recon framework | Web reconnaissance |
| theharvester | OSINT gathering | Email/subdomain gathering |

#### Android (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| drozer | Android assessment | Android security testing |
| androguard | Android analysis | Python-based Android analysis |

#### Web Fuzzing (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| wfuzz | Web fuzzer | Web application fuzzing |

#### Kubernetes (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| kube-hunter | K8s pentesting | Kubernetes penetration testing |

---

### Compiled Tools (7 tools)

#### Port Scanning (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| masscan | Fast port scanner | Internet-scale port scanning |

#### Cloud Security (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| trivy | Container scanner | Container vulnerability scanning |
| cloudsploit | Config scanner | Cloud configuration scanning |

#### Kubernetes (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| kube-bench | CIS benchmark | Kubernetes security benchmarking |

#### Fuzzing (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| afl++ | Coverage-guided fuzzer | Binary fuzzing |
| honggfuzz | Security fuzzer | Security-oriented fuzzing |

#### JavaScript (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| jsfinder | JS analysis | JavaScript file extraction |

---

### Android Tools (3 tools)

| Tool | Description | Use Case |
|------|-------------|----------|
| dex2jar | DEX converter | Convert DEX to JAR |
| jd-gui | Java decompiler | Decompile Java/Android apps |
| bytecode-viewer | APK analyzer | APK/DEX/JAR analysis |

---

**Total: 50+ security tools**

---

## ✅ Pre-Installation Checklist

### 1. System Preparation
- [ ] **Check disk space** - Need at least 15GB free
- [ ] **Verify sudo access** - Script needs sudo privileges
- [ ] **Stable internet** - Will download several gigabytes
- [ ] **Close other package managers** - apt, dnf, pacman shouldn't be running

```bash
# Check disk space
df -h / | tail -1 | awk '{print "Free space: " $4}'

# Test sudo access
sudo -v && echo "✓ Sudo access OK" || echo "✗ Sudo access FAILED"

# Check internet connectivity
ping -c 3 google.com > /dev/null 2>&1 && echo "✓ Internet OK" || echo "✗ Internet FAILED"
```

### 2. Update System First
```bash
# Ubuntu/Debian/Kali
sudo apt update && sudo apt upgrade -y

# Fedora/RHEL/CentOS
sudo dnf update -y

# Arch/Manjaro
sudo pacman -Syu --noconfirm
```

### 3. Free Up Disk Space (if needed)
```bash
# Ubuntu/Debian/Kali - clean package cache
sudo apt autoremove -y
sudo apt autoclean -y

# Fedora/RHEL
sudo dnf autoremove -y
sudo dnf clean all

# Arch/Manjaro
sudo pacman -Sc --noconfirm

# Clear old logs
sudo journalctl --vacuum-time=7d
```

### 4. For Kali Users - Update Existing Tools First
```bash
# Update Kali's default tools first
sudo apt update && sudo apt full-upgrade -y

# Then run this script to add additional tools
```

---

## 🚀 Installation Instructions

### Method 1: Standard Installation (Recommended)

#### Step 1: Download the Script
Save the script to your home directory or Downloads folder.

#### Step 2: Make Script Executable
```bash
chmod +x linux-security-tools.sh
```

#### Step 3: Run Installation
```bash
# Run as regular user (NOT with sudo)
./linux-security-tools.sh
```

**Important Notes**:
- ⚠️ **Do NOT run with `sudo`** - Script will request sudo when needed
- ⏱️ Installation takes 30-60 minutes depending on internet speed
- 📝 Watch for colored output (green = success, red = error)
- ☕ This will take a while - grab coffee!

**For Kali Users**:
- ✅ Script works on Kali Linux - it adds tools not in default repos
- ✅ Complements existing Kali tools with latest versions
- ✅ No conflicts with Kali's package management

---

### Method 2: Quick One-Liner

```bash
chmod +x linux-security-tools.sh && ./linux-security-tools.sh
```

---

### Method 3: Download and Run (if hosted online)

```bash
# Using wget
wget https://raw.githubusercontent.com/yourusername/linux-security-tools/main/linux-security-tools.sh
chmod +x linux-security-tools.sh
./linux-security-tools.sh

# Or using curl
curl -O https://raw.githubusercontent.com/yourusername/linux-security-tools/main/linux-security-tools.sh
chmod +x linux-security-tools.sh
./linux-security-tools.sh
```

---

## 📦 What Gets Installed

### Installation Timeline

```
Phase 1: System Dependencies        [▓▓▓▓░░░░░░] 5-10 min
Phase 2: Go Security Tools          [▓▓▓▓▓▓░░░░] 10-15 min
Phase 3: Python Security Tools      [▓▓▓▓░░░░░░] 5-10 min
Phase 4: Masscan                    [▓▓░░░░░░░░] 2-3 min
Phase 5: Cloud Security Tools       [▓▓▓░░░░░░░] 3-5 min
Phase 6: Kubernetes Tools           [▓▓░░░░░░░░] 2-3 min
Phase 7: Fuzzing Frameworks         [▓▓▓░░░░░░░] 5-7 min
Phase 8: Android Tools              [▓▓░░░░░░░░] 2-3 min
Phase 9: JavaScript Analysis        [▓░░░░░░░░░] 1-2 min
                                    ─────────────────────
                          Total Time: 30-60 minutes
```

### 🎯 What Makes This Different

**Modern Tools Not in Standard Repos**:
- Latest ProjectDiscovery suite (updated frequently)
- Cutting-edge Go-based security tools
- Modern cloud security frameworks
- Container and Kubernetes security tools
- Advanced fuzzing frameworks compiled from source

**For Kali Users**:
These tools complement Kali's excellent default toolkit with:
- Latest versions built from source (often newer than Kali repos)
- Specialized tools for cloud/container security
- Modern bug bounty hunting tools
- Advanced fuzzing frameworks

---


---

## 📁 Installation Locations

### Main Installation Directory
```
~/security-tools/
│
├── masscan/              # Masscan (compiled from source)
├── cloudsploit/          # CloudSploit
├── kube-bench/           # kube-bench
├── aflplusplus/          # AFL++
├── honggfuzz/            # Honggfuzz
├── jsfinder/             # JSFinder
├── android/              # Android tools
│   ├── dex2jar-*/
│   ├── jd-gui.jar
│   └── bytecode-viewer.jar
│
├── tools/                # Additional tools
├── scripts/              # Custom scripts
├── results/              # Scan results
└── configs/              # Configuration files
```

### Go Tools Location
```
~/go/bin/
├── nuclei
├── subfinder
├── httpx
├── katana
├── naabu
├── dnsx
├── notify
├── interactsh-client
├── amass
├── assetfinder
├── subjack
├── gospider
├── hakrawler
├── gau
├── waybackurls
├── ffuf
├── gobuster
├── feroxbuster
├── dalfox
├── kiterunner
├── s3scanner
├── cloudbrute
├── grype
├── sliver
└── merlin
```

### Python Packages Location
```
~/.local/lib/python3.x/site-packages/

Installed packages:
  - sublist3r, arjun, xsstrike, dirsearch
  - graphqlmap, crackql, nosqlmap, ssrfmap, corsy
  - linkfinder, secretfinder, subdomainizer, retire
  - prowler, scoutsuite, pacu, safety
  - recon-ng, theharvester
  - drozer, androguard, wfuzz, kube-hunter
```

### System Binaries
```
/usr/local/bin/
├── masscan
├── trivy
├── kube-bench
├── afl-fuzz
├── afl-gcc
└── honggfuzz
```

### Bug Bounty Workspace
```
~/bug-bounty/
│
├── recon/                       # Reconnaissance phase
│   ├── subdomains/              # Subdomain enumeration results
│   ├── urls/                    # URL discovery results
│   └── ports/                   # Port scan results
│
├── scanning/                    # Vulnerability scanning
├── exploitation/                # Exploitation phase
└── reporting/                   # Reports and documentation
```

### Log File
```
~/security-tools-install.log
```

---

## ✨ Post-Installation Steps

### Step 1: Reload Shell Environment

After installation, reload your shell to apply PATH changes:

```bash
# For bash
source ~/.bashrc

# For zsh (if using zsh)
source ~/.zshrc

# Or simply open a new terminal window
```

---

### Step 2: Verify Installation

Verify all tools are accessible:

```bash
# Test Go tools
nuclei -version
subfinder -version
httpx -version
ffuf -V
amass -version

# Test compiled tools
masscan --version
trivy --version

# Test Python tools
python3 -c "import arjun; print('Arjun: OK')"
prowler -v

# Test PATH configuration
echo $PATH | grep -o "$HOME/go/bin"
which nuclei subfinder httpx
```

**Expected Output**:
```
✓ nuclei: Nuclei v3.x.x
✓ subfinder: Subfinder v2.x.x
✓ httpx: httpx v1.x.x
✓ ffuf: ffuf version v2.x.x
✓ masscan: version 1.3.x
✓ All tools found in PATH
```

---

### Step 3: Update Nuclei Templates

Nuclei templates are updated frequently with new CVE checks:

```bash
# Update templates
nuclei -update-templates

# Verify templates
nuclei -tl | head -20

# Count templates
nuclei -tl | wc -l
# Should show 3000+ templates
```

---

## 🔧 Troubleshooting

### Issue 1: Permission Denied

**Error**: `Permission denied`

**Solution**:
```bash
# Make script executable
chmod +x linux-security-tools.sh

# Verify permissions
ls -l linux-security-tools.sh
# Should show: -rwxr-xr-x
```

---

### Issue 2: Go Tools Not Found

**Error**: `command not found: nuclei`

**Solution**:
```bash
# Check if Go bin is in PATH
echo $PATH | grep "$HOME/go/bin"

# If not found, add to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
which nuclei
```

---

### Issue 3: Python Tools Not Found

**Error**: `ModuleNotFoundError` or `command not found`

**Solution**:
```bash
# Check Python installation
python3 --version
which python3

# Check pip
pip3 --version

# Reinstall tools
python3 -m pip install --user arjun xsstrike prowler

# Add local bin to PATH
echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc
```

---

### Issue 4: Build Failures (Masscan, AFL++, etc.)

**Error**: Compilation errors during build

**Solution**:
```bash
# Install build dependencies
# Ubuntu/Debian/Kali
sudo apt install build-essential libpcap-dev

# Fedora/RHEL
sudo dnf install gcc gcc-c++ make libpcap-devel

# Arch
sudo pacman -S base-devel libpcap

# Retry installation
./linux-security-tools.sh
```

---

### Issue 5: Tools Already Installed (Kali)

**Note**: If tool already exists (common on Kali), script may skip or overwrite

**Solution**:
```bash
# This is expected behavior
# Script installs latest versions from source
# Go tools in ~/go/bin take priority over system versions

# To use system version instead:
/usr/bin/nuclei -version

# To use installed version:
~/go/bin/nuclei -version
# or just
nuclei -version
```

---

### Issue 6: Masscan Requires Root

**Error**: `masscan: permission denied`

**Cause**: Masscan requires root privileges for raw sockets

**Solution**:
```bash
# Run with sudo
sudo masscan 192.168.1.0/24 -p 80,443

# Or set capabilities
sudo setcap cap_net_raw+ep /usr/local/bin/masscan
```

---

## 🔄 Updating Tools

Regular updates ensure you have the latest features and vulnerability checks.

### Update Schedule Recommendation
- **Weekly**: Nuclei templates
- **Monthly**: Go tools, Python packages
- **Quarterly**: System dependencies

---

### Update All Tools Script

Create `update-all-tools.sh`:

```bash
#!/bin/bash

echo "Updating all security tools..."

# Update system
echo "[1/5] Updating system packages..."
sudo apt update && sudo apt upgrade -y 2>/dev/null || \
sudo dnf update -y 2>/dev/null || \
sudo pacman -Syu --noconfirm 2>/dev/null

# Update Python tools
echo "[2/5] Updating Python tools..."
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade arjun xsstrike prowler scoutsuite

# Update Go tools
echo "[3/5] Updating Go tools..."
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Update Nuclei templates
echo "[4/5] Updating Nuclei templates..."
nuclei -update-templates

# Update Trivy database
echo "[5/5] Updating Trivy database..."
trivy image --download-db-only

echo "All tools updated!"
```

---

## 🔒 Security Considerations

### Legal and Ethical Use

⚠️ **CRITICAL WARNING**: Unauthorized security testing is illegal

**You MUST have authorization before testing**:
- ✅ Written permission from system owner
- ✅ Signed penetration testing contract
- ✅ Authorized bug bounty program participation
- ✅ Your own systems/applications

**Legal Testing Environments**:
- Personal lab/servers
- Bug bounty platforms (HackerOne, Bugcrowd)
- Authorized pentesting engagements
- CTF competitions (HackTheBox, TryHackMe)

**NEVER Test Without Permission**:
- ❌ Employer's systems (without authorization)
- ❌ School/university networks
- ❌ Government systems
- ❌ Public websites

---

## 📖 Additional Resources

### Official Documentation
- **Nuclei**: https://docs.projectdiscovery.io/nuclei/
- **Prowler**: https://github.com/prowler-cloud/prowler
- **Trivy**: https://aquasecurity.github.io/trivy/

### Bug Bounty Platforms
- **HackerOne**: https://www.hackerone.com
- **Bugcrowd**: https://www.bugcrowd.com
- **Intigriti**: https://www.intigriti.com

### Learning Platforms
- **HackTheBox**: https://www.hackthebox.com
- **TryHackMe**: https://tryhackme.com

---

## 🤝 Contributing

Contributions welcome! Submit a Pull Request.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**IMPORTANT LEGAL NOTICE**

This tool collection is for:
- Authorized security testing
- Educational purposes
- Security research
- Bug bounty programs

**By using this script, you agree to**:
- Use tools only on authorized targets
- Follow all applicable laws
- Accept full responsibility
- Not hold author liable for misuse

---

<div align="center">

**Made with ⚡ by Security Researchers, for Security Researchers**

If you found this helpful, please ⭐ star the repository!

[Report Bug](https://github.com/yourusername/linux-security-tools/issues) • [Request Feature](https://github.com/yourusername/linux-security-tools/issues)

</div>
