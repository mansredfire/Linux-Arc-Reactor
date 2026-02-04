# Linux Security Tools - Bash Installation Guide

## 📋 Table of Contents
- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Pre-Installation Checklist](#pre-installation-checklist)
- [Installation Instructions](#installation-instructions)
- [What Gets Installed](#what-gets-installed)
- [Installation Locations](#installation-locations)
- [Post-Installation Steps](#post-installation-steps)
- [Tool Usage Examples](#tool-usage-examples)
- [Troubleshooting](#troubleshooting)
- [Complete Tool List](#complete-tool-list)
- [Updating Tools](#updating-tools)
- [Uninstallation](#uninstallation)
- [Security Considerations](#security-considerations)
- [FAQ](#faq)

---

## 🎯 Overview

Automated Bash script that installs 50+ security tools on Linux systems that are **NOT** pre-installed in Kali Linux by default.

### Key Difference from Kali Linux

**This script complements Kali Linux** by installing modern tools that aren't in Kali's default repositories:
- ✅ **ProjectDiscovery Suite**: Nuclei, Subfinder, Httpx, Katana (not in Kali)
- ✅ **Modern Go Tools**: Latest versions of fuzzing, scanning, and enumeration tools
- ✅ **Android Tools**: ADB, JADX, APKTool, MobSF (some not in Kali)
- ✅ **Cloud Security**: Prowler, ScoutSuite, Trivy (not in Kali)

**Kali Users**: You can run this script to add these additional tools to your Kali system!

### Features
- ✅ **Kali-Friendly**: Installs tools NOT in Kali's default repos
- ✅ **Go Security Tools**: 24 modern Go-based tools
- ✅ **Python Security Tools**: 9 specialized Python tools
- ✅ **Android Tools**: Complete Android security testing suite
- ✅ **Cloud Security**: AWS/Azure/GCP security auditing tools
- ✅ **Wordlists**: SecLists, PayloadsAllTheThings
- ✅ **Automatic PATH Configuration**: All tools accessible system-wide
- ✅ **Comprehensive Logging**: Track every installation step

---

## 💻 System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| **OS** | Ubuntu 20.04, Debian 11, Kali 2023.x | Ubuntu 22.04, Debian 12, Kali 2024.x |
| **Architecture** | x86_64 (64-bit) | x86_64 (64-bit) |
| **Kernel** | 5.4+ | 5.15+ |
| **RAM** | 4GB | 8GB |
| **Disk Space** | 10GB free | 20GB free |
| **Internet** | Stable connection | High-speed connection |
| **Privileges** | Non-root with sudo | Non-root with sudo |

### Supported Distributions

**Fully Tested** ✅:
- **Kali Linux** 2022.x, 2023.x, 2024.x (adds tools not in default install)
- Ubuntu 20.04 LTS, 22.04 LTS, 23.04, 24.04 LTS
- Debian 11 (Bullseye), 12 (Bookworm)
- Fedora 35, 36, 37, 38, 39
- RHEL 8, 9
- CentOS Stream 8, 9

**Community Tested** ⚠️:
- Arch Linux
- Manjaro Linux
- Pop!_OS
- Linux Mint
- Parrot Security OS

---

## ✅ Pre-Installation Checklist

### 1. System Preparation
- [ ] **Check disk space** - Need at least 10GB free
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

# Check if package manager is locked (Debian/Ubuntu)
sudo fuser /var/lib/dpkg/lock-frontend 2>/dev/null && echo "⚠ Package manager BUSY" || echo "✓ Package manager available"
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

# Clear temporary files
sudo rm -rf /tmp/*
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
Save `ArcReactor.sh` to your home directory:

```bash
# If downloaded to ~/Downloads
cd ~/Downloads

# Or download directly (if hosted)
# wget https://your-url/ArcReactor.sh
```

#### Step 2: Make Script Executable
```bash
chmod +x ArcReactor.sh
```

#### Step 3: Verify Script Integrity (Optional but Recommended)
```bash
# View script contents to ensure it's safe
less ArcReactor.sh

# Check first 50 lines
head -50 ArcReactor.sh

# Search for suspicious commands
grep -E "rm -rf|format|mkfs|dd if=" ArcReactor.sh
```

#### Step 4: Run Installation
```bash
# Run as regular user (NOT with sudo)
./ArcReactor.sh
```

**Important Notes**:
- ⚠️ **Do NOT run with `sudo`** - Script will request sudo when needed
- ⏱️ Installation takes 30-60 minutes depending on internet speed
- 📝 Watch for any errors in colored output (red text)
- ✅ Green checkmarks indicate successful installations
- ❌ Red X marks indicate failed installations
- ☕ Grab coffee - this will take a while!

---

### Method 2: Quick One-Liner

```bash
chmod +x ArcReactor.sh && ./ArcReactor.sh
```

---

### Method 3: Download and Run

```bash
# Using wget
wget https://your-url/ArcReactor.sh
chmod +x ArcReactor.sh
./ArcReactor.sh

# Or using curl
curl -O https://your-url/ArcReactor.sh
chmod +x ArcReactor.sh
./ArcReactor.sh
```

---

## 📦 What Gets Installed

### Installation Timeline

```
Phase 1: System Dependencies        [▓▓▓▓░░░░░░] 5-10 min
Phase 2: Go Security Tools          [▓▓▓▓▓▓░░░░] 10-15 min
Phase 3: Python Security Tools      [▓▓▓░░░░░░░] 3-5 min
Phase 4: Android SDK & ADB          [▓▓▓░░░░░░░] 3-5 min
Phase 5: Android RE Tools           [▓▓▓░░░░░░░] 3-5 min
Phase 6: Cloud Security Tools       [▓▓░░░░░░░░] 2-3 min
Phase 7: Wordlists                  [▓▓░░░░░░░░] 2-5 min
Phase 8: Updates & Configuration    [▓░░░░░░░░░] 1-2 min
                                    ─────────────────────
                          Total Time: 30-60 minutes
```

### What's Already in Kali Linux (Not Installed)

**These tools are SKIPPED because they're in Kali Linux by default**:
```
❌ nmap, masscan          (port scanners)
❌ sqlmap, nikto          (web vulnerability scanners)
❌ burpsuite, zaproxy     (web application proxies)
❌ metasploit-framework   (exploitation framework)
❌ john, hashcat, hydra   (password cracking)
❌ wireshark, tcpdump     (network packet analysis)
❌ radare2, gdb           (reverse engineering)
❌ dirb, wfuzz            (directory fuzzing)
❌ wpscan                 (WordPress scanner)
❌ enum4linux            (SMB enumeration)
```

### What DOES Get Installed (NOT in Kali by default)

#### Phase 1: System Dependencies (5-10 minutes)
```
Installing Base Development Tools:
  ✓ build-essential     - GCC, G++, make, libc6-dev
  ✓ git                 - Version control
  ✓ curl, wget          - Download utilities
  ✓ unzip               - Archive extraction
  ✓ jq                  - JSON processor

Installing Programming Languages:
  ✓ Python 3.x          - Latest Python (if not already latest)
  ✓ python3-pip         - Python package manager
  ✓ python3-venv        - Virtual environments
  ✓ Go 1.21+            - Latest Go compiler
  ✓ Node.js 16+         - JavaScript runtime
  ✓ npm                 - Node package manager
  ✓ Ruby 3.x            - Ruby interpreter
  ✓ ruby-dev            - Ruby development headers

Installing Development Libraries:
  ✓ libssl-dev          - OpenSSL development files
  ✓ libffi-dev          - Foreign Function Interface
  ✓ libxml2-dev         - XML parsing library
  ✓ libxslt1-dev        - XSLT processing library
  ✓ zlib1g-dev          - Compression library

Installing Container Platform:
  ✓ docker.io           - Docker container engine
```

#### Phase 2: Go Security Tools (10-15 minutes)

**ProjectDiscovery Suite** (NOT in Kali - 8 tools):
```
  ✓ nuclei              - Vulnerability scanner with 3000+ templates
                          Usage: nuclei -u https://example.com
  
  ✓ subfinder           - Fast subdomain discovery tool
                          Usage: subfinder -d example.com
  
  ✓ httpx               - HTTP toolkit and multi-purpose probing
                          Usage: cat domains.txt | httpx
  
  ✓ katana              - Next-gen crawling framework
                          Usage: katana -u https://example.com
  
  ✓ naabu               - Fast port scanner (complement to nmap)
                          Usage: naabu -host example.com
  
  ✓ dnsx                - Fast DNS toolkit
                          Usage: dnsx -l domains.txt
  
  ✓ interactsh-client   - OOB interaction testing
                          Usage: interactsh-client
  
  ✓ notify              - Multi-channel notification system
                          Usage: nuclei ... | notify
```

**Fuzzing Tools** (NOT in Kali - 2 tools):
```
  ✓ ffuf                - Fast web fuzzer in Go
                          Usage: ffuf -u https://example.com/FUZZ -w wordlist.txt
  
  ✓ gobuster            - Directory/DNS/vhost brute-forcer
                          Usage: gobuster dir -u https://example.com -w wordlist.txt
```

**Subdomain Enumeration** (NOT in Kali - 2 tools):
```
  ✓ amass               - OWASP subdomain enumeration
                          Usage: amass enum -d example.com
  
  ✓ assetfinder         - Find related domains and subdomains
                          Usage: assetfinder example.com
```

**URL Discovery** (NOT in Kali - 4 tools):
```
  ✓ gau                 - Get All URLs from multiple sources
                          Usage: echo example.com | gau
  
  ✓ waybackurls         - Fetch URLs from Wayback Machine
                          Usage: echo example.com | waybackurls
  
  ✓ hakrawler           - Simple, fast web crawler
                          Usage: echo https://example.com | hakrawler
  
  ✓ gospider            - Fast web spider
                          Usage: gospider -s https://example.com
```

**Utility Tools** (NOT in Kali - 4 tools):
```
  ✓ gf                  - Wrapper around grep for patterns
                          Usage: cat urls.txt | gf xss
  
  ✓ anew                - Append new lines to files (deduplication)
                          Usage: cat new.txt | anew existing.txt
  
  ✓ unfurl              - Pull out bits of URLs
                          Usage: cat urls.txt | unfurl domains
  
  ✓ qsreplace           - Replace query string values
                          Usage: cat urls.txt | qsreplace FUZZ
```

**XSS & Injection Tools** (NOT in Kali - 3 tools):
```
  ✓ dalfox              - Parameter analysis and XSS scanning
                          Usage: dalfox url https://example.com?q=test
  
  ✓ kxss                - Find XSS parameters
                          Usage: cat urls.txt | kxss
  
  ✓ crlfuzz             - CRLF injection scanner
                          Usage: crlfuzz -l urls.txt
```

**Secret Scanning** (NOT in Kali - 2 tools):
```
  ✓ gitleaks            - Detect secrets in git repositories
                          Usage: gitleaks detect --source .
  
  ✓ trufflehog          - Find credentials in code
                          Usage: trufflehog git https://github.com/user/repo
```

#### Phase 3: Python Security Tools (3-5 minutes)

**Web Application Testing** (3 tools):
```
  ✓ arjun               - HTTP parameter discovery
                          Usage: arjun -u https://example.com/api
  
  ✓ xsstrike            - Advanced XSS detection suite
                          Usage: xsstrike -u "https://example.com?q=test"
  
  ✓ sublist3r           - Fast subdomain enumeration
                          Usage: sublist3r -d example.com
```

**Browser Automation** (1 tool):
```
  ✓ playwright          - Browser automation framework
                          Usage: python -m playwright codegen
  
  ✓ playwright browsers - Chromium for testing
```

**API Clients** (3 tools):
```
  ✓ shodan              - Shodan search engine API
                          Usage: shodan search apache
  
  ✓ censys              - Censys certificate/host search
                          Usage: censys search "example.com"
  
  ✓ securitytrails      - SecurityTrails DNS intelligence
```

**Cloud Security** (2 tools):
```
  ✓ prowler             - AWS security best practices auditing
                          Usage: prowler aws
  
  ✓ scoutsuite          - Multi-cloud security auditing
                          Usage: scout aws
```

#### Phase 4: Android SDK & ADB (3-5 minutes)

**Android Platform Tools** (NOT in Kali by default):
```
  ✓ adb                 - Android Debug Bridge
                          Usage: adb devices
  
  ✓ fastboot            - Android fastboot utility
                          Usage: fastboot devices
```

**Android Studio** (OPTIONAL - user prompt):
```
  ? Android Studio      - Official Android IDE (1GB+ download)
                          Prompt: "Install Android Studio? (y/N)"
```

**Screen Mirroring**:
```
  ✓ scrcpy              - Display and control Android devices
                          Usage: scrcpy
```

#### Phase 5: Android Reverse Engineering Tools (3-5 minutes)

**APK Decompilation** (NOT in Kali - 2 tools):
```
  ✓ JADX                - Dex to Java decompiler
                          Location: ~/security-tools/jadx/
                          Usage: jadx app.apk -d output_folder
  
  ✓ APKTool             - APK reverse engineering tool
                          Location: ~/security-tools/apktool/
                          Usage: apktool d app.apk -o app_source
```

**Mobile Security Framework**:
```
  ✓ MobSF (Docker)      - Mobile app security testing framework
                          Usage: docker run -p 8000:8000 mobsf
                          Access: http://localhost:8000
```

#### Phase 6: Cloud Security Tools (2-3 minutes)

**Container Security** (NOT in Kali):
```
  ✓ Trivy               - Comprehensive container vulnerability scanner
                          Usage: trivy image nginx:latest
```

**Note**: Prowler and ScoutSuite already installed in Phase 3 (Python tools)

#### Phase 7: Wordlists (2-5 minutes)

**Comprehensive Wordlists**:
```
  ✓ SecLists            - 40,000+ security testing lists
                          Location: ~/security-tools/wordlists/SecLists/
                          Categories:
                            - Discovery/Web-Content/
                            - Discovery/DNS/
                            - Passwords/
                            - Usernames/
                            - Fuzzing/
                            - Payloads/
  
  ✓ PayloadsAllTheThings - Exploit payload collection
                          Location: ~/security-tools/wordlists/PayloadsAllTheThings/
                          Categories:
                            - XSS Injection/
                            - SQL Injection/
                            - Command Injection/
                            - File Upload/
                            - XXE Injection/
                            - SSRF/
```

#### Phase 8: Configuration & Updates (1-2 minutes)

**Nuclei Templates**:
```
  ✓ Nuclei Templates    - 3000+ vulnerability detection templates
                          Location: ~/nuclei-templates/
                          Auto-update: nuclei -update-templates
```

**PATH Configuration**:
```
  ✓ Go bin directory    - ~/go/bin added to PATH
  ✓ Local bin           - ~/.local/bin added to PATH
  ✓ Security tools      - Tool symlinks created
```

**Directory Structure**:
```
  ✓ ~/security-tools/   - Main installation directory
  ✓ ~/bug-bounty/       - Organized workspace structure
```

---

## 📁 Installation Locations

### Main Installation Directory
```
~/security-tools/
│
├── platform-tools/              # Android SDK Platform Tools
│   ├── adb                      # Android Debug Bridge binary
│   ├── fastboot                 # Fastboot utility
│   ├── dmtracedump
│   ├── etc1tool
│   ├── hprof-conv
│   ├── lib/
│   ├── make_f2fs
│   └── mke2fs
│
├── jadx/                        # JADX APK Decompiler
│   ├── bin/
│   │   ├── jadx                 # Command-line decompiler
│   │   └── jadx-gui             # GUI version
│   ├── lib/
│   └── jadx-*.jar
│
├── apktool/                     # APKTool
│   ├── apktool.jar              # Main JAR file
│   └── apktool                  # Launch script
│
├── wordlists/                   # Security Wordlists
│   ├── SecLists/
│   │   ├── Discovery/
│   │   │   ├── Web-Content/
│   │   │   │   ├── directory-list-2.3-medium.txt
│   │   │   │   ├── common.txt
│   │   │   │   ├── big.txt
│   │   │   │   └── raft-large-files.txt
│   │   │   ├── DNS/
│   │   │   │   ├── subdomains-top1million-110000.txt
│   │   │   │   └── dns-Jhaddix.txt
│   │   │   └── Infrastructure/
│   │   ├── Fuzzing/
│   │   │   ├── XSS/
│   │   │   ├── SQLi/
│   │   │   └── command-injection-commix.txt
│   │   ├── Passwords/
│   │   │   ├── Common-Credentials/
│   │   │   ├── Leaked-Databases/
│   │   │   └── rockyou.txt
│   │   ├── Usernames/
│   │   └── Payloads/
│   │
│   └── PayloadsAllTheThings/
│       ├── XSS Injection/
│       ├── SQL Injection/
│       ├── Command Injection/
│       ├── File Upload/
│       ├── XXE Injection/
│       ├── SSRF/
│       ├── SSTI/
│       └── Deserialization/
│
├── tools/                       # Additional tools
├── scripts/                     # Custom scripts
├── results/                     # Scan results
└── configs/                     # Configuration files
```

### Go Tools Location
```
~/go/
│
├── bin/                         # Go binaries (added to PATH)
│   ├── nuclei                   # Vulnerability scanner
│   ├── subfinder                # Subdomain enumeration
│   ├── httpx                    # HTTP probing
│   ├── katana                   # Web crawler
│   ├── naabu                    # Port scanner
│   ├── dnsx                     # DNS toolkit
│   ├── interactsh-client        # OOB interaction
│   ├── notify                   # Notifications
│   ├── ffuf                     # Web fuzzer
│   ├── gobuster                 # Directory brute-force
│   ├── amass                    # Subdomain enumeration
│   ├── assetfinder              # Asset discovery
│   ├── gau                      # Get All URLs
│   ├── waybackurls              # Wayback Machine URLs
│   ├── hakrawler                # Web crawler
│   ├── gospider                 # Web spider
│   ├── gf                       # Pattern matching
│   ├── anew                     # Unique line appender
│   ├── unfurl                   # URL parser
│   ├── qsreplace                # Query string replacer
│   ├── dalfox                   # XSS scanner
│   ├── kxss                     # XSS parameter finder
│   ├── crlfuzz                  # CRLF scanner
│   ├── gitleaks                 # Secret scanner
│   └── trufflehog               # Credential finder
│
├── pkg/                         # Go packages (cache)
└── src/                         # Go source (if needed)
```

### Python Packages Location
```
~/.local/lib/python3.x/site-packages/

Installed packages:
  - arjun
  - xsstrike
  - sublist3r
  - playwright
  - shodan
  - censys
  - securitytrails
  - prowler
  - scoutsuite
```

### System Binaries (symlinks)
```
/usr/local/bin/
├── adb -> ~/security-tools/platform-tools/adb
├── fastboot -> ~/security-tools/platform-tools/fastboot
├── jadx -> ~/security-tools/jadx/bin/jadx
└── apktool -> ~/security-tools/apktool/apktool

OR (if sudo not available):

~/go/bin/
├── adb -> ~/security-tools/platform-tools/adb
├── fastboot -> ~/security-tools/platform-tools/fastboot
├── jadx -> ~/security-tools/jadx/bin/jadx
└── apktool -> ~/security-tools/apktool/apktool
```

### Nuclei Templates
```
~/nuclei-templates/
│
├── cves/                        # CVE-based templates (2000+)
│   ├── 2024/
│   ├── 2023/
│   └── [other years]/
│
├── vulnerabilities/             # Generic vulnerabilities
├── exposed-panels/              # Exposed admin panels
├── exposed-tokens/              # API keys, tokens
├── misconfigurations/           # Configuration issues
├── takeovers/                   # Subdomain takeovers
├── default-logins/              # Default credentials
├── workflows/                   # Multi-step workflows
└── technologies/                # Technology detection
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
│   ├── nuclei/                  # Nuclei scan outputs
│   └── custom/                  # Custom scan results
│
├── exploitation/                # Exploitation phase
│   ├── poc/                     # Proof of concepts
│   └── payloads/                # Custom payloads
│
└── reporting/                   # Reports and documentation
    ├── submissions/             # Bug bounty submissions
    └── screenshots/             # Evidence screenshots
```

### Log Files
```
~/security-tools-install.log     # Installation log

Example content:
[2024-01-15 14:32:10] Installation started (Non-Kali systems)
[2024-01-15 14:32:10] OS: ubuntu
[2024-01-15 14:32:15] SUCCESS: System packages updated
[2024-01-15 14:35:22] SUCCESS: nuclei installed
[2024-01-15 14:36:18] SUCCESS: subfinder installed
[2024-01-15 14:37:45] SUCCESS: httpx installed
...
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
gobuster version
amass -version

# Test Python tools
python3 -c "import arjun; print('Arjun: OK')"
python3 -m pip show playwright | grep Version

# Test Android tools
adb version
fastboot --version
jadx --version

# Test PATH configuration
echo $PATH | grep -o "$HOME/go/bin"
echo $PATH | grep -o "$HOME/.local/bin"

# Verify tool locations
which nuclei subfinder httpx ffuf adb jadx
```

**Expected Output**:
```
✓ nuclei: Nuclei - Open-source project (github.com/projectdiscovery/nuclei)
✓ subfinder: Subfinder v2.x.x
✓ httpx: httpx v1.x.x
✓ ffuf: ffuf version v2.x.x
✓ adb: Android Debug Bridge version 1.0.41
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

# Test Nuclei
echo "https://example.com" | nuclei -tags cve
```

---

### Step 4: Connect Android Device via ADB

**Enable Developer Options on Android**:
1. Settings → About Phone
2. Tap "Build Number" 7 times
3. You'll see: "You are now a developer!"

**Enable USB Debugging**:
1. Settings → Developer Options
2. Enable "USB Debugging"
3. Enable "Install via USB" (optional)

**Connect Device**:
```bash
# Connect phone via USB cable
adb devices

# If device shows "unauthorized":
# - Check phone screen for authorization prompt
# - Tap "Allow" and check "Always allow from this computer"

# Verify connection
adb devices
# Expected: List of devices attached
#           ABC123XYZ    device

# Test connection
adb shell "echo 'ADB Works!'"
```

**Wireless ADB** (Android 11+):
```bash
# Connect via USB first
adb devices

# Enable TCP/IP on port 5555
adb tcpip 5555

# Find device IP
# Phone: Settings → About Phone → Status → IP Address
# Example: 192.168.1.50

# Connect wirelessly
adb connect 192.168.1.50:5555

# Disconnect USB - should stay connected

# Verify
adb devices
# Expected: 192.168.1.50:5555    device
```

---

### Step 5: Test Docker and MobSF

**Start Docker Service**:
```bash
# Start Docker
sudo systemctl start docker

# Enable Docker on boot
sudo systemctl enable docker

# Add user to docker group (no sudo needed)
sudo usermod -aG docker $USER

# Apply group changes (logout/login or run):
newgrp docker

# Verify Docker
docker --version
docker ps
```

**Run MobSF**:
```bash
# Pull MobSF image (~2GB download)
docker pull opensecurity/mobile-security-framework-mobsf

# Run MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access MobSF
# Open browser: http://localhost:8000

# Upload APK and analyze
```

**MobSF Usage**:
1. Drag & drop APK file
2. Wait for analysis (1-5 minutes)
3. Review results:
   - Security Score
   - Permissions Analysis
   - Code Analysis
   - Binary Analysis
   - Malware Detection

---

### Step 6: Configure Shell Aliases

Create useful aliases for common workflows:

```bash
# Add to ~/.bashrc or ~/.zshrc
cat >> ~/.bashrc << 'EOF'

# ==========================================
# Security Tools Aliases
# ==========================================

# Nuclei
alias nuclei-update='nuclei -update-templates'
alias nuclei-scan='nuclei -l targets.txt -o results.txt'
alias nuclei-cve='nuclei -tags cve -severity critical,high'

# Subfinder
alias subfinder-all='subfinder -all -recursive'
alias subfinder-silent='subfinder -silent'

# Httpx
alias httpx-probe='httpx -silent -status-code -title -tech-detect'
alias httpx-full='httpx -status-code -title -tech-detect -web-server -method -ip'

# FFUF
alias ffuf-dir='ffuf -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u'
alias ffuf-dns='ffuf -w ~/security-tools/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u'

# Common Workflows
alias recon-basic='subfinder -d $1 | httpx -silent | nuclei -silent'
alias recon-full='subfinder -d $1 -all | httpx | nuclei -t ~/nuclei-templates/ -severity high,critical'
alias recon-subs='subfinder -d $1 -all | dnsx -silent | httpx -silent'

# ADB Shortcuts
alias adb-devices='adb devices'
alias adb-install='adb install'
alias adb-uninstall='adb uninstall'
alias adb-logcat='adb logcat'
alias adb-shell='adb shell'
alias adb-screenshot='adb shell screencap -p'
alias adb-record='adb shell screenrecord'

# Android Analysis
alias jadx-decompile='jadx -d output'
alias apktool-decode='apktool d'
alias apktool-build='apktool b'

# MobSF
alias mobsf-start='docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf'
alias mobsf-bg='docker run -d -p 8000:8000 opensecurity/mobile-security-framework-mobsf'

# Cloud Security
alias prowler-aws='prowler aws'
alias scout-aws='scout aws'
alias trivy-scan='trivy image'

# Wordlists
alias wordlists='cd ~/security-tools/wordlists'
alias seclists='cd ~/security-tools/wordlists/SecLists'
alias payloads='cd ~/security-tools/wordlists/PayloadsAllTheThings'

# Bug Bounty
alias bb='cd ~/bug-bounty'
alias bb-recon='cd ~/bug-bounty/recon'
alias bb-scan='cd ~/bug-bounty/scanning'

EOF

# Reload shell
source ~/.bashrc
```

---

### Step 7: Create Recon Automation Script

Create a basic reconnaissance automation script:

```bash
# Create recon script
cat > ~/security-tools/scripts/recon.sh << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check arguments
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <domain>${NC}"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR=~/bug-bounty/recon/$DOMAIN
mkdir -p $OUTPUT_DIR/{subdomains,urls,ports,vulnerabilities}

echo -e "${BLUE}[+] Starting reconnaissance for $DOMAIN${NC}"

# Subdomain Enumeration
echo -e "${YELLOW}[*] Phase 1: Subdomain Enumeration${NC}"
subfinder -d $DOMAIN -all -silent -o $OUTPUT_DIR/subdomains/subfinder.txt
assetfinder --subs-only $DOMAIN | tee $OUTPUT_DIR/subdomains/assetfinder.txt
amass enum -passive -d $DOMAIN -o $OUTPUT_DIR/subdomains/amass.txt

# Combine and deduplicate
cat $OUTPUT_DIR/subdomains/*.txt | sort -u > $OUTPUT_DIR/subdomains/all.txt
echo -e "${GREEN}[✓] Found $(wc -l < $OUTPUT_DIR/subdomains/all.txt) subdomains${NC}"

# DNS Resolution
echo -e "${YELLOW}[*] Phase 2: DNS Resolution${NC}"
cat $OUTPUT_DIR/subdomains/all.txt | dnsx -silent -o $OUTPUT_DIR/subdomains/resolved.txt
echo -e "${GREEN}[✓] Resolved $(wc -l < $OUTPUT_DIR/subdomains/resolved.txt) subdomains${NC}"

# HTTP Probing
echo -e "${YELLOW}[*] Phase 3: HTTP Probing${NC}"
cat $OUTPUT_DIR/subdomains/resolved.txt | httpx -silent -o $OUTPUT_DIR/urls/alive.txt
echo -e "${GREEN}[✓] Found $(wc -l < $OUTPUT_DIR/urls/alive.txt) alive hosts${NC}"

# URL Discovery
echo -e "${YELLOW}[*] Phase 4: URL Discovery${NC}"
cat $OUTPUT_DIR/urls/alive.txt | waybackurls | tee $OUTPUT_DIR/urls/wayback.txt
cat $OUTPUT_DIR/urls/alive.txt | gau | tee $OUTPUT_DIR/urls/gau.txt
cat $OUTPUT_DIR/urls/wayback.txt $OUTPUT_DIR/urls/gau.txt | sort -u > $OUTPUT_DIR/urls/all.txt
echo -e "${GREEN}[✓] Discovered $(wc -l < $OUTPUT_DIR/urls/all.txt) URLs${NC}"

# Port Scanning
echo -e "${YELLOW}[*] Phase 5: Port Scanning${NC}"
naabu -list $OUTPUT_DIR/subdomains/resolved.txt -silent -o $OUTPUT_DIR/ports/naabu.txt
echo -e "${GREEN}[✓] Port scan complete${NC}"

# Vulnerability Scanning
echo -e "${YELLOW}[*] Phase 6: Vulnerability Scanning${NC}"
nuclei -l $OUTPUT_DIR/urls/alive.txt -severity high,critical -o $OUTPUT_DIR/vulnerabilities/nuclei.txt
echo -e "${GREEN}[✓] Vulnerability scan complete${NC}"

# Summary
echo ""
echo -e "${BLUE}==================== SUMMARY ====================${NC}"
echo -e "${GREEN}Subdomains:${NC} $(wc -l < $OUTPUT_DIR/subdomains/all.txt)"
echo -e "${GREEN}Resolved:${NC} $(wc -l < $OUTPUT_DIR/subdomains/resolved.txt)"
echo -e "${GREEN}Alive Hosts:${NC} $(wc -l < $OUTPUT_DIR/urls/alive.txt)"
echo -e "${GREEN}URLs:${NC} $(wc -l < $OUTPUT_DIR/urls/all.txt)"
echo -e "${GREEN}Vulnerabilities:${NC} $(wc -l < $OUTPUT_DIR/vulnerabilities/nuclei.txt)"
echo -e "${BLUE}Results saved to: $OUTPUT_DIR${NC}"
EOF

# Make executable
chmod +x ~/security-tools/scripts/recon.sh

# Create symlink
sudo ln -sf ~/security-tools/scripts/recon.sh /usr/local/bin/recon 2>/dev/null || \
    ln -sf ~/security-tools/scripts/recon.sh ~/go/bin/recon
```

**Usage**:
```bash
# Run reconnaissance
recon example.com

# Or
~/security-tools/scripts/recon.sh example.com
```

---

### Step 8: Install GF Patterns (Optional but Recommended)

GF patterns help find specific vulnerability patterns in URLs:

```bash
# Clone GF patterns
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

# Also clone tomnomnom's patterns
git clone https://github.com/tomnomnom/gf ~/.gf-tomnomnom

# Copy patterns
cp -r ~/.gf-tomnomnom/*.json ~/.gf/

# Test GF
echo "https://example.com/search?q=test&id=123" | gf xss
```

**Available Patterns**:
- xss - XSS parameters
- sqli - SQL injection points
- ssrf - SSRF vulnerabilities
- redirect - Open redirects
- rce - Remote code execution
- lfi - Local file inclusion

---

## 🎓 Tool Usage Examples

### Subdomain Enumeration

**Basic Subdomain Discovery**:
```bash
# Using Subfinder (fast, multiple sources)
subfinder -d example.com -o subdomains.txt

# Using Subfinder with all sources
subfinder -d example.com -all -recursive -o subdomains_all.txt

# Using Amass (comprehensive, slower)
amass enum -d example.com -o amass_results.txt

# Using Amass passive mode (faster)
amass enum -passive -d example.com -o amass_passive.txt

# Using Assetfinder
assetfinder --subs-only example.com | tee assetfinder_results.txt
```

**Combined Enumeration**:
```bash
# Combine multiple tools
subfinder -d example.com -silent | \
assetfinder --subs-only example.com | \
amass enum -passive -d example.com | \
sort -u | tee all_subdomains.txt

# Or using anew for deduplication
subfinder -d example.com -silent | anew subdomains.txt
assetfinder --subs-only example.com | anew subdomains.txt
amass enum -passive -d example.com | anew subdomains.txt
```

**DNS Resolution**:
```bash
# Resolve subdomains to IPs
cat subdomains.txt | dnsx -silent -o resolved.txt

# Resolve with response codes
cat subdomains.txt | dnsx -resp -o resolved_with_codes.txt

# Find wildcards
cat subdomains.txt | dnsx -wildcard-domain example.com
```

---

### Web Reconnaissance

**HTTP Probing**:
```bash
# Basic probing
cat subdomains.txt | httpx -silent -o alive.txt

# Detailed probing
cat subdomains.txt | httpx -status-code -title -tech-detect -o alive_detailed.txt

# Full information
cat subdomains.txt | httpx \
  -status-code \
  -title \
  -tech-detect \
  -web-server \
  -method \
  -ip \
  -cname \
  -cdn \
  -o full_info.txt

# Probe specific ports
cat subdomains.txt | httpx -ports 80,443,8080,8443 -o custom_ports.txt
```

**Web Crawling**:
```bash
# Crawl with Katana
katana -u https://example.com -o urls.txt

# Crawl with depth limit
katana -u https://example.com -depth 3 -o urls_depth3.txt

# Crawl JavaScript files
katana -u https://example.com -js-crawl -o js_urls.txt

# Crawl with Gospider
gospider -s https://example.com -o gospider_output

# Crawl with Hakrawler
echo "https://example.com" | hakrawler -depth 2 -o hakrawler_urls.txt
```

**URL Discovery from Archives**:
```bash
# Wayback Machine
echo "example.com" | waybackurls > wayback_urls.txt

# Get All URLs (GAU) - multiple sources
echo "example.com" | gau --threads 5 --o gau_urls.txt

# Combine all sources
cat wayback_urls.txt gau_urls.txt katana_urls.txt | \
  sort -u | \
  tee all_urls.txt
```

---

### Directory and File Fuzzing

**FFUF - Fast Fuzzing**:
```bash
# Directory fuzzing
ffuf -u https://example.com/FUZZ \
  -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -mc 200,301,302,403 \
  -o ffuf_dirs.json

# File fuzzing with extensions
ffuf -u https://example.com/FUZZ \
  -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -e .php,.html,.txt,.bak,.zip \
  -mc 200 \
  -o ffuf_files.json

# VHost fuzzing
ffuf -u https://example.com \
  -H "Host: FUZZ.example.com" \
  -w ~/security-tools/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200 \
  -o vhosts.json

# Parameter fuzzing
ffuf -u https://example.com/api?FUZZ=test \
  -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -o parameters.json
```

**Gobuster - Directory Brute-forcing**:
```bash
# Directory enumeration
gobuster dir \
  -u https://example.com \
  -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -o gobuster_dirs.txt

# With extensions
gobuster dir \
  -u https://example.com \
  -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/common.txt \
  -x php,html,txt,bak \
  -o gobuster_files.txt

# DNS enumeration
gobuster dns \
  -d example.com \
  -w ~/security-tools/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o gobuster_dns.txt

# VHost enumeration
gobuster vhost \
  -u https://example.com \
  -w ~/security-tools/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o gobuster_vhosts.txt
```

---

### Vulnerability Scanning

**Nuclei - Template-Based Scanning**:
```bash
# Basic scan
nuclei -u https://example.com -o nuclei_results.txt

# Scan multiple targets
nuclei -l targets.txt -o nuclei_scan.txt

# Scan with specific severity
nuclei -l targets.txt -severity critical,high -o nuclei_critical.txt

# Scan specific vulnerability types
nuclei -l targets.txt -tags cve,xss,sqli -o nuclei_tagged.txt

# Scan with specific templates
nuclei -l targets.txt -t ~/nuclei-templates/cves/ -o nuclei_cves.txt

# Scan with rate limiting
nuclei -l targets.txt -rate-limit 50 -o nuclei_ratelimited.txt

# Scan and get notifications
nuclei -l targets.txt -severity critical -notify

# Scan with custom headers
nuclei -u https://example.com -H "Authorization: Bearer token123" -o results.txt
```

**XSS Scanning**:
```bash
# Find XSS parameters with Kxss
cat urls.txt | kxss -o xss_params.txt

# Scan for XSS with Dalfox
cat urls.txt | dalfox pipe -o xss_vulnerabilities.txt

# Dalfox on single URL
dalfox url "https://example.com/search?q=test" -o dalfox_results.txt

# Dalfox with custom payloads
dalfox url "https://example.com/search?q=FUZZ" \
  --custom-payload "<script>alert(1)</script>" \
  -o dalfox_custom.txt

# XSStrike (Python)
xsstrike -u "https://example.com/search?q=test"

# XSStrike with crawling
xsstrike -u "https://example.com" --crawl -l 2
```

**CRLF Injection**:
```bash
# Scan for CRLF injection
crlfuzz -l urls.txt -o crlf_results.txt

# Scan with custom payloads
crlfuzz -l urls.txt -o crlf_custom.txt
```

**Parameter Discovery**:
```bash
# Discover parameters with Arjun
arjun -u https://example.com/api/user -o arjun_params.json

# Arjun on multiple URLs
arjun -i urls.txt -o arjun_all_params.json

# Arjun with custom wordlist
arjun -u https://example.com/api \
  -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
```

---

### Android Application Testing

**ADB Commands**:
```bash
# List devices
adb devices

# Install APK
adb install app.apk

# Install and replace
adb install -r app.apk

# Uninstall app
adb uninstall com.example.app

# List installed packages
adb shell pm list packages

# Find package name
adb shell pm list packages | grep -i keyword

# Get app info
adb shell dumpsys package com.example.app

# Start app
adb shell am start -n com.example.app/.MainActivity

# Force stop app
adb shell am force-stop com.example.app

# Clear app data
adb shell pm clear com.example.app
```

**APK Analysis**:
```bash
# Decompile with JADX (command-line)
jadx app.apk -d output_folder

# Decompile with JADX-GUI
jadx-gui app.apk

# Reverse engineer with APKTool
apktool d app.apk -o app_source

# Rebuild APK
apktool b app_source -o modified.apk

# Sign APK (requires Java keytool)
keytool -genkey -v -keystore my-key.keystore -alias my-alias -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key.keystore modified.apk my-alias
```

**Dynamic Analysis**:
```bash
# View logcat
adb logcat

# Filter logcat by app
adb logcat | grep -i "com.example.app"

# Filter by tag
adb logcat -s TAG_NAME

# Clear logcat
adb logcat -c

# Save logcat to file
adb logcat > logcat.txt

# Pull file from device
adb pull /sdcard/file.txt ./

# Push file to device
adb push file.txt /sdcard/

# Pull APK from device
adb shell pm path com.example.app
# Output: package:/data/app/com.example.app-randomstring/base.apk
adb pull /data/app/com.example.app-randomstring/base.apk ./app.apk

# Take screenshot
adb shell screencap /sdcard/screenshot.png
adb pull /sdcard/screenshot.png ./

# Record screen
adb shell screenrecord /sdcard/recording.mp4
# Stop with Ctrl+C
adb pull /sdcard/recording.mp4 ./

# Get device info
adb shell getprop ro.build.version.release  # Android version
adb shell getprop ro.product.model           # Device model
adb shell getprop ro.product.manufacturer    # Manufacturer
```

**Screen Mirroring with scrcpy**:
```bash
# Basic mirroring
scrcpy

# Mirror with custom bitrate
scrcpy --bit-rate 2M

# Mirror and record
scrcpy --record screen_recording.mp4

# Mirror specific device (if multiple)
scrcpy --serial ABC123XYZ

# Mirror with custom resolution
scrcpy --max-size 1024

# Mirror in fullscreen
scrcpy --fullscreen

# Disable screensaver
scrcpy --stay-awake

# Turn off device screen
scrcpy --turn-screen-off
```

**MobSF Analysis**:
```bash
# Start MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access web interface
# Open browser: http://localhost:8000

# Upload APK through web interface
# Analysis includes:
#   - Static Analysis
#   - Manifest Analysis
#   - Code Analysis
#   - Binary Analysis
#   - Security Score
#   - Malware Detection
```

---

### Secret Scanning

**Gitleaks - Git Repository Secret Detection**:
```bash
# Scan current directory
gitleaks detect --source . --verbose

# Scan with report
gitleaks detect --source . --report-path leaks.json

# Scan specific repository
gitleaks detect --source /path/to/repo --verbose

# Scan remote repository
gitleaks detect --source https://github.com/user/repo

# Scan and create baseline
gitleaks detect --source . --baseline-path baseline.json

# Scan with custom config
gitleaks detect --source . --config-path custom-config.toml

# Scan specific commit range
gitleaks detect --source . --log-opts="--since='1 week ago'"
```

**TruffleHog - Credential Scanning**:
```bash
# Scan Git repository
trufflehog git https://github.com/user/repo

# Scan local repository
trufflehog filesystem /path/to/repo

# Scan with JSON output
trufflehog git https://github.com/user/repo --json > trufflehog_results.json

# Scan only recent commits
trufflehog git https://github.com/user/repo --since-commit abc123

# Scan Docker image
trufflehog docker --image nginx:latest

# Scan S3 bucket
trufflehog s3 --bucket my-bucket
```

---

### Cloud Security Auditing

**Prowler - AWS Security Assessment**:
```bash
# Full AWS assessment
prowler aws

# Scan specific service
prowler aws --services s3,ec2

# Scan specific regions
prowler aws --regions us-east-1,us-west-2

# Generate HTML report
prowler aws --output-formats html

# Scan with specific profile
prowler aws --profile my-aws-profile

# Scan for specific compliance
prowler aws --compliance cis_1.5_aws
```

**ScoutSuite - Multi-Cloud Auditing**:
```bash
# Scan AWS
scout aws

# Scan Azure
scout azure

# Scan GCP
scout gcp

# Scan with specific profile
scout aws --profile my-profile

# Generate report
scout aws --report-dir ./scout-report
```

**Trivy - Container Vulnerability Scanning**:
```bash
# Scan Docker image
trivy image nginx:latest

# Scan with severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# Scan filesystem
trivy fs /path/to/project

# Scan Kubernetes cluster
trivy k8s --report summary cluster

# Scan with JSON output
trivy image --format json nginx:latest > trivy_results.json

# Scan and ignore unfixed vulnerabilities
trivy image --ignore-unfixed nginx:latest
```

---

### URL Manipulation and Filtering

**Unfurl - URL Parsing**:
```bash
# Extract domains
cat urls.txt | unfurl domains

# Extract paths
cat urls.txt | unfurl paths

# Extract query parameters
cat urls.txt | unfurl keys

# Extract values
cat urls.txt | unfurl values

# Custom format
cat urls.txt | unfurl format "%s://%d%p"

# Get unique domains
cat urls.txt | unfurl domains | sort -u
```

**Qsreplace - Query String Replacement**:
```bash
# Replace all parameter values with "FUZZ"
cat urls.txt | qsreplace "FUZZ"

# Replace with XSS payload
cat urls.txt | qsreplace "<script>alert(1)</script>"

# Replace with SQL injection payload
cat urls.txt | qsreplace "' OR '1'='1"

# Pipe to fuzzer
cat urls.txt | qsreplace "FUZZ" | ffuf -w wordlist.txt -u STDIN
```

**GF - Pattern Matching**:
```bash
# Find XSS parameters
cat urls.txt | gf xss

# Find SQL injection points
cat urls.txt | gf sqli

# Find SSRF parameters
cat urls.txt | gf ssrf

# Find open redirects
cat urls.txt | gf redirect

# Find LFI parameters
cat urls.txt | gf lfi

# List all patterns
gf -list

# Custom pattern matching
cat urls.txt | gf custom-pattern
```

**Anew - Unique Line Appender**:
```bash
# Append unique lines to file
cat new_urls.txt | anew existing_urls.txt

# Find new entries
cat new_urls.txt | anew existing_urls.txt | wc -l

# Use in pipeline
subfinder -d example.com -silent | anew subdomains.txt
waybackurls example.com | anew urls.txt
```

---

## 🔧 Troubleshooting

### Issue 1: Script Exits Immediately

**Symptom**: Script exits with "This script is for NON-Kali systems"

**Cause**: Script detects Kali Linux

**Solution**: 
This script is designed to add tools NOT in Kali's default repos. If you're on Kali and want these additional tools, you can:

```bash
# Option 1: Comment out the Kali check
nano ArcReactor.sh

# Find and comment out these lines (add # at beginning):
# if grep -qi "kali" /etc/os-release 2>/dev/null; then
#     print_error "This script is for NON-Kali systems"
#     exit 1
# fi

# Then run script
./ArcReactor.sh
```

**Or use Kali's package manager for standard tools**:
```bash
sudo apt update
sudo apt install nmap sqlmap metasploit-framework burpsuite zaproxy
```

---

### Issue 2: Permission Denied Errors

**Symptom**: "Permission denied" when running script

**Solution**:
```bash
# Make script executable
chmod +x ArcReactor.sh

# Verify permissions
ls -l ArcReactor.sh
# Should show: -rwxr-xr-x

# Run script (NOT with sudo)
./ArcReactor.sh
```

---

### Issue 3: Go Tools Not Found

**Symptom**: `command not found: nuclei` after installation

**Solution**:
```bash
# Check if Go bin is in PATH
echo $PATH | grep "$HOME/go/bin"

# If not found, add to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Or for zsh
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc

# Verify
which nuclei subfinder httpx

# If still not found, check if tools are installed
ls -la ~/go/bin/

# Reinstall specific tool
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

### Issue 4: Python Tools Not Found

**Symptom**: `ModuleNotFoundError` or `command not found` for Python tools

**Solution**:
```bash
# Check Python installation
python3 --version
which python3

# Check pip
pip3 --version

# Check if tools are installed
python3 -m pip list | grep -i arjun

# Reinstall Python tools
python3 -m pip install --user arjun xsstrike sublist3r playwright

# Add local bin to PATH if needed
echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
which arjun
python3 -c "import arjun; print('OK')"
```

---

### Issue 5: ADB Device Not Found

**Symptom**: `adb devices` shows "no permissions" or device not listed

**Solution**:
```bash
# Check ADB installation
adb version

# Start ADB server as root
sudo adb kill-server
sudo adb start-server

# Or add udev rules (Ubuntu/Debian)
sudo wget -O /etc/udev/rules.d/51-android.rules https://raw.githubusercontent.com/M0Rf30/android-udev-rules/main/51-android.rules
sudo chmod a+r /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules

# Reconnect device
adb kill-server
adb start-server
adb devices

# Check on phone
# - Revoke USB debugging authorizations
# - Disable and re-enable USB debugging
# - Connect again and approve prompt
```

---

### Issue 6: Docker Permission Denied

**Symptom**: `permission denied while trying to connect to the Docker daemon socket`

**Solution**:
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Apply group changes
newgrp docker

# Or logout and login again

# Verify
docker ps

# If still issues, start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Check Docker status
sudo systemctl status docker
```

---

### Issue 7: Package Manager Locked

**Symptom**: `Could not get lock /var/lib/dpkg/lock-frontend`

**Solution**:
```bash
# Wait for other package managers to finish
# Or kill the process

# Check what's using it
sudo fuser /var/lib/dpkg/lock-frontend

# Kill the process (use PID from above)
sudo kill -9 PID

# Or remove locks (use carefully)
sudo rm /var/lib/dpkg/lock-frontend
sudo rm /var/lib/dpkg/lock
sudo dpkg --configure -a
sudo apt update
```

---

### Issue 8: Disk Space Issues

**Symptom**: "No space left on device" during installation

**Solution**:
```bash
# Check disk space
df -h /

# Free up space
sudo apt autoremove -y
sudo apt autoclean -y
sudo journalctl --vacuum-time=7d

# Remove old kernels (Ubuntu/Debian)
sudo apt autoremove --purge

# Clear Docker cache
docker system prune -a --volumes -f

# Clear package cache
sudo rm -rf /var/cache/apt/archives/*

# Check again
df -h /
```

---

### Issue 9: Nuclei Templates Not Updating

**Symptom**: `nuclei -update-templates` fails or shows error

**Solution**:
```bash
# Remove old templates
rm -rf ~/nuclei-templates

# Update Nuclei first
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Verify
nuclei -tl | wc -l
# Should show 3000+

# If still issues, clone manually
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
```

---

### Issue 10: Git Clone Failures

**Symptom**: `fatal: unable to access` or timeout errors

**Solution**:
```bash
# Check internet connection
ping -c 4 github.com

# Increase Git buffer
git config --global http.postBuffer 524288000

# Increase timeout
git config --global http.lowSpeedLimit 0
git config --global http.lowSpeedTime 999999

# Use shallow clone
git clone --depth 1 <repository-url>

# If behind proxy
git config --global http.proxy http://proxy.example.com:8080

# Remove proxy (if not needed)
git config --global --unset http.proxy
```

---

### Issue 11: Installation Hangs

**Symptom**: Script hangs at specific tool installation

**Solution**:
```bash
# Check log file
tail -f ~/security-tools-install.log

# Identify hanging process
ps aux | grep -E "apt|dnf|pip|go install"

# Press Ctrl+C to stop script

# Install failed tool manually
# For Go tools:
go install <package-path>@latest

# For Python tools:
python3 -m pip install <package-name>

# Re-run script (it will skip installed tools)
./ArcReactor.sh
```

---

### Issue 12: Android Studio Prompt Doesn't Appear

**Symptom**: Script doesn't ask about Android Studio installation

**Solution**:
The script includes a user prompt for Android Studio. If it doesn't appear:

```bash
# Install manually via snap
sudo snap install android-studio --classic

# Or download from official website
wget https://redirector.gvt1.com/edgedl/android/studio/ide-zips/2023.1.1.26/android-studio-2023.1.1.26-linux.tar.gz
tar -xzf android-studio-*.tar.gz
sudo mv android-studio /opt/
/opt/android-studio/bin/studio.sh
```

---

### Issue 13: Tool Conflicts with Kali Versions

**Symptom**: Newly installed tool conflicts with Kali's version

**Solution**:
```bash
# Check which version is being used
which nuclei
# If shows /usr/bin/nuclei (Kali's version)

# Update PATH priority to use Go version
export PATH="$HOME/go/bin:$PATH"

# Make permanent
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
which nuclei
# Should show /home/username/go/bin/nuclei

# Or create alias
alias nuclei-new='$HOME/go/bin/nuclei'
```

---

## 📚 Complete Tool List

### Go Security Tools (24 tools)

#### ProjectDiscovery Suite (8)
| Tool | Description | GitHub Stars | Use Case |
|------|-------------|--------------|----------|
| nuclei | Vulnerability scanner | 17k+ | Automated vulnerability detection |
| subfinder | Subdomain discovery | 8k+ | Passive subdomain enumeration |
| httpx | HTTP toolkit | 6k+ | Probing live hosts |
| katana | Web crawler | 7k+ | Crawling modern web apps |
| naabu | Port scanner | 4k+ | Fast port scanning |
| dnsx | DNS toolkit | 1k+ | DNS queries and validation |
| interactsh | OOB interaction | 3k+ | Out-of-band testing |
| notify | Notifications | 1k+ | Multi-channel alerts |

#### Fuzzing Tools (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| ffuf | Web fuzzer | Directory/parameter fuzzing |
| gobuster | Brute-forcer | Directory/DNS enumeration |

#### Discovery Tools (6)
| Tool | Description | Use Case |
|------|-------------|----------|
| amass | Subdomain enum | Comprehensive subdomain discovery |
| assetfinder | Asset discovery | Find related domains |
| gau | URL fetcher | Aggregate URLs from multiple sources |
| waybackurls | Archive URLs | Wayback Machine URL extraction |
| hakrawler | Web crawler | Fast crawling |
| gospider | Web spider | JavaScript-aware spidering |

#### Utility Tools (4)
| Tool | Description | Use Case |
|------|-------------|----------|
| gf | Pattern matcher | Find vulnerability patterns in URLs |
| anew | Unique appender | Deduplicate results |
| unfurl | URL parser | Extract URL components |
| qsreplace | Query replacer | Replace query string values |

#### Security Tools (4)
| Tool | Description | Use Case |
|------|-------------|----------|
| dalfox | XSS scanner | Parameter analysis and XSS detection |
| kxss | XSS finder | Find reflected XSS parameters |
| crlfuzz | CRLF scanner | CRLF injection detection |
| gitleaks | Secret scanner | Git repository secret detection |
| trufflehog | Credential finder | Find credentials in code |

---

### Python Security Tools (9 tools)

#### Web Testing (3)
| Tool | Description | Use Case |
|------|-------------|----------|
| arjun | Parameter discovery | Find hidden API parameters |
| xsstrike | XSS scanner | Advanced XSS detection |
| sublist3r | Subdomain enum | Fast subdomain enumeration |

#### Automation (1)
| Tool | Description | Use Case |
|------|-------------|----------|
| playwright | Browser automation | Automated testing with real browsers |

#### API Clients (3)
| Tool | Description | Use Case |
|------|-------------|----------|
| shodan | Shodan API | Internet-wide device search |
| censys | Censys API | Certificate and host intelligence |
| securitytrails | SecurityTrails API | DNS and domain intelligence |

#### Cloud Security (2)
| Tool | Description | Use Case |
|------|-------------|----------|
| prowler | AWS auditing | AWS security best practices |
| scoutsuite | Multi-cloud audit | AWS/Azure/GCP security assessment |

---

### Android Tools (7 tools)

| Tool | Description | Use Case | Location |
|------|-------------|----------|----------|
| ADB | Android Debug Bridge | Device communication | ~/security-tools/platform-tools/ |
| Fastboot | Android flashing tool | Device flashing | ~/security-tools/platform-tools/ |
| Android Studio | Official IDE | Full Android development | /opt/ or ~/snap/ |
| JADX | APK decompiler | Dex to Java decompilation | ~/security-tools/jadx/ |
| APKTool | APK reverse engineering | Decompile and rebuild APKs | ~/security-tools/apktool/ |
| scrcpy | Screen mirroring | Display and control devices | System PATH |
| MobSF | Mobile security framework | Comprehensive app analysis | Docker |

---

### Cloud Security Tools (3 tools)

| Tool | Description | Cloud Platform | Use Case |
|------|-------------|----------------|----------|
| Prowler | Security auditing | AWS | CIS benchmarks, compliance |
| ScoutSuite | Security auditing | AWS/Azure/GCP | Multi-cloud assessment |
| Trivy | Vulnerability scanner | All | Container/IaC scanning |

---

### Wordlists (2 collections)

| Collection | Files | Size | Categories |
|------------|-------|------|------------|
| SecLists | 40,000+ | ~1GB | Discovery, Passwords, Usernames, Fuzzing, Payloads |
| PayloadsAllTheThings | 1,000+ | ~200MB | XSS, SQLi, Command Injection, File Upload, XXE, SSRF |

---

### System Dependencies (Installed but not primary tools)

| Tool | Purpose |
|------|---------|
| Git | Version control |
| Python 3 | Python runtime |
| Go | Go compiler |
| Node.js | JavaScript runtime |
| Ruby | Ruby interpreter |
| Docker | Container platform |
| Build tools | Compilation dependencies |

---

## 🔄 Updating Tools

Regular updates ensure you have the latest features and vulnerability checks.

### Update Schedule Recommendation
- **Daily**: Nuclei templates (if actively hunting)
- **Weekly**: Nuclei templates, Go tools (if casually hunting)
- **Monthly**: All tools, system packages
- **Quarterly**: Wordlists, major version updates

---

### Update Go Tools

**Update All Go Tools at Once**:
```bash
# Create update script
cat > ~/security-tools/scripts/update-go-tools.sh << 'EOF'
#!/bin/bash

echo "Updating Go security tools..."

go_tools=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/Emoe/kxss@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/gitleaks/gitleaks/v8@latest"
    "github.com/trufflesecurity/trufflehog/v3@latest"
)

for tool in "${go_tools[@]}"; do
    echo "Updating $tool..."
    go install "$tool"
done

echo "All Go tools updated!"
EOF

chmod +x ~/security-tools/scripts/update-go-tools.sh

# Run update script
~/security-tools/scripts/update-go-tools.sh
```

**Update Individual Tools**:
```bash
# Update Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Update FFUF
go install github.com/ffuf/ffuf/v2@latest

# Verify updates
nuclei -version
subfinder -version
ffuf -V
```

---

### Update Python Tools

```bash
# Update pip first
python3 -m pip install --upgrade pip

# Update all Python security tools
python3 -m pip install --upgrade arjun xsstrike sublist3r playwright shodan censys securitytrails prowler scoutsuite

# Update Playwright browsers
python3 -m playwright install chromium

# List installed packages
python3 -m pip list | grep -E "arjun|xsstrike|sublist3r|playwright|shodan|censys|prowler|scoutsuite"
```

---

### Update Nuclei Templates

**Daily/Weekly Update** (Most Important):
```bash
# Update templates
nuclei -update-templates

# Verify update
nuclei -version
nuclei -templates-version

# Count templates
nuclei -tl | wc -l

# List recent additions (last 7 days)
find ~/nuclei-templates -type f -name "*.yaml" -mtime -7

# Search for specific CVE
nuclei -tl | grep -i "cve-2024"
```

---

### Update Wordlists

```bash
# Update SecLists
cd ~/security-tools/wordlists/SecLists
git pull origin master

# Check what changed
git log --oneline -10

# Update PayloadsAllTheThings
cd ~/security-tools/wordlists/PayloadsAllTheThings
git pull origin master

# Check what changed
git log --oneline -10
```

---

### Update System Packages

```bash
# Ubuntu/Debian/Kali
sudo apt update
sudo apt full-upgrade -y

# Fedora/RHEL/CentOS
sudo dnf update -y

# Arch/Manjaro
sudo pacman -Syu --noconfirm

# Clean up
sudo apt autoremove -y  # Ubuntu/Debian
sudo dnf autoremove -y  # Fedora/RHEL
sudo pacman -Sc --noconfirm  # Arch
```

---

### Update Docker Images

```bash
# Update MobSF
docker pull opensecurity/mobile-security-framework-mobsf:latest

# Remove old images
docker image prune -a -f

# Verify
docker images | grep mobsf
```

---

### Update Android Tools

**Update ADB/Platform Tools**:
```bash
# Download latest
wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip -O /tmp/platform-tools.zip

# Backup old version
mv ~/security-tools/platform-tools ~/security-tools/platform-tools-backup

# Extract new version
unzip /tmp/platform-tools.zip -d ~/security-tools/

# Verify
adb version

# Remove backup if working
rm -rf ~/security-tools/platform-tools-backup
```

**Update JADX**:
```bash
# Get latest version URL
JADX_URL=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep "browser_download_url.*jadx-.*.zip" | cut -d '"' -f 4)

# Download
wget $JADX_URL -O /tmp/jadx.zip

# Backup and update
mv ~/security-tools/jadx ~/security-tools/jadx-backup
mkdir -p ~/security-tools/jadx
unzip /tmp/jadx.zip -d ~/security-tools/jadx

# Verify
jadx --version
```

---

### Complete Update Script

**Create Master Update Script**:
```bash
cat > ~/security-tools/scripts/update-all.sh << 'EOF'
#!/bin/bash

echo "======================================"
echo "  Security Tools - Update All"
echo "======================================"

# Update system packages
echo ""
echo "[1/5] Updating system packages..."
if command -v apt &> /dev/null; then
    sudo apt update && sudo apt upgrade -y
elif command -v dnf &> /dev/null; then
    sudo dnf update -y
elif command -v pacman &> /dev/null; then
    sudo pacman -Syu --noconfirm
fi

# Update Python tools
echo ""
echo "[2/5] Updating Python tools..."
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade arjun xsstrike sublist3r playwright shodan censys prowler scoutsuite

# Update Go tools
echo ""
echo "[3/5] Updating Go tools..."
~/security-tools/scripts/update-go-tools.sh

# Update Nuclei templates
echo ""
echo "[4/5] Updating Nuclei templates..."
nuclei -update-templates

# Update wordlists
echo ""
echo "[5/5] Updating wordlists..."
cd ~/security-tools/wordlists/SecLists && git pull
cd ~/security-tools/wordlists/PayloadsAllTheThings && git pull

echo ""
echo "======================================"
echo "  All tools updated successfully!"
echo "======================================"
EOF

chmod +x ~/security-tools/scripts/update-all.sh

# Run update script
~/security-tools/scripts/update-all.sh
```

---

## 🗑️ Uninstallation

Complete removal of all installed tools.

### Quick Uninstall

```bash
# Remove main directories
rm -rf ~/security-tools
rm -rf ~/go
rm -rf ~/bug-bounty
rm -rf ~/nuclei-templates

# Remove Python packages
python3 -m pip uninstall -y arjun xsstrike sublist3r playwright shodan censys securitytrails prowler scoutsuite

# Remove Docker images
docker rmi opensecurity/mobile-security-framework-mobsf

# Clean PATH (edit ~/.bashrc)
nano ~/.bashrc
# Remove lines with: go/bin, security-tools, etc.
source ~/.bashrc
```

---

### Detailed Uninstallation Steps

#### Step 1: Remove Installation Directories
```bash
# Remove security tools
if [ -d ~/security-tools ]; then
    echo "Removing security-tools..."
    rm -rf ~/security-tools
fi

# Remove Go installation
if [ -d ~/go ]; then
    echo "Removing Go tools..."
    rm -rf ~/go
fi

# Remove bug bounty workspace
if [ -d ~/bug-bounty ]; then
    echo "Removing bug-bounty workspace..."
    rm -rf ~/bug-bounty
fi

# Remove Nuclei templates
if [ -d ~/nuclei-templates ]; then
    echo "Removing nuclei-templates..."
    rm -rf ~/nuclei-templates
fi

# Remove GF patterns
if [ -d ~/.gf ]; then
    echo "Removing GF patterns..."
    rm -rf ~/.gf ~/.gf-tomnomnom
fi

echo "Directories removed successfully!"
```

---

#### Step 2: Uninstall Python Packages
```bash
# List installed security packages
python3 -m pip list | grep -E "arjun|xsstrike|sublist3r|playwright|shodan|censys|prowler|scoutsuite"

# Uninstall all security packages
python3 -m pip uninstall -y \
    arjun \
    xsstrike \
    sublist3r \
    playwright \
    shodan \
    censys \
    securitytrails \
    prowler \
    scoutsuite

echo "Python packages uninstalled!"
```

---

#### Step 3: Remove Docker Images
```bash
# List Docker images
docker images | grep mobsf

# Remove MobSF
docker rmi opensecurity/mobile-security-framework-mobsf

# Remove any stopped containers
docker container prune -f

# Remove unused images
docker image prune -a -f

echo "Docker images removed!"
```

---

#### Step 4: Clean PATH Environment
```bash
# Backup bashrc
cp ~/.bashrc ~/.bashrc.backup

# Remove tool paths from bashrc
sed -i '/security-tools/d' ~/.bashrc
sed -i '/go\/bin/d' ~/.bashrc
sed -i '/\.local\/bin/d' ~/.bashrc
sed -i '/GOPATH/d' ~/.bashrc

# If using zsh
if [ -f ~/.zshrc ]; then
    cp ~/.zshrc ~/.zshrc.backup
    sed -i '/security-tools/d' ~/.zshrc
    sed -i '/go\/bin/d' ~/.zshrc
    sed -i '/\.local\/bin/d' ~/.zshrc
fi

# Reload shell
source ~/.bashrc

echo "PATH cleaned!"
```

---

#### Step 5: Remove Symlinks
```bash
# Remove symlinks from /usr/local/bin (if created)
sudo rm -f /usr/local/bin/adb
sudo rm -f /usr/local/bin/fastboot
sudo rm -f /usr/local/bin/jadx
sudo rm -f /usr/local/bin/apktool

echo "Symlinks removed!"
```

---

#### Step 6: Uninstall System Packages (Optional)

⚠️ **Warning**: Only remove if you're sure you don't need these for other purposes

```bash
# Ubuntu/Debian
sudo apt remove --purge -y \
    golang-go \
    docker.io \
    nodejs \
    npm

sudo apt autoremove -y

# Fedora/RHEL
sudo dnf remove -y \
    golang \
    docker \
    nodejs \
    npm

sudo dnf autoremove -y
```

---

#### Step 7: Remove Log Files
```bash
# Remove installation log
rm -f ~/security-tools-install.log

# Remove Nuclei cache
rm -rf ~/.config/nuclei

# Remove Docker logs (optional)
sudo rm -rf /var/lib/docker/containers/*/

echo "Log files removed!"
```

---

### Complete Uninstall Script

```bash
# Create uninstall script
cat > ~/uninstall-security-tools.sh << 'EOF'
#!/bin/bash

echo "=========================================="
echo "  Security Tools - Complete Uninstaller"
echo "=========================================="
echo ""

read -p "Are you sure you want to uninstall ALL security tools? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo ""
echo "[1/7] Removing installation directories..."
rm -rf ~/security-tools ~/go ~/bug-bounty ~/nuclei-templates ~/.gf ~/.gf-tomnomnom

echo "[2/7] Uninstalling Python packages..."
python3 -m pip uninstall -y arjun xsstrike sublist3r playwright shodan censys prowler scoutsuite 2>/dev/null

echo "[3/7] Removing Docker images..."
docker rmi opensecurity/mobile-security-framework-mobsf 2>/dev/null
docker container prune -f 2>/dev/null
docker image prune -a -f 2>/dev/null

echo "[4/7] Cleaning PATH..."
cp ~/.bashrc ~/.bashrc.backup
sed -i '/security-tools/d' ~/.bashrc
sed -i '/go\/bin/d' ~/.bashrc
sed -i '/\.local\/bin/d' ~/.bashrc

if [ -f ~/.zshrc ]; then
    cp ~/.zshrc ~/.zshrc.backup
    sed -i '/security-tools/d' ~/.zshrc
    sed -i '/go\/bin/d' ~/.zshrc
fi

echo "[5/7] Removing symlinks..."
sudo rm -f /usr/local/bin/{adb,fastboot,jadx,apktool} 2>/dev/null

echo "[6/7] Removing log files..."
rm -f ~/security-tools-install.log
rm -rf ~/.config/nuclei

echo "[7/7] Cleaning up..."
[ -f ~/.bashrc.backup ] && echo "Backup saved: ~/.bashrc.backup"
[ -f ~/.zshrc.backup ] && echo "Backup saved: ~/.zshrc.backup"

echo ""
echo "=========================================="
echo "  Uninstallation completed successfully!"
echo "=========================================="
echo ""
echo "Please restart your terminal or run: source ~/.bashrc"
EOF

chmod +x ~/uninstall-security-tools.sh

# Run uninstall script
~/uninstall-security-tools.sh
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

**Legal Consequences**:
- Criminal prosecution under Computer Fraud and Abuse Act (CFAA) or equivalent
- Civil lawsuits for damages
- Employment termination
- Criminal record
- Imprisonment

**Legal Testing Environments**:
- ✅ Personal lab/servers
- ✅ Bug bounty platforms (HackerOne, Bugcrowd, Intigriti, YesWeHack)
- ✅ Authorized penetration testing engagements
- ✅ Vulnerability disclosure programs (with explicit permission)
- ✅ CTF competitions and training platforms

**NEVER Test Without Permission**:
- ❌ Employer's systems (without written authorization)
- ❌ School/university networks
- ❌ Government systems
- ❌ Public websites/services
- ❌ Third-party applications
- ❌ "Just to see if it's vulnerable"

---

### Network Security

Many tools generate significant traffic that may trigger alerts:

**High-Traffic Tools**:
- Port scanners: nmap, masscan, naabu
- Web crawlers: katana, gospider, hakrawler
- Vulnerability scanners: nuclei
- Web fuzzers: ffuf, gobuster

**Best Practices**:

1. **Always Get Authorization**:
```bash
# Before running any scan
# Verify you have written permission
# Document your authorization
```

2. **Use Rate Limiting**:
```bash
# Nuclei with rate limit
nuclei -l targets.txt -rate-limit 50

# FFUF with rate limit
ffuf -rate 100 -u https://example.com/FUZZ -w wordlist.txt
```

3. **Respect robots.txt**:
```bash
# Check robots.txt before crawling
curl https://example.com/robots.txt
```

4. **Use VPN/Proxy When Appropriate**:
```bash
# Configure proxy for tools
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=https://proxy.example.com:8080

# Or use proxychains
proxychains4 nuclei -u https://example.com
```

5. **Monitor Your Traffic**:
```bash
# Watch network usage
sudo iftop

# Monitor connections
sudo netstat -tunap | grep ESTABLISHED
```

---

### Privacy Considerations

**Data Collection**:
- Some tools send telemetry (check privacy policies)
- API-based tools (Shodan, Censys) log your requests
- Cloud-based tools may store scan data

**Minimize Data Exposure**:
```bash
# Disable telemetry when available
nuclei -disable-update-check

# Use local tools for sensitive targets
# Avoid cloud-based scanners

# Encrypt results
# Use encrypted partitions or file-level encryption

# Secure your findings
chmod 600 ~/bug-bounty/results/*
```

**GDPR Compliance** (if in EU):
- Don't scan systems with personal data without authorization
- Follow data minimization principles
- Implement data retention policies
- Secure all collected data

---

### Responsible Disclosure

When you find vulnerabilities:

**1. Contact Security Team**:
- Look for security.txt: `https://example.com/.well-known/security.txt`
- Check for bug bounty program
- Email: security@example.com

**2. Provide Complete Details**:
```
Vulnerability Report Template:

Title: [Brief description]
Severity: [Critical/High/Medium/Low]
Type: [XSS/SQLi/RCE/etc.]

Description:
[Detailed explanation of the vulnerability]

Steps to Reproduce:
1. Navigate to https://example.com/page
2. Enter payload: <payload>
3. Observe result: <result>

Proof of Concept:
[Code, screenshots, video]

Impact:
[What can an attacker do with this vulnerability]

Remediation:
[How to fix the issue]

Discovered by: [Your name]
Date: [Date discovered]
```

**3. Give Time to Fix**:
- Standard: 90 days before public disclosure
- Critical: 30-60 days (coordinate with vendor)
- Actively exploited: Immediate notification

**4. Follow Program Rules**:
- Read scope carefully
- Respect out-of-scope items
- Don't test in production (if prohibited)
- Follow reporting guidelines
- Don't access user data

---

### Secure Your Environment

**1. Keep Tools Updated**:
```bash
# Weekly updates
~/security-tools/scripts/update-all.sh

# Daily Nuclei template updates
nuclei -update-templates
```

**2. Use Strong Authentication**:
- Enable 2FA on all accounts
- Use password manager
- Don't store credentials in scripts

**3. Secure Your Workspace**:
```bash
# Encrypt sensitive directories
# Use LUKS or eCryptfs

# Set file permissions
chmod 700 ~/security-tools
chmod 700 ~/bug-bounty

# Secure results
chmod 600 ~/bug-bounty/results/*
```

**4. Use VPN for Research**:
```bash
# Install VPN
sudo apt install openvpn

# Or use commercial VPN service
```

**5. Isolate Testing**:
- Use virtual machines for testing
- Separate network for scanning
- Don't use personal devices for testing

**6. Clean Up After Testing**:
```bash
# Remove test payloads
rm -f /tmp/test_payload.*

# Clear browser data
# Delete temporary files

# Securely delete sensitive data
shred -vfz -n 10 sensitive_file.txt
```

---

## ❓ FAQ

### General Questions

**Q: Can I use this script on Kali Linux?**
A: Yes! This script adds modern tools that aren't in Kali's default repos (ProjectDiscovery suite, latest Go tools, etc.). Kali already has nmap, sqlmap, metasploit, burp, etc.

**Q: How long does installation take?**
A: 30-60 minutes depending on internet speed. Faster connections: ~30 min. Slower connections: ~60 min.

**Q: How much disk space do I need?**
A: Minimum 10GB, recommended 20GB. Wordlists alone take ~1.5GB.

**Q: Can I install only specific tools?**
A: Yes, comment out sections in the script you don't want, or manually install tools:
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Q: Do I need administrator/root access?**
A: Yes, but run script as regular user. It will request sudo when needed.

---

### Community Resources

**Discord Servers**:
- ProjectDiscovery: https://discord.gg/projectdiscovery
- Bug Bounty Hunters: Various servers for platforms

**Forums**:
- Reddit: r/netsec, r/AskNetsec, r/bugbounty
- Stack Overflow: Security tag

**Learning Platforms**:
- HackTheBox: https://www.hackthebox.com
- TryHackMe: https://tryhackme.com
- PentesterLab: https://pentesterlab.com
- PortSwigger Web Security Academy: https://portswigger.net/web-security

---

### Bug Bounty Platforms

- **HackerOne**: https://www.hackerone.com
- **Bugcrowd**: https://www.bugcrowd.com
- **Intigriti**: https://www.intigriti.com
- **YesWeHack**: https://www.yeswehack.com
- **Synack**: https://www.synack.com

---

### Getting Help

**Script Issues**:
- Check log file: `$env:USERPROFILE\security-tools-install.log`
- Review troubleshooting section
- Search existing GitHub issues
- Create new GitHub issue with log file

**Tool-Specific Issues**:
- Check tool's official documentation
- Search tool's GitHub issues
- Ask in tool's Discord/forum
- Create issue on tool's repository

**General Security Questions**:
- r/AskNetsec on Reddit
- Information Security Stack Exchange
- Security-focused Discord servers

---

### Additional Resources

**Security Research Blogs**:
- PortSwigger Research: https://portswigger.net/research
- ProjectDiscovery Blog: https://blog.projectdiscovery.io
- Google Project Zero: https://googleprojectzero.blogspot.com

**Bug Bounty Writeups**:
- HackerOne Hacktivity: https://hackerone.com/hacktivity
- Pentester Land: https://pentester.land
- Medium Bug Bounty tag

**Video Tutorials**:
- YouTube: Search for specific tools
- Udemy/Coursera: Security courses
- PentesterAcademy: Video courses

---

## 📄 License & Legal

### Tools Licenses

Different tools have different licenses. Most are open source:

- **MIT License**: Nuclei, Subfinder, Httpx, many others
- **GPL**: OWASP ZAP, some Sysinternals tools
- **Apache 2.0**: Amass, some Go tools
- **Commercial**: Burp Suite Pro (Community version is free)

**Check individual tool licenses before commercial use**.

---

### Script License

This installation script is provided "as is" without warranty.

**Usage Terms**:
- ✅ Personal use
- ✅ Educational use
- ✅ Commercial use (script itself, not necessarily all tools)
- ✅ Modification and redistribution

**Disclaimer**:
```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### Legal Disclaimer

⚠️ **IMPORTANT LEGAL NOTICE**

This tool collection is intended for:
- Authorized security testing
- Educational purposes
- Security research
- Bug bounty programs
- Penetration testing with written permission

**Unauthorized use of these tools is illegal and may result in:**
- Criminal prosecution
- Civil liability
- Termination of employment
- Termination from educational institutions
- Blacklisting from bug bounty programs

**Users are responsible for:**
- Obtaining proper authorization before testing
- Following all applicable laws and regulations
- Respecting privacy and data protection laws
- Following responsible disclosure practices
- Understanding and accepting risks

**By using this script and tools, you agree to:**
- Use tools only on authorized targets
- Follow all applicable laws
- Accept full responsibility for your actions
- Not hold script author liable for misuse

---

## 🎉 Conclusion

You now have a comprehensive Windows security testing toolkit installed and ready to use.


### Next Steps

1. **Familiarize yourself with tools**:
   - Start with basic tools (Subfinder, Httpx, Nuclei)
   - Practice on authorized targets
   - Follow tool documentation

2. **Join bug bounty platforms**:
   - Create accounts on HackerOne, Bugcrowd
   - Read program scopes carefully
   - Start with easy targets

3. **Practice safely**:
   - Use HackTheBox, TryHackMe
   - Set up home lab
   - Follow responsible disclosure

4. **Stay updated**:
   - Update Nuclei templates weekly
   - Update tools monthly
   - Follow security researchers on Twitter

5. **Learn continuously**:
   - Read writeups and blogs
   - Watch tutorials and courses
   - Participate in CTFs
   - Join security communities

---

### Stay Secure, Stay Legal, Happy Hunting! 🎯

Remember: With great tools comes great responsibility. Always get permission before testing!

---

**Version**: 1.0.0  
**Last Updated**: 2024  
**Maintained By**: Security Tools Community

- Report writing skills

**Q: Which tools are most valuable for bug bounties?**
A: Most used:
1. **Nuclei**: Automated vulnerability detection
