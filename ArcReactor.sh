# Linux Security Tools Installation Script (Non-Kali Tools Only)

```bash
#!/bin/bash

#############################################################################
# Linux Security Tools Installation Script
# 
# Description: Installs security tools that are:
#              1. NOT pre-installed on Kali Linux by default
#              2. FROM the comprehensive tools list provided
#
# Author: Security Tools Installer
# Version: 1.0.0
# Requires: Ubuntu/Debian/Fedora/Arch (NOT Kali Linux)
#############################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Directories
INSTALL_DIR="$HOME/security-tools"
LOG_FILE="$HOME/security-tools-install.log"
SUCCESSFUL_INSTALLS=()
FAILED_INSTALLS=()

#############################################################################
# UTILITY FUNCTIONS
#############################################################################

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║              ⚡ LINUX SECURITY TOOLS INSTALLER ⚡                 ║
║         Tools NOT Pre-Installed on Kali Linux                     ║
║                                                                   ║
║          Installing 50+ Additional Security Tools                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
    log_message "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
    log_message "ERROR: $1"
}

print_info() {
    echo -e "${CYAN}[*] $1${NC}"
    log_message "INFO: $1"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
    log_message "WARNING: $1"
}

#############################################################################
# SYSTEM DETECTION
#############################################################################

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
}

check_not_kali() {
    if grep -qi "kali" /etc/os-release 2>/dev/null; then
        print_error "This script is for NON-Kali systems only"
        print_info "Kali Linux already includes most tools"
        print_info "Run this on Ubuntu, Debian, Fedora, or Arch"
        exit 1
    fi
}

check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_error "Do NOT run this script as root"
        print_info "Script will request sudo when needed"
        exit 1
    fi
}

#############################################################################
# PACKAGE MANAGER FUNCTIONS
#############################################################################

update_system() {
    print_info "Updating system packages..."
    
    case $OS in
        ubuntu|debian)
            sudo apt update && sudo apt upgrade -y
            ;;
        fedora|rhel|centos)
            sudo dnf update -y
            ;;
        arch|manjaro)
            sudo pacman -Syu --noconfirm
            ;;
    esac
    
    print_success "System updated"
}

install_package() {
    local package=$1
    
    case $OS in
        ubuntu|debian)
            sudo apt install -y "$package" 2>&1 | tee -a "$LOG_FILE"
            ;;
        fedora|rhel|centos)
            sudo dnf install -y "$package" 2>&1 | tee -a "$LOG_FILE"
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm "$package" 2>&1 | tee -a "$LOG_FILE"
            ;;
    esac
}

#############################################################################
# DEPENDENCY INSTALLATION
#############################################################################

install_dependencies() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING SYSTEM DEPENDENCIES${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    local deps=()
    
    case $OS in
        ubuntu|debian)
            deps=(
                "build-essential"
                "git"
                "curl"
                "wget"
                "python3"
                "python3-pip"
                "python3-venv"
                "golang-go"
                "nodejs"
                "npm"
                "ruby"
                "ruby-dev"
                "libssl-dev"
                "libffi-dev"
                "libpcap-dev"
                "libxml2-dev"
                "libxslt1-dev"
                "zlib1g-dev"
                "unzip"
                "jq"
            )
            ;;
        fedora|rhel|centos)
            deps=(
                "gcc" "gcc-c++" "make"
                "git" "curl" "wget"
                "python3" "python3-pip"
                "golang" "nodejs" "npm"
                "ruby" "ruby-devel"
                "openssl-devel" "libffi-devel"
                "libpcap-devel" "libxml2-devel"
                "libxslt-devel" "zlib-devel"
                "unzip" "jq"
            )
            ;;
        arch|manjaro)
            deps=(
                "base-devel" "git" "curl" "wget"
                "python" "python-pip" "go"
                "nodejs" "npm" "ruby"
                "openssl" "libffi" "libpcap"
                "libxml2" "libxslt" "zlib"
                "unzip" "jq"
            )
            ;;
    esac
    
    for dep in "${deps[@]}"; do
        print_info "Installing $dep..."
        if install_package "$dep"; then
            SUCCESSFUL_INSTALLS+=("$dep")
        else
            FAILED_INSTALLS+=("$dep")
        fi
    done
}

#############################################################################
# GO TOOLS (NOT IN KALI)
#############################################################################

install_go_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING GO SECURITY TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    if ! grep -q "export GOPATH=" ~/.bashrc 2>/dev/null; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    fi
    
    if [ -f ~/.zshrc ]; then
        if ! grep -q "export GOPATH=" ~/.zshrc; then
            echo 'export GOPATH=$HOME/go' >> ~/.zshrc
            echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
        fi
    fi
    
    declare -A go_tools=(
        # Subdomain Enumeration
        ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["subjack"]="github.com/haccer/subjack@latest"
        
        # Web Crawling
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["gospider"]="github.com/jaeles-project/gospider@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        
        # Directory Discovery
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["gobuster"]="github.com/OJ/gobuster/v3@latest"
        ["feroxbuster"]="github.com/epi052/feroxbuster@latest"
        
        # Web Security
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        
        # API Testing
        ["kiterunner"]="github.com/assetnote/kiterunner@latest"
        
        # SSRF
        ["interactsh"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        
        # Cloud Security
        ["s3scanner"]="github.com/sa7mon/S3Scanner@latest"
        ["cloudbrute"]="github.com/0xsha/CloudBrute@latest"
        
        # Container Security
        ["grype"]="github.com/anchore/grype@latest"
        
        # Exploitation
        ["sliver"]="github.com/BishopFox/sliver@latest"
        ["merlin"]="github.com/Ne0nd0g/merlin-cli@latest"
    )
    
    for tool in "${!go_tools[@]}"; do
        print_info "Installing $tool..."
        if go install "${go_tools[$tool]}" 2>&1 | tee -a "$LOG_FILE"; then
            print_success "$tool installed"
            SUCCESSFUL_INSTALLS+=("$tool")
        else
            print_error "Failed to install $tool"
            FAILED_INSTALLS+=("$tool")
        fi
    done
}

#############################################################################
# PYTHON TOOLS (NOT IN KALI)
#############################################################################

install_python_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING PYTHON SECURITY TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    python3 -m pip install --upgrade pip 2>&1 | tee -a "$LOG_FILE"
    
    local python_tools=(
        # Subdomain Enumeration
        "sublist3r"
        
        # Web Security
        "arjun"
        "xsstrike"
        "dirsearch"
        
        # GraphQL
        "graphqlmap"
        "crackql"
        
        # NoSQL
        "nosqlmap"
        
        # SSRF
        "ssrfmap"
        
        # CORS
        "corsy"
        
        # JavaScript Analysis
        "linkfinder"
        "secretfinder"
        "subdomainizer"
        "retire"
        
        # Cloud Security
        "prowler"
        "scoutsuite"
        "pacu"
        
        # Dependency Security
        "safety"
        
        # OSINT
        "recon-ng"
        "theHarvester"
        
        # Android
        "drozer"
        "androguard"
        
        # API Testing
        "wfuzz"
        
        # Container Security
        "kube-hunter"
    )
    
    for tool in "${python_tools[@]}"; do
        print_info "Installing $tool..."
        if python3 -m pip install "$tool" 2>&1 | tee -a "$LOG_FILE"; then
            print_success "$tool installed"
            SUCCESSFUL_INSTALLS+=("$tool")
        else
            print_error "Failed to install $tool"
            FAILED_INSTALLS+=("$tool")
        fi
    done
}

#############################################################################
# MASSCAN (NOT IN KALI DEFAULT)
#############################################################################

install_masscan() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING MASSCAN${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    print_info "Installing Masscan..."
    if git clone https://github.com/robertdavidgraham/masscan "$INSTALL_DIR/masscan" 2>&1 | tee -a "$LOG_FILE"; then
        cd "$INSTALL_DIR/masscan"
        if make 2>&1 | tee -a "$LOG_FILE"; then
            sudo make install 2>&1 | tee -a "$LOG_FILE"
            print_success "Masscan installed"
            SUCCESSFUL_INSTALLS+=("masscan")
        else
            print_error "Failed to build Masscan"
            FAILED_INSTALLS+=("masscan")
        fi
        cd - > /dev/null
    else
        print_error "Failed to clone Masscan"
        FAILED_INSTALLS+=("masscan")
    fi
}

#############################################################################
# CLOUD SECURITY TOOLS
#############################################################################

install_cloud_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING CLOUD SECURITY TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    # Trivy
    print_info "Installing Trivy..."
    case $OS in
        ubuntu|debian)
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt update
            if sudo apt install -y trivy 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Trivy installed"
                SUCCESSFUL_INSTALLS+=("trivy")
            fi
            ;;
        fedora|rhel|centos)
            cat <<EOF | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/\$basearch/
gpgcheck=0
enabled=1
EOF
            if sudo dnf install -y trivy 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Trivy installed"
                SUCCESSFUL_INSTALLS+=("trivy")
            fi
            ;;
        arch|manjaro)
            if sudo pacman -S --noconfirm trivy 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Trivy installed"
                SUCCESSFUL_INSTALLS+=("trivy")
            fi
            ;;
    esac
    
    # CloudSploit
    print_info "Installing CloudSploit..."
    if git clone https://github.com/aquasecurity/cloudsploit.git "$INSTALL_DIR/cloudsploit" 2>&1 | tee -a "$LOG_FILE"; then
        cd "$INSTALL_DIR/cloudsploit"
        npm install 2>&1 | tee -a "$LOG_FILE"
        print_success "CloudSploit installed"
        SUCCESSFUL_INSTALLS+=("cloudsploit")
        cd - > /dev/null
    else
        print_error "Failed to install CloudSploit"
        FAILED_INSTALLS+=("cloudsploit")
    fi
}

#############################################################################
# KUBERNETES TOOLS
#############################################################################

install_kubernetes_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING KUBERNETES SECURITY TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    # kube-bench
    print_info "Installing kube-bench..."
    if git clone https://github.com/aquasecurity/kube-bench.git "$INSTALL_DIR/kube-bench" 2>&1 | tee -a "$LOG_FILE"; then
        cd "$INSTALL_DIR/kube-bench"
        if go build -o kube-bench . 2>&1 | tee -a "$LOG_FILE"; then
            sudo mv kube-bench /usr/local/bin/ 2>&1 | tee -a "$LOG_FILE"
            print_success "kube-bench installed"
            SUCCESSFUL_INSTALLS+=("kube-bench")
        fi
        cd - > /dev/null
    fi
}

#############################################################################
# FUZZING TOOLS
#############################################################################

install_fuzzing_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING FUZZING FRAMEWORKS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    # AFL++
    print_info "Installing AFL++..."
    if git clone https://github.com/AFLplusplus/AFLplusplus "$INSTALL_DIR/aflplusplus" 2>&1 | tee -a "$LOG_FILE"; then
        cd "$INSTALL_DIR/aflplusplus"
        if make 2>&1 | tee -a "$LOG_FILE"; then
            sudo make install 2>&1 | tee -a "$LOG_FILE"
            print_success "AFL++ installed"
            SUCCESSFUL_INSTALLS+=("afl++")
        fi
        cd - > /dev/null
    fi
    
    # Honggfuzz
    print_info "Installing Honggfuzz..."
    if git clone https://github.com/google/honggfuzz.git "$INSTALL_DIR/honggfuzz" 2>&1 | tee -a "$LOG_FILE"; then
        cd "$INSTALL_DIR/honggfuzz"
        if make 2>&1 | tee -a "$LOG_FILE"; then
            sudo make install 2>&1 | tee -a "$LOG_FILE"
            print_success "Honggfuzz installed"
            SUCCESSFUL_INSTALLS+=("honggfuzz")
        fi
        cd - > /dev/null
    fi
}

#############################################################################
# ANDROID TOOLS
#############################################################################

install_android_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING ANDROID TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    mkdir -p "$INSTALL_DIR/android"
    
    # dex2jar
    print_info "Installing dex2jar..."
    DEX2JAR_URL=$(curl -s https://api.github.com/repos/pxb1988/dex2jar/releases/latest | grep "browser_download_url.*zip" | cut -d '"' -f 4)
    if [ -n "$DEX2JAR_URL" ]; then
        wget -q "$DEX2JAR_URL" -O /tmp/dex2jar.zip
        unzip -q /tmp/dex2jar.zip -d "$INSTALL_DIR/android/"
        chmod +x "$INSTALL_DIR/android"/dex2jar-*/d2j-*.sh
        print_success "dex2jar installed"
        SUCCESSFUL_INSTALLS+=("dex2jar")
    fi
    
    # JD-GUI
    print_info "Installing JD-GUI..."
    JDGUI_URL=$(curl -s https://api.github.com/repos/java-decompiler/jd-gui/releases/latest | grep "browser_download_url.*\.jar" | cut -d '"' -f 4)
    if [ -n "$JDGUI_URL" ]; then
        wget -q "$JDGUI_URL" -O "$INSTALL_DIR/android/jd-gui.jar"
        print_success "JD-GUI installed"
        SUCCESSFUL_INSTALLS+=("jd-gui")
    fi
    
    # Bytecode Viewer
    print_info "Installing Bytecode Viewer..."
    BCV_URL=$(curl -s https://api.github.com/repos/Konloch/bytecode-viewer/releases/latest | grep "browser_download_url.*\.jar" | cut -d '"' -f 4)
    if [ -n "$BCV_URL" ]; then
        wget -q "$BCV_URL" -O "$INSTALL_DIR/android/bytecode-viewer.jar"
        print_success "Bytecode Viewer installed"
        SUCCESSFUL_INSTALLS+=("bytecode-viewer")
    fi
}

#############################################################################
# JAVASCRIPT ANALYSIS TOOLS
#############################################################################

install_javascript_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING JAVASCRIPT ANALYSIS TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    # JSFinder
    print_info "Installing JSFinder..."
    if git clone https://github.com/Threezh1/JSFinder.git "$INSTALL_DIR/jsfinder" 2>&1 | tee -a "$LOG_FILE"; then
        cd "$INSTALL_DIR/jsfinder"
        python3 -m pip install -r requirements.txt 2>&1 | tee -a "$LOG_FILE"
        print_success "JSFinder installed"
        SUCCESSFUL_INSTALLS+=("jsfinder")
        cd - > /dev/null
    fi
}

#############################################################################
# DIRECTORY STRUCTURE
#############################################################################

create_directory_structure() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  CREATING DIRECTORY STRUCTURE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    mkdir -p "$INSTALL_DIR"/{tools,wordlists,scripts,results,configs,android}
    mkdir -p "$HOME/bug-bounty"/{recon/{subdomains,urls,ports},scanning,exploitation,reporting}
    
    print_success "Directory structure created"
}

#############################################################################
# SUMMARY
#############################################################################

show_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLATION SUMMARY${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${GREEN}Successfully Installed (${#SUCCESSFUL_INSTALLS[@]}):${NC}"
    printf '%s\n' "${SUCCESSFUL_INSTALLS[@]}" | sort | while read tool; do
        echo -e "${GREEN}  ✓ $tool${NC}"
    done
    
    if [ ${#FAILED_INSTALLS[@]} -gt 0 ]; then
        echo ""
        echo -e "${RED}Failed Installations (${#FAILED_INSTALLS[@]}):${NC}"
        printf '%s\n' "${FAILED_INSTALLS[@]}" | sort | while read tool; do
            echo -e "${RED}  ✗ $tool${NC}"
        done
    fi
    
    echo ""
    echo -e "${BLUE}Installation Directory: $INSTALL_DIR${NC}"
    echo -e "${BLUE}Log File: $LOG_FILE${NC}"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  TOOLS INSTALLED (NOT IN KALI LINUX)${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}📡 Network Scanning:${NC}"
    echo -e "  • Masscan - Fast port scanner${NC}"
    echo ""
    echo -e "${CYAN}🌐 Subdomain Enumeration:${NC}"
    echo -e "  • Amass, Subfinder, Assetfinder, Sublist3r, Subjack${NC}"
    echo ""
    echo -e "${CYAN}🔍 Web Crawling:${NC}"
    echo -e "  • Katana, GoSpider, Hakrawler, GAU, Waybackurls${NC}"
    echo ""
    echo -e "${CYAN}📂 Directory Discovery:${NC}"
    echo -e "  • Ffuf, Gobuster, Feroxbuster, Dirsearch, Wfuzz${NC}"
    echo ""
    echo -e "${CYAN}🔐 Web Security:${NC}"
    echo -e "  • Nuclei, Httpx, Naabu, Dnsx, Notify${NC}"
    echo ""
    echo -e "${CYAN}🔎 Parameter & API:${NC}"
    echo -e "  • Arjun, Kiterunner${NC}"
    echo ""
    echo -e "${CYAN}📊 GraphQL:${NC}"
    echo -e "  • GraphQLmap, CrackQL${NC}"
    echo ""
    echo -e "${CYAN}💉 Injection:${NC}"
    echo -e "  • NoSQLMap${NC}"
    echo ""
    echo -e "${CYAN}💥 XSS:${NC}"
    echo -e "  • XSStrike, Dalfox${NC}"
    echo ""
    echo -e "${CYAN}🔓 SSRF:${NC}"
    echo -e "  • SSRFmap, Interactsh${NC}"
    echo ""
    echo -e "${CYAN}🌐 CORS:${NC}"
    echo -e "  • Corsy${NC}"
    echo ""
    echo -e "${CYAN}📜 JavaScript Analysis:${NC}"
    echo -e "  • LinkFinder, JSFinder, SecretFinder, Subdomainizer, Retire.js${NC}"
    echo ""
    echo -e "${CYAN}☁️ Cloud Security:${NC}"
    echo -e "  • Prowler, ScoutSuite, CloudSploit, Pacu${NC}"
    echo -e "  • S3Scanner, CloudBrute${NC}"
    echo ""
    echo -e "${CYAN}🐳 Container & Kubernetes:${NC}"
    echo -e "  • Trivy, Grype, kube-bench, kube-hunter${NC}"
    echo ""
    echo -e "${CYAN}📦 Dependency:${NC}"
    echo -e "  • Safety${NC}"
    echo ""
    echo -e "${CYAN}🎯 Exploitation:${NC}"
    echo -e "  • Sliver, Merlin${NC}"
    echo ""
    echo -e "${CYAN}🔨 Fuzzing:${NC}"
    echo -e "  • AFL++, Honggfuzz${NC}"
    echo ""
    echo -e "${CYAN}🔧 Android:${NC}"
    echo -e "  • Drozer, Androguard, dex2jar, JD-GUI, Bytecode Viewer${NC}"
    echo ""
    echo -e "${CYAN}🔍 OSINT:${NC}"
    echo -e "  • Recon-ng, theHarvester${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  1. Reload shell: ${CYAN}source ~/.bashrc${NC}"
    echo -e "  2. Verify: ${CYAN}nuclei -version${NC}"
    echo -e "  3. Update templates: ${CYAN}nuclei -update-templates${NC}"
    echo ""
}

#############################################################################
# MAIN
#############################################################################

main() {
    print_banner
    
    check_root
    detect_os
    check_not_kali
    
    touch "$LOG_FILE"
    
    print_info "Installation started"
    print_info "OS: $OS $OS_VERSION"
    echo ""
    
    update_system
    install_dependencies
    create_directory_structure
    
    install_go_tools
    install_python_tools
    install_masscan
    install_cloud_tools
    install_kubernetes_tools
    install_fuzzing_tools
    install_android_tools
    install_javascript_tools
    
    show_summary
}

main
Linux systems that complement Kali's default toolset.
