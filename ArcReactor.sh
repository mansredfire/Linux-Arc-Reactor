#!/bin/bash

#################################################################
#                                                               #
#  Security Tools - Non-Kali Installation Script               #
#  Platform: Linux (Ubuntu/Debian/Fedora/Arch)                 #
#  Excludes: Tools already in Kali Linux                       #
#                                                               #
#################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/security-tools"
LOG_FILE="$HOME/security-tools-install.log"
FAILED_INSTALLS=()
SUCCESSFUL_INSTALLS=()

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     SECURITY TOOLS - NON-KALI INSTALLATION SCRIPT                ║
║                    Version 1.0.0                                  ║
║                                                                   ║
║        Installing tools NOT pre-installed in Kali Linux          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    log "ERROR: $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
    log "INFO: $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARNING: $1"
}

check_not_kali() {
    if grep -qi "kali" /etc/os-release 2>/dev/null; then
        print_error "This script is for NON-Kali systems"
        print_info "Kali Linux already has most of these tools pre-installed"
        print_info "Run 'sudo apt update && sudo apt upgrade' on Kali instead"
        exit 1
    fi
    
    print_success "Confirmed: Not running on Kali Linux"
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            VER=$VERSION_ID
        fi
        print_info "Detected OS: Linux ($OS)"
    else
        print_error "This script is for Linux systems only"
        print_info "For Windows, use the PowerShell script"
        exit 1
    fi
}

update_system() {
    print_info "Updating system packages..."
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        sudo apt update && sudo apt upgrade -y
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]]; then
        sudo dnf update -y
    elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
        sudo pacman -Syu --noconfirm
    fi
    
    print_success "System packages updated"
}

install_base_dependencies() {
    print_info "Installing base dependencies (not in Kali by default)..."
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        sudo apt install -y \
            build-essential \
            git \
            curl \
            wget \
            python3 \
            python3-pip \
            python3-venv \
            golang-go \
            nodejs \
            npm \
            ruby \
            ruby-dev \
            libssl-dev \
            libffi-dev \
            libxml2-dev \
            libxslt1-dev \
            zlib1g-dev \
            unzip \
            jq \
            docker.io
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]]; then
        sudo dnf install -y \
            @development-tools \
            git \
            curl \
            wget \
            python3 \
            python3-pip \
            golang \
            nodejs \
            npm \
            ruby \
            ruby-devel \
            openssl-devel \
            libffi-devel \
            libxml2-devel \
            libxslt-devel \
            zlib-devel \
            unzip \
            jq \
            docker
    fi
    
    print_success "Base dependencies installed"
}

setup_go() {
    print_info "Setting up Go environment..."
    
    if ! grep -q "export PATH=\$PATH:\$HOME/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
    fi
    
    if [ -f ~/.zshrc ]; then
        if ! grep -q "export PATH=\$PATH:\$HOME/go/bin" ~/.zshrc; then
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
        fi
    fi
    
    print_success "Go environment configured"
}

install_go_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING GO SECURITY TOOLS (NOT IN KALI)${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    print_warning "Kali Linux includes: nmap, sqlmap, metasploit, burpsuite, wireshark, etc."
    print_info "Installing additional tools not in Kali's default repos..."
    
    declare -A go_tools=(
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["interactsh"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["gobuster"]="github.com/OJ/gobuster/v3@latest"
        ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"
        ["gospider"]="github.com/jaeles-project/gospider@latest"
        ["gf"]="github.com/tomnomnom/gf@latest"
        ["anew"]="github.com/tomnomnom/anew@latest"
        ["unfurl"]="github.com/tomnomnom/unfurl@latest"
        ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        ["kxss"]="github.com/Emoe/kxss@latest"
        ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        ["gitleaks"]="github.com/gitleaks/gitleaks/v8@latest"
        ["trufflehog"]="github.com/trufflesecurity/trufflehog/v3@latest"
    )
    
    for tool_name in "${!go_tools[@]}"; do
        package="${go_tools[$tool_name]}"
        print_info "Installing $tool_name..."
        
        if go install "$package" >> "$LOG_FILE" 2>&1; then
            print_success "$tool_name installed"
            SUCCESSFUL_INSTALLS+=("$tool_name")
        else
            print_error "Failed to install $tool_name"
            FAILED_INSTALLS+=("$tool_name")
        fi
    done
}

install_python_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING PYTHON TOOLS (NOT IN KALI)${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    python3 -m pip install --upgrade pip
    
    print_warning "Kali includes: sqlmap, wpscan, nikto, dirb, etc."
    print_info "Installing additional Python tools..."
    
    python_tools=(
        "arjun"
        "xsstrike"
        "sublist3r"
        "playwright"
        "shodan"
        "censys"
        "securitytrails"
        "prowler"
        "scoutsuite"
    )
    
    for tool in "${python_tools[@]}"; do
        print_info "Installing $tool..."
        
        if python3 -m pip install --break-system-packages "$tool" >> "$LOG_FILE" 2>&1; then
            print_success "$tool installed"
            SUCCESSFUL_INSTALLS+=("$tool")
        else
            print_error "Failed to install $tool"
            FAILED_INSTALLS+=("$tool")
        fi
    done
    
    print_info "Installing Playwright browsers..."
    python3 -m playwright install chromium >> "$LOG_FILE" 2>&1
}

install_android_sdk_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING ANDROID SDK & ADB${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    print_info "Installing Android SDK Platform Tools (ADB, Fastboot)..."
    
    PLATFORM_TOOLS_DIR="$INSTALL_DIR/platform-tools"
    mkdir -p "$PLATFORM_TOOLS_DIR"
    
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        PLATFORM_TOOLS_URL="https://dl.google.com/android/repository/platform-tools-latest-linux.zip"
    else
        print_error "Unsupported architecture for Android Platform Tools: $ARCH"
        FAILED_INSTALLS+=("adb")
        return
    fi
    
    if wget -O "$PLATFORM_TOOLS_DIR/platform-tools.zip" "$PLATFORM_TOOLS_URL" >> "$LOG_FILE" 2>&1; then
        unzip -q "$PLATFORM_TOOLS_DIR/platform-tools.zip" -d "$INSTALL_DIR"
        chmod +x "$INSTALL_DIR/platform-tools/adb"
        chmod +x "$INSTALL_DIR/platform-tools/fastboot"
        
        sudo ln -sf "$INSTALL_DIR/platform-tools/adb" /usr/local/bin/adb 2>/dev/null || \
            ln -sf "$INSTALL_DIR/platform-tools/adb" "$HOME/go/bin/adb"
        
        sudo ln -sf "$INSTALL_DIR/platform-tools/fastboot" /usr/local/bin/fastboot 2>/dev/null || \
            ln -sf "$INSTALL_DIR/platform-tools/fastboot" "$HOME/go/bin/fastboot"
        
        print_success "Android Platform Tools installed"
        print_info "ADB location: $INSTALL_DIR/platform-tools/adb"
        SUCCESSFUL_INSTALLS+=("adb")
        SUCCESSFUL_INSTALLS+=("fastboot")
    else
        print_error "Failed to install Android Platform Tools"
        FAILED_INSTALLS+=("adb")
    fi
    
    print_info "Android Studio installation..."
    print_warning "Android Studio is a large download (~1GB)"
    read -p "Install Android Studio? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            if command -v snap &> /dev/null; then
                sudo snap install android-studio --classic >> "$LOG_FILE" 2>&1
                print_success "Android Studio installed via snap"
                SUCCESSFUL_INSTALLS+=("android-studio")
            else
                print_warning "Snap not available. Download manually from: https://developer.android.com/studio"
            fi
        else
            print_warning "Download Android Studio manually from: https://developer.android.com/studio"
        fi
    else
        print_info "Skipping Android Studio installation"
    fi
    
    print_info "Installing scrcpy (Android screen mirroring)..."
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        if command -v snap &> /dev/null; then
            sudo snap install scrcpy >> "$LOG_FILE" 2>&1
            print_success "scrcpy installed"
            SUCCESSFUL_INSTALLS+=("scrcpy")
        else
            sudo apt install -y scrcpy >> "$LOG_FILE" 2>&1
            print_success "scrcpy installed"
            SUCCESSFUL_INSTALLS+=("scrcpy")
        fi
    fi
}

install_android_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING ANDROID REVERSE ENGINEERING TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    # JADX
    print_info "Installing JADX..."
    JADX_URL=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep "browser_download_url.*jadx-.*.zip" | cut -d '"' -f 4)
    JADX_DIR="$INSTALL_DIR/jadx"
    
    mkdir -p "$JADX_DIR"
    if wget -O "$JADX_DIR/jadx.zip" "$JADX_URL" >> "$LOG_FILE" 2>&1; then
        unzip -q "$JADX_DIR/jadx.zip" -d "$JADX_DIR"
        chmod +x "$JADX_DIR/bin/jadx"
        sudo ln -sf "$JADX_DIR/bin/jadx" /usr/local/bin/jadx 2>/dev/null || ln -sf "$JADX_DIR/bin/jadx" "$HOME/go/bin/jadx"
        print_success "JADX installed"
        SUCCESSFUL_INSTALLS+=("jadx")
    else
        print_error "Failed to install JADX"
        FAILED_INSTALLS+=("jadx")
    fi
    
    # APKTool
    print_info "Installing APKTool..."
    mkdir -p "$INSTALL_DIR/apktool"
    
    if wget -O "$INSTALL_DIR/apktool/apktool.jar" "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.1.jar" >> "$LOG_FILE" 2>&1; then
        wget -O "$INSTALL_DIR/apktool/apktool" "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" >> "$LOG_FILE" 2>&1
        chmod +x "$INSTALL_DIR/apktool/apktool"
        sudo ln -sf "$INSTALL_DIR/apktool/apktool" /usr/local/bin/apktool 2>/dev/null || ln -sf "$INSTALL_DIR/apktool/apktool" "$HOME/go/bin/apktool"
        print_success "APKTool installed"
        SUCCESSFUL_INSTALLS+=("apktool")
    else
        print_error "Failed to install APKTool"
        FAILED_INSTALLS+=("apktool")
    fi
    
    # MobSF (Docker)
    print_info "Installing MobSF (Docker)..."
    if command -v docker &> /dev/null; then
        docker pull opensecurity/mobile-security-framework-mobsf >> "$LOG_FILE" 2>&1
        print_success "MobSF Docker image pulled"
        print_info "Run with: docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
        SUCCESSFUL_INSTALLS+=("mobsf")
    else
        print_warning "Docker not installed. Skipping MobSF"
    fi
}

install_cloud_tools() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING CLOUD SECURITY TOOLS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    print_info "Prowler installed via Python tools"
    
    # Trivy
    print_info "Installing Trivy..."
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt update && sudo apt install -y trivy
        print_success "Trivy installed"
        SUCCESSFUL_INSTALLS+=("trivy")
    fi
}

install_wordlists() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLING WORDLISTS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    WORDLIST_DIR="$INSTALL_DIR/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    # SecLists
    print_info "Cloning SecLists..."
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" >> "$LOG_FILE" 2>&1; then
        print_success "SecLists installed"
        SUCCESSFUL_INSTALLS+=("seclists")
    else
        print_error "Failed to install SecLists"
        FAILED_INSTALLS+=("seclists")
    fi
    
    # PayloadsAllTheThings
    print_info "Cloning PayloadsAllTheThings..."
    if git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$WORDLIST_DIR/PayloadsAllTheThings" >> "$LOG_FILE" 2>&1; then
        print_success "PayloadsAllTheThings installed"
        SUCCESSFUL_INSTALLS+=("payloadsallthethings")
    else
        print_error "Failed to install PayloadsAllTheThings"
        FAILED_INSTALLS+=("payloadsallthethings")
    fi
}

update_nuclei_templates() {
    print_info "Updating Nuclei templates..."
    
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates >> "$LOG_FILE" 2>&1
        print_success "Nuclei templates updated"
    fi
}

print_kali_note() {
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  TOOLS ALREADY IN KALI LINUX${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}The following tools are pre-installed in Kali:${NC}"
    echo ""
    echo -e "${GREEN}Network Scanning:${NC}"
    echo "  • nmap, masscan, nessus"
    echo "  • wireshark, tcpdump"
    echo ""
    echo -e "${GREEN}Web Application Testing:${NC}"
    echo "  • burpsuite, owasp-zap"
    echo "  • sqlmap, nikto, dirb"
    echo "  • wpscan, wfuzz"
    echo ""
    echo -e "${GREEN}Exploitation:${NC}"
    echo "  • metasploit-framework"
    echo "  • john, hashcat, hydra"
    echo ""
    echo -e "${GREEN}Reverse Engineering:${NC}"
    echo "  • radare2, gdb"
    echo ""
    echo -e "${CYAN}On Kali, update these with:${NC}"
    echo "  sudo apt update && sudo apt upgrade"
    echo ""
}

print_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLATION SUMMARY${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${GREEN}Successfully Installed (${#SUCCESSFUL_INSTALLS[@]})${NC}:"
    for tool in "${SUCCESSFUL_INSTALLS[@]}"; do
        echo -e "${GREEN}  ✓${NC} $tool"
    done
    
    if [ ${#FAILED_INSTALLS[@]} -gt 0 ]; then
        echo ""
        echo -e "${RED}Failed Installations (${#FAILED_INSTALLS[@]})${NC}:"
        for tool in "${FAILED_INSTALLS[@]}"; do
            echo -e "${RED}  ✗${NC} $tool"
        done
    fi
    
    echo ""
    echo -e "${BLUE}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  1. Restart terminal: ${CYAN}source ~/.bashrc${NC}"
    echo -e "  2. Verify ADB: ${CYAN}adb version${NC}"
    echo -e "  3. Verify Go tools: ${CYAN}which nuclei ffuf subfinder${NC}"
    echo -e "  4. Update Nuclei: ${CYAN}nuclei -update-templates${NC}"
    echo ""
    
    print_kali_note
}

main() {
    clear
    print_banner
    
    check_not_kali
    detect_os
    
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log "Installation started (Non-Kali systems)"
    log "OS: $OS"
    
    update_system
    install_base_dependencies
    setup_go
    
    mkdir -p "$INSTALL_DIR"
    
    install_go_tools
    install_python_tools
    install_android_sdk_tools
    install_android_tools
    install_cloud_tools
    install_wordlists
    
    update_nuclei_templates
    
    print_summary
    
    log "Installation completed"
}

main "$@"
