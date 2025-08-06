#!/bin/bash

#==============================================================================
# SSH Manager Script - Professional Edition
# Description: Comprehensive SSH account manager with Stunnel and V2Ray support
# Compatible with: Ubuntu 18.04, 20.04, 22.04
# Author: SSH Manager Team
# Version: 2.0
#==============================================================================

# Color codes for professional output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Configuration constants
readonly LOG_FILE="/var/log/ssh-manager.log"
readonly STUNNEL_CONF="/etc/stunnel/stunnel.conf"
readonly V2RAY_CONF="/usr/local/etc/v2ray/config.json"
readonly SSL_CERT_DIR="/etc/stunnel"
readonly SCRIPT_NAME="ssh-manager.sh"

# Progress indicators
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Enhanced logging with timestamps
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Also display to user with colors
    case $level in
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
    esac
}

# Progress bar function
show_progress() {
    local current=$1
    local total=$2
    local message=$3
    local percentage=$((current * 100 / total))
    local filled=$((percentage / 2))
    local empty=$((50 - filled))
    
    printf "\r${BLUE}[$message]${NC} ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] ${WHITE}%d%%${NC}" "$percentage"
}

# Check system compatibility
check_system_compatibility() {
    log_message "INFO" "Checking system compatibility..."
    
    if [[ ! -f /etc/os-release ]]; then
        log_message "ERROR" "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    case $VERSION_ID in
        "18.04"|"20.04"|"22.04")
            log_message "SUCCESS" "Ubuntu $VERSION_ID detected - Compatible"
            ;;
        *)
            log_message "WARNING" "Ubuntu $VERSION_ID may not be fully supported"
            echo -en "${YELLOW}Continue anyway? [y/N]: ${NC}"
            read -r response
            [[ ! "$response" =~ ^[Yy]$ ]] && exit 1
            ;;
    esac
}

# Root privilege check
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root (use sudo)"
        echo -e "${RED}Please run: ${WHITE}sudo $0${NC}"
        exit 1
    fi
}

# Initialize logging system
init_logging() {
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 644 "$LOG_FILE"
    fi
    log_message "INFO" "SSH Manager started - Version 2.0"
}

# Professional welcome banner
show_welcome_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                      SSH MANAGER SCRIPT v2.0                    ║
║                   Professional SSH & VPN Solution                ║
║                                                                  ║
║  🔐 SSH Account Management  🌐 V2Ray Support  🔒 Stunnel SSL     ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# User confirmation before proceeding
get_user_confirmation() {
    local message=$1
    echo -e "\n${YELLOW}⚠️  IMPORTANT: ${message}${NC}"
    echo -e "${WHITE}This will make changes to your system.${NC}"
    echo -en "${BLUE}Do you want to continue? [Y/N]: ${NC}"
    read -r response
    
    case $response in
        [Yy]|[Yy][Ee][Ss])
            log_message "INFO" "User confirmed: $message"
            return 0
            ;;
        *)
            log_message "INFO" "User cancelled: $message"
            echo -e "${YELLOW}Operation cancelled by user.${NC}"
            return 1
            ;;
    esac
}

# Enhanced main menu
show_main_menu() {
    clear
    show_welcome_banner
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│                         MAIN MENU                              │${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}│  ${WHITE}1)${NC} ${GREEN}Create SSH Account${NC}                                   │"
    echo -e "${BLUE}│  ${WHITE}2)${NC} ${RED}Delete SSH Account${NC}                                   │"
    echo -e "${BLUE}│  ${WHITE}3)${NC} ${CYAN}List Active SSH Users${NC}                               │"
    echo -e "${BLUE}│  ${WHITE}4)${NC} ${PURPLE}Monitor Online Users${NC}                                │"
    echo -e "${BLUE}│  ${WHITE}5)${NC} ${YELLOW}Install Dependencies${NC}                                │"
    echo -e "${BLUE}│  ${WHITE}6)${NC} ${CYAN}Configure Stunnel SSL${NC}                               │"
    echo -e "${BLUE}│  ${WHITE}7)${NC} ${PURPLE}Configure V2Ray${NC}                                     │"
    echo -e "${BLUE}│  ${WHITE}8)${NC} ${GREEN}Connection Information${NC}                              │"
    echo -e "${BLUE}│  ${WHITE}9)${NC} ${YELLOW}Generate Config Templates${NC}                           │"
    echo -e "${BLUE}│  ${WHITE}10)${NC} ${CYAN}Generate QR Codes${NC}                                   │"
    echo -e "${BLUE}│  ${WHITE}11)${NC} ${GREEN}System Status & Health Check${NC}                       │"
    echo -e "${BLUE}│  ${WHITE}12)${NC} ${PURPLE}Cleanup Expired Users${NC}                              │"
    echo -e "${BLUE}│  ${WHITE}0)${NC} ${RED}Exit${NC}                                                 │"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo -e "\n${WHITE}💡 Tip: Type '${GREEN}menu${WHITE}' anytime to return here${NC}"
    echo -en "\n${YELLOW}Please select an option [0-12]: ${NC}"
}

# Input validation functions
validate_username() {
    local username=$1
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]] || [[ ${#username} -lt 3 ]] || [[ ${#username} -gt 32 ]]; then
        return 1
    fi
    return 0
}

validate_password() {
    local password=$1
    if [[ ${#password} -lt 6 ]]; then
        return 1
    fi
    return 0
}

validate_days() {
    local days=$1
    if [[ ! "$days" =~ ^[0-9]+$ ]] || [[ $days -lt 1 ]] || [[ $days -gt 365 ]]; then
        return 1
    fi
    return 0
}

# Enhanced SSH account creation
create_ssh_account() {
    if ! get_user_confirmation "Create a new SSH account"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 🔐 SSH Account Creation ===${NC}"
    
    # Username input with validation
    while true; do
        echo -en "\n${YELLOW}👤 Enter username (3-32 chars, alphanumeric + _ -): ${NC}"
        read -r username
        
        if validate_username "$username"; then
            if id "$username" &>/dev/null; then
                log_message "ERROR" "User '$username' already exists"
                continue
            fi
            break
        else
            log_message "ERROR" "Invalid username format"
        fi
    done
    
    # Password input with validation
    while true; do
        echo -en "${YELLOW}🔑 Enter password (minimum 6 characters): ${NC}"
        read -rs password
        echo
        echo -en "${YELLOW}🔑 Confirm password: ${NC}"
        read -rs password_confirm
        echo
        
        if [[ "$password" != "$password_confirm" ]]; then
            log_message "ERROR" "Passwords do not match"
            continue
        fi
        
        if validate_password "$password"; then
            break
        else
            log_message "ERROR" "Password must be at least 6 characters"
        fi
    done
    
    # Expiration input
    while true; do
        echo -en "${YELLOW}📅 Enter expiration in days (1-365): ${NC}"
        read -r days
        
        if validate_days "$days"; then
            break
        else
            log_message "ERROR" "Please enter a number between 1 and 365"
        fi
    done
    
    # Account creation process
    echo -e "\n${BLUE}🔄 Creating SSH account...${NC}"
    
    # Create user
    log_message "INFO" "Creating user account for '$username'"
    if useradd -m -s /bin/bash "$username" 2>/dev/null; then
        log_message "SUCCESS" "User '$username' created successfully"
    else
        log_message "ERROR" "Failed to create user '$username'"
        return 1
    fi
    
    # Set password
    log_message "INFO" "Setting password for user '$username'"
    if echo "$username:$password" | chpasswd; then
        log_message "SUCCESS" "Password set successfully"
    else
        log_message "ERROR" "Failed to set password for '$username'"
        userdel -r "$username" 2>/dev/null
        return 1
    fi
    
    # Set expiration
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    log_message "INFO" "Setting expiration date to $expire_date"
    if chage -E "$expire_date" "$username"; then
        log_message "SUCCESS" "Account expiration set to $expire_date"
    else
        log_message "WARNING" "Failed to set expiration date"
    fi
    
    # Display account summary
    echo -e "\n${GREEN}✅ SSH Account Created Successfully!${NC}"
    echo -e "${BLUE}┌─────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│           ACCOUNT DETAILS               │${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}│ ${WHITE}Username:${NC} ${GREEN}$username${NC}"
    echo -e "${BLUE}│ ${WHITE}Password:${NC} ${GREEN}$password${NC}"
    echo -e "${BLUE}│ ${WHITE}Expires:${NC}  ${YELLOW}$expire_date${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────┘${NC}"
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Install dependencies with progress tracking
install_dependencies() {
    if ! get_user_confirmation "Install required dependencies and packages"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 📦 Installing Dependencies ===${NC}"
    
    local packages=("openssh-server" "stunnel4" "openssl" "curl" "wget" "unzip" "qrencode" "jq" "ufw")
    local total_packages=${#packages[@]}
    
    # Update package lists
    log_message "INFO" "Updating package repositories..."
    if apt update -qq &>/dev/null; then
        log_message "SUCCESS" "Package repositories updated"
    else
        log_message "ERROR" "Failed to update package repositories"
        return 1
    fi
    
    # Install packages with progress
    for i in "${!packages[@]}"; do
        local package="${packages[i]}"
        local current=$((i + 1))
        
        show_progress "$current" "$total_packages" "Installing $package"
        
        if apt install -y "$package" -qq &>/dev/null; then
            log_message "SUCCESS" "$package installed successfully"
        else
            log_message "WARNING" "Failed to install $package - continuing..."
        fi
        sleep 1
    done
    echo # New line after progress bar
    
    # Install V2Ray
    log_message "INFO" "Installing V2Ray..."
    if [[ ! -f "/usr/local/bin/v2ray" ]]; then
        cd /tmp || exit 1
        if curl -L -s -o v2ray-installer.sh https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh; then
            chmod +x v2ray-installer.sh
            if bash v2ray-installer.sh &>/dev/null; then
                log_message "SUCCESS" "V2Ray installed successfully"
            else
                log_message "ERROR" "Failed to install V2Ray"
            fi
            rm -f v2ray-installer.sh
        else
            log_message "ERROR" "Failed to download V2Ray installer"
        fi
    else
        log_message "SUCCESS" "V2Ray already installed"
    fi
    
    # Enable SSH service
    log_message "INFO" "Configuring SSH service..."
    if systemctl enable ssh && systemctl start ssh &>/dev/null; then
        log_message "SUCCESS" "SSH service enabled and started"
    else
        log_message "ERROR" "Failed to configure SSH service"
    fi
    
    echo -e "\n${GREEN}✅ Dependencies installation completed!${NC}"
    echo -e "${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# System status and health check
system_health_check() {
    echo -e "\n${CYAN}=== 🏥 System Health Check ===${NC}"
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo -e "\n${WHITE}📊 System Information:${NC}"
    echo -e "${BLUE}├─ Server IP:${NC} ${GREEN}$server_ip${NC}"
    echo -e "${BLUE}├─ Hostname:${NC} ${GREEN}$(hostname)${NC}"
    echo -e "${BLUE}├─ OS Version:${NC} ${GREEN}$(lsb_release -d | cut -f2)${NC}"
    echo -e "${BLUE}└─ Uptime:${NC} ${GREEN}$(uptime -p)${NC}"
    
    echo -e "\n${WHITE}🔧 Service Status:${NC}"
    
    # Check SSH
    if systemctl is-active --quiet ssh; then
        echo -e "${GREEN}✅ SSH Service: Running (Port 22)${NC}"
    else
        echo -e "${RED}❌ SSH Service: Not running${NC}"
    fi
    
    # Check Stunnel
    if systemctl is-active --quiet stunnel4; then
        echo -e "${GREEN}✅ Stunnel Service: Running (Port 443 → 22)${NC}"
    else
        echo -e "${YELLOW}⚠️  Stunnel Service: Not configured/running${NC}"
    fi
    
    # Check V2Ray
    if systemctl is-active --quiet v2ray; then
        echo -e "${GREEN}✅ V2Ray Service: Running${NC}"
    else
        echo -e "${YELLOW}⚠️  V2Ray Service: Not configured/running${NC}"
    fi
    
    # Check firewall
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✅ UFW Firewall: Active${NC}"
    else
        echo -e "${YELLOW}⚠️  UFW Firewall: Inactive${NC}"
    fi
    
    # Resource usage
    echo -e "\n${WHITE}💾 Resource Usage:${NC}"
    local memory_usage=$(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100)}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}')
    echo -e "${BLUE}├─ Memory Usage:${NC} ${GREEN}$memory_usage${NC}"
    echo -e "${BLUE}└─ Disk Usage:${NC} ${GREEN}$disk_usage${NC}"
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Cleanup expired users
cleanup_expired_users() {
    if ! get_user_confirmation "Clean up expired SSH accounts"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 🧹 Cleaning Up Expired Users ===${NC}"
    
    local expired_users=()
    local current_date=$(date +%s)
    
    # Find expired users
    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ $uid -ge 1000 && $uid != 65534 && "$shell" != "/usr/sbin/nologin" ]]; then
            local expire_info=$(chage -l "$user" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
            if [[ "$expire_info" != "never" && "$expire_info" != "" ]]; then
                local expire_date=$(date -d "$expire_info" +%s 2>/dev/null)
                if [[ $expire_date -lt $current_date ]]; then
                    expired_users+=("$user")
                fi
            fi
        fi
    done < /etc/passwd
    
    if [[ ${#expired_users[@]} -eq 0 ]]; then
        log_message "INFO" "No expired users found"
        return 0
    fi
    
    echo -e "${YELLOW}Found ${#expired_users[@]} expired user(s):${NC}"
    for user in "${expired_users[@]}"; do
        echo -e "${RED}  - $user${NC}"
    done
    
    echo -en "\n${YELLOW}Delete all expired users? [y/N]: ${NC}"
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        for user in "${expired_users[@]}"; do
            if userdel -r "$user" 2>/dev/null; then
                log_message "SUCCESS" "Deleted expired user: $user"
            else
                log_message "ERROR" "Failed to delete user: $user"
            fi
        done
    else
        log_message "INFO" "Cleanup cancelled by user"
    fi
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Completion message
show_completion_message() {
    clear
    echo -e "${GREEN}"
    cat << 'EOF'
✅ Setup Complete!
👋 Welcome to SSH Manager Script

🎉 Your SSH management system is now ready!

🔧 Available Commands:
   • Type 'menu' to access the main menu
   • Type 'status' for system health check  
   • Type 'help' for command help

📋 Quick Access:
   • SSH Account Management
   • Stunnel SSL Configuration  
   • V2Ray Protocol Setup
   • Real-time Monitoring
   • Configuration Templates

EOF
    echo -e "${NC}"
    log_message "SUCCESS" "Setup completed successfully"
}

# Command processor for menu system
process_command() {
    local command=$1
    case $command in
        "menu"|"m")
            main_menu_loop
            ;;
        "status"|"s")
            system_health_check
            ;;
        "help"|"h")
            show_help
            ;;
        "exit"|"quit"|"q")
            echo -e "${GREEN}Thank you for using SSH Manager!${NC}"
            log_message "INFO" "SSH Manager exited by user command"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown command: $command${NC}"
            echo -e "${YELLOW}Type 'help' for available commands${NC}"
            ;;
    esac
}

# Help system
show_help() {
    echo -e "\n${CYAN}=== 📖 SSH Manager Help ===${NC}"
    echo -e "${WHITE}Available Commands:${NC}"
    echo -e "${GREEN}  menu, m${NC}     - Show main menu"
    echo -e "${GREEN}  status, s${NC}   - System health check"
    echo -e "${GREEN}  help, h${NC}     - Show this help"
    echo -e "${GREEN}  exit, quit, q${NC} - Exit the program"
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Main menu loop
main_menu_loop() {
    while true; do
        show_main_menu
        read -r choice
        
        case $choice in
            1) create_ssh_account ;;
            2) delete_ssh_account ;;
            3) list_ssh_users ;;
            4) monitor_online_users ;;
            5) install_dependencies ;;
            6) setup_stunnel ;;
            7) setup_v2ray ;;
            8) show_connection_info ;;
            9) generate_config_templates ;;
            10) generate_qr_codes ;;
            11) system_health_check ;;
            12) cleanup_expired_users ;;
            0) 
                echo -e "\n${GREEN}Thank you for using SSH Manager!${NC}"
                log_message "INFO" "SSH Manager exited normally"
                exit 0
                ;;
            *)
                log_message "WARNING" "Invalid menu option: $choice"
                echo -e "\n${RED}Invalid option. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Initial setup and main execution
main() {
    # System checks
    check_root_privileges
    check_system_compatibility
    init_logging
    
    # Check if this is first run
    if [[ "$1" == "--first-run" ]]; then
        show_welcome_banner
        if get_user_confirmation "Set up SSH Manager on this system"; then
            install_dependencies
            show_completion_message
            echo -e "${WHITE}➤ Type '${GREEN}menu${WHITE}' to get started.${NC}"
        else
            echo -e "${YELLOW}Setup cancelled. Run again when ready.${NC}"
            exit 0
        fi
    else
        # Handle command line arguments
        if [[ $# -gt 0 ]]; then
            process_command "$1"
        else
            main_menu_loop
        fi
    fi
}

# Complete implementation of all features

# Delete SSH account
delete_ssh_account() {
    if ! get_user_confirmation "Delete an SSH account"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 🗑️  Delete SSH Account ===${NC}"
    
    # List existing users (excluding system users)
    log_message "INFO" "Listing available SSH users for deletion"
    local users=($(awk -F: '$3 >= 1000 && $3 != 65534 { print $1 }' /etc/passwd))
    
    if [[ ${#users[@]} -eq 0 ]]; then
        log_message "WARNING" "No SSH users found"
        return 0
    fi
    
    echo -e "${WHITE}📋 Available SSH users:${NC}"
    for i in "${!users[@]}"; do
        echo -e "${CYAN}  $((i+1))) ${users[i]}${NC}"
    done
    
    echo -en "\n${YELLOW}👤 Enter username to delete: ${NC}"
    read -r username
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_message "ERROR" "User '$username' does not exist"
        return 1
    fi
    
    # Confirm deletion
    echo -en "${RED}⚠️  Are you sure you want to delete user '$username'? [y/N]: ${NC}"
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log_message "INFO" "Attempting to delete user '$username'"
        if userdel -r "$username" 2>/dev/null; then
            log_message "SUCCESS" "User '$username' deleted successfully"
        else
            log_message "ERROR" "Failed to delete user '$username'"
        fi
    else
        log_message "INFO" "User deletion cancelled"
    fi
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# List active SSH users
list_ssh_users() {
    echo -e "\n${CYAN}=== 👥 Active SSH Users ===${NC}"
    
    echo -e "\n${BLUE}┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐${NC}"
    echo -e "${BLUE}│    Username     │      UID        │   Home Dir      │   Expire Date   │${NC}"
    echo -e "${BLUE}├─────────────────┼─────────────────┼─────────────────┼─────────────────┤${NC}"
    
    local found=false
    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ $uid -ge 1000 && $uid != 65534 && "$shell" != "/usr/sbin/nologin" ]]; then
            local expire_info=$(chage -l "$user" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
            [[ "$expire_info" == "never" ]] && expire_info="Never"
            printf "${GREEN}│ %-15s │ %-15s │ %-15s │ %-15s │${NC}\n" "$user" "$uid" "$home" "$expire_info"
            found=true
        fi
    done < /etc/passwd
    
    echo -e "${BLUE}└─────────────────┴─────────────────┴─────────────────┴─────────────────┘${NC}"
    
    if [[ "$found" == false ]]; then
        log_message "INFO" "No SSH users found"
    fi
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Monitor online users
monitor_online_users() {
    echo -e "\n${CYAN}=== 👁️  Online Users Monitor ===${NC}"
    
    echo -e "\n${WHITE}🔗 Currently logged in users:${NC}"
    if who | grep -q .; then
        echo -e "${BLUE}┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐${NC}"
        echo -e "${BLUE}│    Username     │    Terminal     │    Login Time   │      From       │${NC}"
        echo -e "${BLUE}├─────────────────┼─────────────────┼─────────────────┼─────────────────┤${NC}"
        
        while read -r user terminal time from; do
            [[ -z "$from" ]] && from="local"
            printf "${GREEN}│ %-15s │ %-15s │ %-15s │ %-15s │${NC}\n" "$user" "$terminal" "$time" "$from"
        done < <(who)
        
        echo -e "${BLUE}└─────────────────┴─────────────────┴─────────────────┴─────────────────┘${NC}"
    else
        log_message "INFO" "No users currently logged in"
    fi
    
    echo -e "\n${WHITE}📊 SSH connection summary:${NC}"
    local ssh_count=$(ss -tn state established '( dport = :22 or sport = :22 )' | grep -c ":22" 2>/dev/null || echo "0")
    echo -e "${CYAN}├─ Active SSH connections: ${GREEN}$ssh_count${NC}"
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Generate UUID for V2Ray
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null || \
        od -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}'
    fi
}

# Generate SSL certificate for Stunnel
generate_ssl_cert() {
    local cert_file="$SSL_CERT_DIR/stunnel.pem"
    
    if [[ -f "$cert_file" ]]; then
        log_message "WARNING" "SSL certificate already exists"
        echo -en "${YELLOW}🔄 Regenerate SSL certificate? [y/N]: ${NC}"
        read -r regenerate
        if [[ ! "$regenerate" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    log_message "INFO" "Generating self-signed SSL certificate"
    mkdir -p "$SSL_CERT_DIR"
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    if openssl req -new -x509 -days 365 -nodes \
        -out "$cert_file" \
        -keyout "$cert_file" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=$server_ip" &>/dev/null; then
        
        chmod 600 "$cert_file"
        log_message "SUCCESS" "SSL certificate generated successfully"
        return 0
    else
        log_message "ERROR" "Failed to generate SSL certificate"
        return 1
    fi
}

# Setup Stunnel
setup_stunnel() {
    if ! get_user_confirmation "Configure Stunnel SSL tunnel"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 🔒 Configure Stunnel SSL ===${NC}"
    
    # Check dependencies
    if ! command -v stunnel4 &> /dev/null; then
        log_message "ERROR" "Stunnel4 is not installed"
        echo -e "${RED}Please run 'Install Dependencies' first.${NC}"
        return 1
    fi
    
    # Create directories
    mkdir -p /etc/stunnel /var/log/stunnel4 /var/run/stunnel4
    
    # Generate SSL certificate
    log_message "INFO" "Setting up SSL certificate"
    if ! generate_ssl_cert; then
        return 1
    fi
    
    # Create Stunnel configuration
    log_message "INFO" "Creating Stunnel configuration"
    cat > "$STUNNEL_CONF" << 'EOF'
; Stunnel configuration - Professional SSH Manager
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

; Security settings
options = NO_SSLv2
options = NO_SSLv3
options = CIPHER_SERVER_PREFERENCE
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256

; Logging
debug = 4
output = /var/log/stunnel4/stunnel.log

; SSH SSL tunnel service
[ssh-ssl]
accept = 443
connect = 127.0.0.1:22
EOF
    
    # Create systemd service
    log_message "INFO" "Setting up Stunnel systemd service"
    cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for SSH connections
After=network.target syslog.target

[Service]
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
Type=forking
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Start and enable service
    systemctl daemon-reload
    if systemctl enable stunnel4 && systemctl restart stunnel4; then
        sleep 2
        if systemctl is-active --quiet stunnel4; then
            log_message "SUCCESS" "Stunnel service started successfully"
            
            # Show connection info
            local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
            echo -e "\n${GREEN}✅ Stunnel SSL Setup Complete!${NC}"
            echo -e "${BLUE}┌─────────────────────────────────────────┐${NC}"
            echo -e "${BLUE}│           SSL TUNNEL DETAILS            │${NC}"
            echo -e "${BLUE}├─────────────────────────────────────────┤${NC}"
            echo -e "${BLUE}│ ${WHITE}Server IP:${NC} ${GREEN}$server_ip${NC}"
            echo -e "${BLUE}│ ${WHITE}SSL Port:${NC}  ${GREEN}443${NC}"
            echo -e "${BLUE}│ ${WHITE}SSH Port:${NC}  ${GREEN}22${NC}"
            echo -e "${BLUE}│ ${WHITE}Tunnel:${NC}   ${GREEN}$server_ip:443 → localhost:22${NC}"
            echo -e "${BLUE}└─────────────────────────────────────────┘${NC}"
        else
            log_message "ERROR" "Stunnel service failed to start"
            systemctl status stunnel4 --no-pager
        fi
    else
        log_message "ERROR" "Failed to configure Stunnel service"
    fi
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Setup V2Ray
setup_v2ray() {
    if ! get_user_confirmation "Configure V2Ray proxy server"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 🚀 Configure V2Ray ===${NC}"
    
    # Check V2Ray installation
    if [[ ! -f "/usr/local/bin/v2ray" ]]; then
        log_message "ERROR" "V2Ray is not installed"
        echo -e "${RED}Please run 'Install Dependencies' first.${NC}"
        return 1
    fi
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    # Generate UUIDs
    log_message "INFO" "Generating UUIDs for V2Ray protocols"
    local vmess_uuid=$(generate_uuid)
    local vless_uuid=$(generate_uuid)
    
    echo -e "${WHITE}🔑 Generated UUIDs:${NC}"
    echo -e "${CYAN}├─ Vmess UUID: ${GREEN}$vmess_uuid${NC}"
    echo -e "${CYAN}└─ Vless UUID: ${GREEN}$vless_uuid${NC}"
    
    # Create configuration directory
    mkdir -p /usr/local/etc/v2ray /var/log/v2ray
    
    # Create V2Ray configuration
    log_message "INFO" "Creating V2Ray configuration with multiple protocols"
    cat > "$V2RAY_CONF" << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log"
    },
    "inbounds": [
        {
            "tag": "vmess-tcp",
            "port": 8080,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$vmess_uuid",
                        "level": 1,
                        "alterId": 0,
                        "email": "vmess@ssh-manager.local"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp"
            }
        },
        {
            "tag": "vmess-ws",
            "port": 8081,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$vmess_uuid",
                        "level": 1,
                        "alterId": 0,
                        "email": "vmess-ws@ssh-manager.local"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess"
                }
            }
        },
        {
            "tag": "vless-tcp",
            "port": 8082,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$vless_uuid",
                        "level": 0,
                        "email": "vless@ssh-manager.local"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp"
            }
        },
        {
            "tag": "vless-ws",
            "port": 8083,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$vless_uuid",
                        "level": 0,
                        "email": "vless-ws@ssh-manager.local"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
    
    # Create systemd service
    log_message "INFO" "Setting up V2Ray systemd service"
    cat > /etc/systemd/system/v2ray.service << 'EOF'
[Unit]
Description=V2Ray Service - SSH Manager
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    # Start and enable service
    systemctl daemon-reload
    if systemctl enable v2ray && systemctl restart v2ray; then
        sleep 3
        if systemctl is-active --quiet v2ray; then
            log_message "SUCCESS" "V2Ray service started successfully"
            
            # Generate connection URLs
            local vmess_tcp_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-TCP-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8080\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}" | base64 -w 0)
            local vmess_ws_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-WS-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8081\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w 0)
            
            echo -e "\n${GREEN}✅ V2Ray Setup Complete!${NC}"
            echo -e "${WHITE}🌐 V2Ray Configurations:${NC}"
            echo -e "\n${BLUE}1. Vmess TCP (Port 8080):${NC}"
            echo -e "${GREEN}vmess://$vmess_tcp_config${NC}"
            echo -e "\n${BLUE}2. Vmess WebSocket (Port 8081):${NC}"
            echo -e "${GREEN}vmess://$vmess_ws_config${NC}"
            echo -e "\n${BLUE}3. Vless TCP (Port 8082):${NC}"
            echo -e "${GREEN}vless://$vless_uuid@$server_ip:8082?type=tcp&security=none#Vless-TCP-$server_ip${NC}"
            echo -e "\n${BLUE}4. Vless WebSocket (Port 8083):${NC}"
            echo -e "${GREEN}vless://$vless_uuid@$server_ip:8083?type=ws&security=none&path=/vless#Vless-WS-$server_ip${NC}"
            
            # Save configurations
            local config_file="/tmp/v2ray-configs.txt"
            cat > "$config_file" << EOF
V2Ray Configuration Details - SSH Manager
Generated: $(date)
Server IP: $server_ip

UUIDs:
- Vmess: $vmess_uuid
- Vless: $vless_uuid

Connection URLs:
1. vmess://$vmess_tcp_config
2. vmess://$vmess_ws_config  
3. vless://$vless_uuid@$server_ip:8082?type=tcp&security=none#Vless-TCP-$server_ip
4. vless://$vless_uuid@$server_ip:8083?type=ws&security=none&path=/vless#Vless-WS-$server_ip
EOF
            echo -e "\n${CYAN}📄 Configurations saved to: ${GREEN}$config_file${NC}"
        else
            log_message "ERROR" "V2Ray service failed to start"
            systemctl status v2ray --no-pager
        fi
    else
        log_message "ERROR" "Failed to configure V2Ray service"
    fi
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Show connection information
show_connection_info() {
    echo -e "\n${CYAN}=== 📡 Connection Information ===${NC}"
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo -e "\n${WHITE}🌐 Server Information:${NC}"
    echo -e "${BLUE}├─ Public IP:${NC} ${GREEN}$server_ip${NC}"
    echo -e "${BLUE}├─ Hostname:${NC} ${GREEN}$(hostname)${NC}"
    echo -e "${BLUE}└─ OS:${NC} ${GREEN}$(lsb_release -d | cut -f2 2>/dev/null || echo "Unknown")${NC}"
    
    echo -e "\n${WHITE}🔧 Service Ports:${NC}"
    local ports=(22 443 8080 8081 8082 8083)
    for port in "${ports[@]}"; do
        if ss -tlnp | grep -q ":$port "; then
            echo -e "${GREEN}✅ Port $port: Active${NC}"
        else
            echo -e "${RED}❌ Port $port: Not active${NC}"
        fi
    done
    
    echo -e "\n${WHITE}📊 Connection Statistics:${NC}"
    local ssh_count=$(ss -tn state established '( dport = :22 or sport = :22 )' | grep -c ":22" 2>/dev/null || echo "0")
    echo -e "${CYAN}├─ Active SSH connections: ${GREEN}$ssh_count${NC}"
    
    # Show recent SSH attempts
    echo -e "\n${WHITE}🔍 Recent SSH Activity:${NC}"
    if [[ -f "/var/log/auth.log" ]]; then
        tail -5 /var/log/auth.log | grep "sshd" | grep -E "(Accepted|Failed)" | while read -r line; do
            if echo "$line" | grep -q "Accepted"; then
                echo -e "${GREEN}✅ $line${NC}"
            else
                echo -e "${RED}❌ $line${NC}"
            fi
        done
    else
        echo -e "${YELLOW}⚠️  Auth log not available${NC}"
    fi
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Generate config templates
generate_config_templates() {
    if ! get_user_confirmation "Generate configuration templates"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 📄 Generate Config Templates ===${NC}"
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    local template_dir="/tmp/vpn-configs"
    
    mkdir -p "$template_dir"
    log_message "INFO" "Generating configuration templates"
    
    # HTTP Custom template
    cat > "$template_dir/http-custom.ehi" << EOF
{
    "name": "SSH-Manager-$server_ip",
    "proxy_type": 2,
    "proxy_host": "$server_ip",
    "proxy_port": 443,
    "ssh_host": "127.0.0.1",
    "ssh_port": 22,
    "ssh_user": "USERNAME_HERE",
    "ssh_pass": "PASSWORD_HERE",
    "use_ssl": true,
    "payload": "GET / HTTP/1.1[crlf]Host: $server_ip[crlf]Upgrade: websocket[crlf][crlf]"
}
EOF
    
    # HTTP Injector template  
    cat > "$template_dir/http-injector.ehi" << EOF
{
    "name": "SSH-Manager-Injector-$server_ip",
    "proxy_type": 1,
    "proxy_host": "$server_ip", 
    "proxy_port": 443,
    "ssh_host": "127.0.0.1",
    "ssh_port": 22,
    "ssh_user": "USERNAME_HERE",
    "ssh_pass": "PASSWORD_HERE",
    "payload": "GET wss://$server_ip/ HTTP/1.1[crlf]Host: $server_ip[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]",
    "use_ssl": true
}
EOF
    
    # OpenVPN template
    cat > "$template_dir/client.ovpn" << EOF
# SSH Manager - OpenVPN Template
client
dev tun
proto tcp
remote $server_ip 443
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3

# SSH SOCKS proxy configuration
# ssh -D 1080 username@$server_ip -p 443
# Configure applications to use SOCKS proxy: 127.0.0.1:1080
EOF
    
    echo -e "${GREEN}✅ Configuration templates generated!${NC}"
    echo -e "${WHITE}📁 Templates location: ${GREEN}$template_dir/${NC}"
    echo -e "${CYAN}├─ http-custom.ehi${NC}"
    echo -e "${CYAN}├─ http-injector.ehi${NC}"
    echo -e "${CYAN}└─ client.ovpn${NC}"
    
    log_message "SUCCESS" "Config templates generated in $template_dir"
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Generate QR codes
generate_qr_codes() {
    if ! get_user_confirmation "Generate QR codes for V2Ray configurations"; then
        return 1
    fi
    
    echo -e "\n${CYAN}=== 📱 Generate QR Codes ===${NC}"
    
    # Check dependencies
    if ! command -v qrencode &> /dev/null; then
        log_message "ERROR" "qrencode is not installed"
        echo -e "${RED}Please run 'Install Dependencies' first.${NC}"
        return 1
    fi
    
    if [[ ! -f "$V2RAY_CONF" ]]; then
        log_message "ERROR" "V2Ray is not configured"
        echo -e "${RED}Please configure V2Ray first.${NC}"
        return 1
    fi
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    local qr_dir="/tmp/v2ray-qrcodes"
    
    mkdir -p "$qr_dir"
    
    # Extract UUIDs from config
    local vmess_uuid=$(grep -o '"id": *"[^"]*"' "$V2RAY_CONF" | head -1 | sed 's/"id": *"\([^"]*\)"/\1/')
    local vless_uuid=$(grep -o '"id": *"[^"]*"' "$V2RAY_CONF" | tail -1 | sed 's/"id": *"\([^"]*\)"/\1/')
    
    if [[ -z "$vmess_uuid" || -z "$vless_uuid" ]]; then
        log_message "ERROR" "Could not extract UUIDs from V2Ray configuration"
        return 1
    fi
    
    log_message "INFO" "Generating QR codes for V2Ray configurations"
    
    # Generate config strings
    local vmess_tcp_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-TCP-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8080\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}" | base64 -w 0)
    local vmess_ws_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-WS-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8081\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w 0)
    local vless_tcp_config="vless://$vless_uuid@$server_ip:8082?type=tcp&security=none#Vless-TCP-$server_ip"
    local vless_ws_config="vless://$vless_uuid@$server_ip:8083?type=ws&security=none&path=/vless#Vless-WS-$server_ip"
    
    # Generate QR code files
    local configs=("vmess://$vmess_tcp_config:vmess-tcp.png" "vmess://$vmess_ws_config:vmess-ws.png" "$vless_tcp_config:vless-tcp.png" "$vless_ws_config:vless-ws.png")
    
    for config_info in "${configs[@]}"; do
        IFS=':' read -r config_url filename <<< "$config_info"
        if qrencode -o "$qr_dir/$filename" "$config_url"; then
            echo -e "${GREEN}✅ Generated: $filename${NC}"
        else
            log_message "ERROR" "Failed to generate QR code: $filename"
        fi
    done
    
    # Create summary file
    cat > "$qr_dir/qr-summary.txt" << EOF
V2Ray QR Codes - SSH Manager
Generated: $(date)
Server: $server_ip

Files:
- vmess-tcp.png: Vmess TCP configuration
- vmess-ws.png: Vmess WebSocket configuration  
- vless-tcp.png: Vless TCP configuration
- vless-ws.png: Vless WebSocket configuration

Usage: Import QR codes into V2Ray client apps
EOF
    
    echo -e "\n${GREEN}✅ QR codes generated successfully!${NC}"
    echo -e "${WHITE}📁 QR codes location: ${GREEN}$qr_dir/${NC}"
    
    log_message "SUCCESS" "QR codes generated in $qr_dir"
    
    echo -e "\n${YELLOW}📋 Press Enter to continue...${NC}"
    read -r
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 