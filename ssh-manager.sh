#!/bin/bash

#==============================================================================
# SSH Manager Script v3.0 - Professional SSH/VPN Management Solution
# Description: Automated setup for OpenSSH, Stunnel SSL, and V2Ray (HTTP Injector optimized)
# Compatible with: Ubuntu 18.04, 20.04, 22.04
# Author: SSH Manager Team
# Version: 3.0
#==============================================================================

# Script configuration
SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Configuration paths
readonly LOG_FILE="/var/log/ssh-manager.log"
readonly STUNNEL_CONF="/etc/stunnel/stunnel.conf"
readonly V2RAY_CONF="/usr/local/etc/v2ray/config.json"
readonly SSL_CERT_DIR="/etc/stunnel"
readonly INSTALL_MARKER="/etc/ssh-manager.installed"

# Initialize logging
init_logging() {
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    log_message "INFO" "SSH Manager started - Version 3.0"
}

# Enhanced logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Display colored messages
show_message() {
    local type=$1
    local message=$2
    case $type in
        "success") echo -e "${GREEN}✅ $message${NC}" ;;
        "error") echo -e "${RED}❌ $message${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "info") echo -e "${BLUE}ℹ️  $message${NC}" ;;
        "progress") echo -e "${YELLOW}🔄 $message${NC}" ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_message "error" "This script must be run as root"
        echo -e "${YELLOW}Please run: ${GREEN}sudo $0${NC}"
        exit 1
    fi
}

# Show welcome banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              SSH Manager Script v3.0                       ║"
    echo "║         OpenSSH + Stunnel + V2Ray Management              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Get user confirmation
get_confirmation() {
    local prompt="${1:-Do you want to continue?}"
    echo -en "${YELLOW}$prompt [Y/N]: ${NC}"
    read -r response
    case $response in
        [Yy]|[Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

# Install dependencies
install_dependencies() {
    show_message "info" "Installing dependencies..."
    
    local packages=("openssh-server" "stunnel4" "openssl" "curl" "wget" "unzip" "jq" "net-tools")
    
    show_message "progress" "Updating package lists..."
    apt update -qq || {
        show_message "error" "Failed to update package lists"
        return 1
    }
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package"; then
            show_message "progress" "Installing $package..."
            apt install -y "$package" -qq || {
                show_message "error" "Failed to install $package"
                log_message "ERROR" "Failed to install $package"
            }
        else
            show_message "success" "$package already installed"
        fi
    done
    
    # Install V2Ray
    if [[ ! -f "/usr/local/bin/v2ray" ]]; then
        show_message "progress" "Installing V2Ray..."
        bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) || {
            show_message "error" "Failed to install V2Ray"
            return 1
        }
    else
        show_message "success" "V2Ray already installed"
    fi
    
    show_message "success" "All dependencies installed successfully"
    return 0
}

# Configure Stunnel
configure_stunnel() {
    show_message "info" "Configuring Stunnel SSL tunnel..."
    
    # Prompt for custom port
    local stunnel_port
    while true; do
        echo -en "${YELLOW}Enter Stunnel port (e.g., 443, 8443) [443]: ${NC}"
        read -r stunnel_port
        stunnel_port=${stunnel_port:-443}
        
        if [[ "$stunnel_port" =~ ^[0-9]+$ ]] && [ "$stunnel_port" -ge 1 ] && [ "$stunnel_port" -le 65535 ]; then
            break
        else
            show_message "error" "Invalid port. Please enter a number between 1 and 65535"
        fi
    done
    
    # Create SSL certificate
    mkdir -p "$SSL_CERT_DIR"
    if [[ ! -f "$SSL_CERT_DIR/stunnel.pem" ]]; then
        show_message "progress" "Generating SSL certificate..."
        openssl req -new -x509 -days 365 -nodes \
            -out "$SSL_CERT_DIR/stunnel.pem" \
            -keyout "$SSL_CERT_DIR/stunnel.pem" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$(hostname)" 2>/dev/null
        chmod 600 "$SSL_CERT_DIR/stunnel.pem"
    fi
    
    # Create Stunnel configuration
    cat > "$STUNNEL_CONF" << EOF
; Stunnel configuration for SSH Manager
cert = $SSL_CERT_DIR/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid
output = /var/log/stunnel4/stunnel.log

[ssh]
accept = $stunnel_port
connect = 127.0.0.1:22
EOF
    
    # Create necessary directories
    mkdir -p /var/run/stunnel4
    mkdir -p /var/log/stunnel4
    
    # Enable and start Stunnel
    systemctl enable stunnel4 >/dev/null 2>&1
    systemctl restart stunnel4
    
    if systemctl is-active --quiet stunnel4; then
        show_message "success" "Stunnel configured successfully"
        echo -e "${GREEN}Stunnel Details:${NC}"
        echo -e "  ${CYAN}Port: ${WHITE}$stunnel_port${NC}"
        echo -e "  ${CYAN}SSH Connection: ${WHITE}ssl://$(curl -s ipinfo.io/ip):$stunnel_port${NC}"
        
        # Save configuration
        echo "STUNNEL_PORT=$stunnel_port" >> "$INSTALL_MARKER"
    else
        show_message "error" "Failed to start Stunnel"
        return 1
    fi
}

# Generate UUID for V2Ray
generate_uuid() {
    cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen
}

# Configure V2Ray optimized for HTTP Injector
configure_v2ray() {
    show_message "info" "Configuring V2Ray (HTTP Injector optimized)..."
    
    # Prompt for custom port
    local v2ray_port
    while true; do
        echo -en "${YELLOW}Enter V2Ray port (e.g., 80, 443, 8080) [80]: ${NC}"
        read -r v2ray_port
        v2ray_port=${v2ray_port:-80}
        
        if [[ "$v2ray_port" =~ ^[0-9]+$ ]] && [ "$v2ray_port" -ge 1 ] && [ "$v2ray_port" -le 65535 ]; then
            break
        else
            show_message "error" "Invalid port"
        fi
    done
    
    # Prompt for SNI/Host
    echo -en "${YELLOW}Enter SNI/Host domain (for CDN/bug-host) [example.com]: ${NC}"
    read -r sni_host
    sni_host=${sni_host:-example.com}
    
    # Generate UUID
    local uuid=$(generate_uuid)
    local server_ip=$(curl -s ipinfo.io/ip)
    
    # Create V2Ray server configuration
    mkdir -p /usr/local/etc/v2ray
    cat > "$V2RAY_CONF" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [{
    "port": $v2ray_port,
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "$uuid",
        "level": 0,
        "email": "sshmanager@v2ray.com"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {
        "path": "/v2ray",
        "headers": {
          "Host": "$sni_host"
        }
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    
    # Create V2Ray client configuration
    local client_config="/tmp/v2ray-client-config.json"
    cat > "$client_config" << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [{
    "port": 1080,
    "protocol": "socks",
    "settings": {
      "auth": "noauth"
    }
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$server_ip",
        "port": $v2ray_port,
        "users": [{
          "id": "$uuid",
          "level": 0,
          "encryption": "none"
        }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {
        "path": "/v2ray",
        "headers": {
          "Host": "$sni_host"
        }
      }
    }
  }]
}
EOF
    
    # Create log directory
    mkdir -p /var/log/v2ray
    
    # Enable and start V2Ray
    systemctl enable v2ray >/dev/null 2>&1
    systemctl restart v2ray
    
    if systemctl is-active --quiet v2ray; then
        show_message "success" "V2Ray configured successfully"
        
        # Generate VLESS URL
        local vless_url="vless://${uuid}@${server_ip}:${v2ray_port}?type=ws&security=none&host=${sni_host}&path=/v2ray#SSHManager"
        
        echo -e "\n${GREEN}════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}V2Ray Server Configuration:${NC}"
        echo -e "${WHITE}Port: $v2ray_port${NC}"
        echo -e "${WHITE}UUID: $uuid${NC}"
        echo -e "${WHITE}SNI/Host: $sni_host${NC}"
        echo -e "${WHITE}Path: /v2ray${NC}"
        echo -e "${WHITE}Protocol: VLESS + WebSocket${NC}"
        echo -e "\n${CYAN}VLESS URL (for HTTP Injector):${NC}"
        echo -e "${GREEN}$vless_url${NC}"
        echo -e "\n${CYAN}Configuration files saved:${NC}"
        echo -e "${WHITE}Server: $V2RAY_CONF${NC}"
        echo -e "${WHITE}Client: $client_config${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════${NC}\n"
        
        # Save configuration
        echo "V2RAY_PORT=$v2ray_port" >> "$INSTALL_MARKER"
        echo "V2RAY_UUID=$uuid" >> "$INSTALL_MARKER"
        echo "V2RAY_HOST=$sni_host" >> "$INSTALL_MARKER"
    else
        show_message "error" "Failed to start V2Ray"
        return 1
    fi
}

# Create SSH account
create_ssh_account() {
    show_message "info" "Creating SSH account..."
    
    # Get username
    echo -en "${YELLOW}Enter username: ${NC}"
    read -r username
    
    if id "$username" &>/dev/null; then
        show_message "error" "User '$username' already exists"
        return 1
    fi
    
    # Get password
    echo -en "${YELLOW}Enter password: ${NC}"
    read -rs password
    echo
    
    # Get expiration
    echo -en "${YELLOW}Enter expiration days (1-365): ${NC}"
    read -r days
    
    # Create user
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    
    # Set expiration
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$expire_date" "$username"
    
    show_message "success" "SSH account created successfully"
    echo -e "${CYAN}Username: ${WHITE}$username${NC}"
    echo -e "${CYAN}Password: ${WHITE}$password${NC}"
    echo -e "${CYAN}Expires: ${WHITE}$expire_date${NC}"
    
    log_message "INFO" "Created SSH account: $username"
}

# Delete SSH account
delete_ssh_account() {
    show_message "info" "Delete SSH account..."
    
    # List users
    echo -e "${CYAN}Existing SSH users:${NC}"
    local users=($(awk -F: '$3 >= 1000 && $3 != 65534 { print $1 }' /etc/passwd))
    
    if [[ ${#users[@]} -eq 0 ]]; then
        show_message "warning" "No SSH users found"
        return
    fi
    
    for i in "${!users[@]}"; do
        echo "  $((i+1))) ${users[i]}"
    done
    
    echo -en "${YELLOW}Enter username to delete: ${NC}"
    read -r username
    
    if id "$username" &>/dev/null; then
        if get_confirmation "Delete user '$username'?"; then
            userdel -r "$username" 2>/dev/null
            show_message "success" "User '$username' deleted"
            log_message "INFO" "Deleted SSH account: $username"
        fi
    else
        show_message "error" "User not found"
    fi
}

# List active users
list_active_users() {
    show_message "info" "Active SSH users:"
    echo -e "${CYAN}Username\tUID\tHome\t\tExpires${NC}"
    echo "----------------------------------------"
    
    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ $uid -ge 1000 && $uid != 65534 && "$shell" != "/usr/sbin/nologin" ]]; then
            local expire=$(chage -l "$user" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
            printf "%-15s %-7s %-15s %s\n" "$user" "$uid" "$home" "$expire"
        fi
    done < /etc/passwd
}

# Monitor online users
monitor_online_users() {
    show_message "info" "Currently logged in users:"
    who
    echo
    show_message "info" "Active SSH connections:"
    ss -tn state established '( dport = :22 or sport = :22 )' | grep -c ":22" | xargs echo "Total connections:"
}

# Restart all services
restart_services() {
    show_message "progress" "Restarting services..."
    
    systemctl restart sshd && show_message "success" "SSH restarted"
    systemctl restart stunnel4 && show_message "success" "Stunnel restarted"
    systemctl restart v2ray && show_message "success" "V2Ray restarted"
}

# View logs
view_logs() {
    echo -e "${CYAN}Select log to view:${NC}"
    echo "1) SSH Manager log"
    echo "2) Stunnel log"
    echo "3) V2Ray log"
    echo "4) SSH auth log"
    
    read -p "Choice: " choice
    
    case $choice in
        1) tail -30 "$LOG_FILE" ;;
        2) tail -30 /var/log/stunnel4/stunnel.log 2>/dev/null || echo "No Stunnel logs found" ;;
        3) tail -30 /var/log/v2ray/error.log 2>/dev/null || echo "No V2Ray logs found" ;;
        4) tail -30 /var/log/auth.log | grep sshd ;;
        *) show_message "error" "Invalid choice" ;;
    esac
}

# Uninstall function
uninstall_all() {
    show_banner
    show_message "warning" "This will remove all components installed by SSH Manager"
    
    if ! get_confirmation "Are you sure you want to uninstall everything?"; then
        return
    fi
    
    show_message "progress" "Stopping services..."
    systemctl stop stunnel4 2>/dev/null
    systemctl stop v2ray 2>/dev/null
    systemctl disable stunnel4 2>/dev/null
    systemctl disable v2ray 2>/dev/null
    
    show_message "progress" "Removing V2Ray..."
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
    
    show_message "progress" "Removing Stunnel..."
    apt remove -y stunnel4 --purge 2>/dev/null
    
    show_message "progress" "Removing configuration files..."
    rm -rf /etc/stunnel
    rm -rf /usr/local/etc/v2ray
    rm -rf /var/log/v2ray
    rm -f "$LOG_FILE"
    rm -f "$INSTALL_MARKER"
    
    # Ask about removing created users
    if get_confirmation "Remove SSH users created by this script?"; then
        # This is a simplified approach - in production, track created users
        show_message "info" "Please manually remove users if needed"
    fi
    
    # Ask about removing the script itself
    if get_confirmation "Remove the SSH Manager script itself?"; then
        rm -f "$SCRIPT_PATH"
        show_message "success" "Uninstall complete. All components removed."
        exit 0
    else
        show_message "success" "Uninstall complete. Script retained."
    fi
}

# Show menu
show_menu() {
    echo -e "${CYAN}┌──────────────────────────────┐${NC}"
    echo -e "${CYAN}│     SSH Manager - Menu       │${NC}"
    echo -e "${CYAN}└──────────────────────────────┘${NC}"
    echo "1. Create SSH Account"
    echo "2. Delete SSH Account"
    echo "3. List Active Users"
    echo "4. Monitor Online Users"
    echo "5. Install Dependencies"
    echo "6. Configure Stunnel"
    echo "7. Configure V2Ray"
    echo "8. Restart Services"
    echo "9. View Logs"
    echo "10. Uninstall All"
    echo "11. Exit"
    echo
    echo -en "${YELLOW}Select option [1-11]: ${NC}"
}

# Main menu loop
menu_loop() {
    while true; do
        show_banner
        show_menu
        read -r choice
        
        case $choice in
            1) create_ssh_account ;;
            2) delete_ssh_account ;;
            3) list_active_users ;;
            4) monitor_online_users ;;
            5) install_dependencies ;;
            6) configure_stunnel ;;
            7) configure_v2ray ;;
            8) restart_services ;;
            9) view_logs ;;
            10) uninstall_all ;;
            11) 
                show_message "info" "Exiting SSH Manager"
                exit 0
                ;;
            *)
                show_message "error" "Invalid option"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
    done
}

# First run installation
first_run_install() {
    show_banner
    echo -e "${YELLOW}Welcome to SSH Manager first-time setup!${NC}\n"
    
    if ! get_confirmation "Do you want to continue with installation?"; then
        show_message "warning" "Installation cancelled"
        exit 0
    fi
    
    # Install dependencies
    if install_dependencies; then
        show_message "success" "Dependencies installed"
    else
        show_message "error" "Failed to install dependencies"
        exit 1
    fi
    
    # Configure Stunnel
    if get_confirmation "Configure Stunnel SSL tunnel?"; then
        configure_stunnel
    fi
    
    # Configure V2Ray
    if get_confirmation "Configure V2Ray (HTTP Injector optimized)?"; then
        configure_v2ray
    fi
    
    # Mark installation complete
    touch "$INSTALL_MARKER"
    
    # Show completion message
    echo
    show_message "success" "Installation and Configuration Completed!"
    echo -e "${GREEN}👋 Welcome to the SSH Manager Script.${NC}"
    echo -e "${CYAN}➤ Type '${WHITE}menu${CYAN}' to get started.${NC}"
    
    # Create convenient menu command
    if [[ ! -f /usr/local/bin/menu ]]; then
        cat > /usr/local/bin/menu << EOF
#!/bin/bash
exec "$SCRIPT_PATH" menu
EOF
        chmod +x /usr/local/bin/menu
    fi
}

# Main function
main() {
    check_root
    init_logging
    
    # Handle command line arguments
    case "${1,,}" in
        --uninstall)
            uninstall_all
            ;;
        menu)
            menu_loop
            ;;
        --first-run|--install)
            first_run_install
            ;;
        "")
            if [[ ! -f "$INSTALL_MARKER" ]]; then
                first_run_install
            else
                menu_loop
            fi
            ;;
        *)
            show_message "error" "Unknown option: $1"
            echo "Usage: $0 [menu|--install|--uninstall]"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@" 