#!/bin/bash

#==============================================================================
# SSH/VPN Manager Script
# Description: Comprehensive tool for managing SSH accounts, Stunnel, and V2Ray
# Compatible with: Ubuntu 18.04, 20.04, 22.04
# Author: VPN Manager
# Version: 1.0
#==============================================================================

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
LOG_FILE="/var/log/ssh-manager.log"
STUNNEL_CONF="/etc/stunnel/stunnel.conf"
V2RAY_CONF="/usr/local/etc/v2ray/config.json"
SSL_CERT_DIR="/etc/stunnel"

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_FILE"
}

# Initialize log file
init_logging() {
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 644 "$LOG_FILE"
    fi
    log_message "INFO" "SSH Manager started"
}

# Display header
show_header() {
    clear
    echo -e "${CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    SSH/VPN Manager v1.0                     ║
║              Stunnel + V2Ray + SSH Management               ║
╚══════════════════════════════════════════════════════════════╝
${NC}"
}

# Display main menu
show_menu() {
    echo -e "${BLUE}
┌─────────────────────────────────────────────────────────────┐
│                        MAIN MENU                           │
├─────────────────────────────────────────────────────────────┤
│  1) Create SSH Account                                      │
│  2) Delete SSH Account                                      │
│  3) List Active SSH Users                                  │
│  4) Monitor Online Users                                   │
│  5) Install Dependencies                                   │
│  6) Configure and Start Stunnel                          │
│  7) Configure and Start V2Ray                            │
│  8) Show Connection Information                           │
│  9) Generate Config Templates                             │
│ 10) Generate QR Codes                                     │
│  0) Exit                                                   │
└─────────────────────────────────────────────────────────────┘
${NC}"
    echo -en "${YELLOW}Please select an option [0-10]: ${NC}"
}

# Validate input
validate_input() {
    local input=$1
    local type=$2
    
    case $type in
        "username")
            if [[ ! "$input" =~ ^[a-zA-Z0-9_-]+$ ]] || [[ ${#input} -lt 3 ]] || [[ ${#input} -gt 32 ]]; then
                return 1
            fi
            ;;
        "password")
            if [[ ${#input} -lt 6 ]]; then
                return 1
            fi
            ;;
        "days")
            if [[ ! "$input" =~ ^[0-9]+$ ]] || [[ $input -lt 1 ]] || [[ $input -gt 365 ]]; then
                return 1
            fi
            ;;
    esac
    return 0
}

# Create SSH account
create_ssh_account() {
    echo -e "\n${CYAN}=== Create SSH Account ===${NC}"
    
    # Get username
    while true; do
        echo -en "${YELLOW}Enter username (3-32 chars, alphanumeric + _ -): ${NC}"
        read -r username
        
        if validate_input "$username" "username"; then
            # Check if user already exists
            if id "$username" &>/dev/null; then
                echo -e "${RED}Error: User '$username' already exists${NC}"
                continue
            fi
            break
        else
            echo -e "${RED}Error: Invalid username format${NC}"
        fi
    done
    
    # Get password
    while true; do
        echo -en "${YELLOW}Enter password (minimum 6 characters): ${NC}"
        read -rs password
        echo
        echo -en "${YELLOW}Confirm password: ${NC}"
        read -rs password_confirm
        echo
        
        if [[ "$password" != "$password_confirm" ]]; then
            echo -e "${RED}Error: Passwords do not match${NC}"
            continue
        fi
        
        if validate_input "$password" "password"; then
            break
        else
            echo -e "${RED}Error: Password must be at least 6 characters${NC}"
        fi
    done
    
    # Get expiration days
    while true; do
        echo -en "${YELLOW}Enter expiration in days (1-365): ${NC}"
        read -r days
        
        if validate_input "$days" "days"; then
            break
        else
            echo -e "${RED}Error: Please enter a number between 1 and 365${NC}"
        fi
    done
    
    # Create user
    echo -e "${BLUE}Creating user account...${NC}"
    
    if useradd -m -s /bin/bash "$username" 2>/dev/null; then
        echo -e "${GREEN}✓ User created successfully${NC}"
        log_message "INFO" "User '$username' created"
    else
        echo -e "${RED}✗ Failed to create user${NC}"
        log_message "ERROR" "Failed to create user '$username'"
        return 1
    fi
    
    # Set password
    if echo "$username:$password" | chpasswd; then
        echo -e "${GREEN}✓ Password set successfully${NC}"
        log_message "INFO" "Password set for user '$username'"
    else
        echo -e "${RED}✗ Failed to set password${NC}"
        log_message "ERROR" "Failed to set password for user '$username'"
        return 1
    fi
    
    # Set expiration
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    if chage -E "$expire_date" "$username"; then
        echo -e "${GREEN}✓ Expiration set to $expire_date${NC}"
        log_message "INFO" "Expiration set for user '$username' to $expire_date"
    else
        echo -e "${RED}✗ Failed to set expiration${NC}"
        log_message "ERROR" "Failed to set expiration for user '$username'"
    fi
    
    echo -e "\n${GREEN}SSH Account Created Successfully!${NC}"
    echo -e "${CYAN}Username: ${NC}$username"
    echo -e "${CYAN}Password: ${NC}$password"
    echo -e "${CYAN}Expires: ${NC}$expire_date"
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Delete SSH account
delete_ssh_account() {
    echo -e "\n${CYAN}=== Delete SSH Account ===${NC}"
    
    # List existing users (excluding system users)
    echo -e "${BLUE}Existing SSH users:${NC}"
    local users=($(awk -F: '$3 >= 1000 && $3 != 65534 { print $1 }' /etc/passwd))
    
    if [[ ${#users[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No SSH users found${NC}"
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
        return
    fi
    
    for i in "${!users[@]}"; do
        echo -e "${CYAN}$((i+1))) ${users[i]}${NC}"
    done
    
    echo -en "\n${YELLOW}Enter username to delete: ${NC}"
    read -r username
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
        return
    fi
    
    # Confirm deletion
    echo -en "${RED}Are you sure you want to delete user '$username'? (y/N): ${NC}"
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if userdel -r "$username" 2>/dev/null; then
            echo -e "${GREEN}✓ User '$username' deleted successfully${NC}"
            log_message "INFO" "User '$username' deleted"
        else
            echo -e "${RED}✗ Failed to delete user '$username'${NC}"
            log_message "ERROR" "Failed to delete user '$username'"
        fi
    else
        echo -e "${YELLOW}Deletion cancelled${NC}"
    fi
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# List active SSH users
list_ssh_users() {
    echo -e "\n${CYAN}=== Active SSH Users ===${NC}"
    
    echo -e "${BLUE}┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐${NC}"
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
        echo -e "${YELLOW}No SSH users found${NC}"
    fi
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Monitor online users
monitor_online_users() {
    echo -e "\n${CYAN}=== Online Users Monitor ===${NC}"
    
    echo -e "${BLUE}Currently logged in users:${NC}"
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
        echo -e "${YELLOW}No users currently logged in${NC}"
    fi
    
    echo -e "\n${BLUE}SSH connection summary:${NC}"
    local ssh_count=$(ss -tn state established '( dport = :22 or sport = :22 )' | grep -c ":22")
    echo -e "${CYAN}Active SSH connections: ${GREEN}$ssh_count${NC}"
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Install dependencies
install_dependencies() {
    echo -e "\n${CYAN}=== Install Dependencies ===${NC}"
    
    echo -e "${BLUE}Updating package lists...${NC}"
    if apt update -q; then
        echo -e "${GREEN}✓ Package lists updated${NC}"
        log_message "INFO" "Package lists updated"
    else
        echo -e "${RED}✗ Failed to update package lists${NC}"
        log_message "ERROR" "Failed to update package lists"
        return 1
    fi
    
    local packages=("openssh-server" "stunnel4" "openssl" "curl" "wget" "unzip" "qrencode" "jq")
    
    echo -e "${BLUE}Installing required packages...${NC}"
    for package in "${packages[@]}"; do
        echo -e "${YELLOW}Installing $package...${NC}"
        if apt install -y "$package" -q; then
            echo -e "${GREEN}✓ $package installed successfully${NC}"
            log_message "INFO" "$package installed"
        else
            echo -e "${RED}✗ Failed to install $package${NC}"
            log_message "ERROR" "Failed to install $package"
        fi
    done
    
    # Install V2Ray
    echo -e "${BLUE}Installing V2Ray...${NC}"
    if [[ ! -f "/usr/local/bin/v2ray" ]]; then
        cd /tmp || exit 1
        if curl -L -o v2ray-installer.sh https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh; then
            chmod +x v2ray-installer.sh
            if bash v2ray-installer.sh; then
                echo -e "${GREEN}✓ V2Ray installed successfully${NC}"
                log_message "INFO" "V2Ray installed"
            else
                echo -e "${RED}✗ Failed to install V2Ray${NC}"
                log_message "ERROR" "Failed to install V2Ray"
            fi
            rm -f v2ray-installer.sh
        else
            echo -e "${RED}✗ Failed to download V2Ray installer${NC}"
            log_message "ERROR" "Failed to download V2Ray installer"
        fi
    else
        echo -e "${GREEN}✓ V2Ray already installed${NC}"
    fi
    
    # Enable SSH service
    echo -e "${BLUE}Enabling SSH service...${NC}"
    if systemctl enable ssh && systemctl start ssh; then
        echo -e "${GREEN}✓ SSH service enabled and started${NC}"
        log_message "INFO" "SSH service enabled"
    else
        echo -e "${RED}✗ Failed to enable SSH service${NC}"
        log_message "ERROR" "Failed to enable SSH service"
    fi
    
    echo -e "\n${GREEN}Dependencies installation completed!${NC}"
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Generate SSL certificate for Stunnel
generate_ssl_cert() {
    local cert_file="$SSL_CERT_DIR/stunnel.pem"
    
    if [[ -f "$cert_file" ]]; then
        echo -e "${YELLOW}SSL certificate already exists at $cert_file${NC}"
        echo -en "${YELLOW}Do you want to regenerate it? (y/N): ${NC}"
        read -r regenerate
        if [[ ! "$regenerate" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    echo -e "${BLUE}Generating self-signed SSL certificate...${NC}"
    
    # Create SSL directory if it doesn't exist
    mkdir -p "$SSL_CERT_DIR"
    
    # Get server IP
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    # Generate certificate
    if openssl req -new -x509 -days 365 -nodes \
        -out "$cert_file" \
        -keyout "$cert_file" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=$server_ip" 2>/dev/null; then
        
        chmod 600 "$cert_file"
        echo -e "${GREEN}✓ SSL certificate generated successfully${NC}"
        log_message "INFO" "SSL certificate generated at $cert_file"
        return 0
    else
        echo -e "${RED}✗ Failed to generate SSL certificate${NC}"
        log_message "ERROR" "Failed to generate SSL certificate"
        return 1
    fi
}

# Setup Stunnel
setup_stunnel() {
    echo -e "\n${CYAN}=== Configure and Start Stunnel ===${NC}"
    
    # Check if stunnel4 is installed
    if ! command -v stunnel4 &> /dev/null; then
        echo -e "${RED}Stunnel4 is not installed. Please run 'Install Dependencies' first.${NC}"
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
        return 1
    fi
    
    # Create Stunnel directory
    mkdir -p /etc/stunnel
    mkdir -p /var/log/stunnel4
    
    # Generate SSL certificate
    if ! generate_ssl_cert; then
        echo -e "${RED}Failed to generate SSL certificate${NC}"
        return 1
    fi
    
    # Create Stunnel configuration
    echo -e "${BLUE}Creating Stunnel configuration...${NC}"
    
    cat > "$STUNNEL_CONF" << 'EOF'
; Stunnel configuration file
; SSL tunnel from port 443 to SSH port 22

cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
pid = /var/run/stunnel4/stunnel.pid

; Logging
debug = 4
output = /var/log/stunnel4/stunnel.log

; Security settings
options = NO_SSLv2
options = NO_SSLv3
options = CIPHER_SERVER_PREFERENCE
ciphers = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256

; Service definition
[ssh]
accept = 443
connect = 127.0.0.1:22
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ Stunnel configuration created${NC}"
        log_message "INFO" "Stunnel configuration created"
    else
        echo -e "${RED}✗ Failed to create Stunnel configuration${NC}"
        log_message "ERROR" "Failed to create Stunnel configuration"
        return 1
    fi
    
    # Create systemd service file
    echo -e "${BLUE}Creating Stunnel systemd service...${NC}"
    
    cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for network daemons
Documentation=man:stunnel
DefaultDependencies=no
After=network.target
After=syslog.target

[Service]
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
Type=forking
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Create PID directory
    mkdir -p /var/run/stunnel4
    
    # Reload systemd and start service
    systemctl daemon-reload
    
    if systemctl enable stunnel4 && systemctl restart stunnel4; then
        sleep 2
        if systemctl is-active --quiet stunnel4; then
            echo -e "${GREEN}✓ Stunnel service started successfully${NC}"
            log_message "INFO" "Stunnel service started"
        else
            echo -e "${RED}✗ Stunnel service failed to start${NC}"
            echo -e "${YELLOW}Checking logs...${NC}"
            systemctl status stunnel4 --no-pager
            log_message "ERROR" "Stunnel service failed to start"
            return 1
        fi
    else
        echo -e "${RED}✗ Failed to enable/start Stunnel service${NC}"
        log_message "ERROR" "Failed to enable/start Stunnel service"
        return 1
    fi
    
    # Show connection info
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    echo -e "\n${GREEN}Stunnel Setup Completed Successfully!${NC}"
    echo -e "${CYAN}SSL Tunnel Configuration:${NC}"
    echo -e "${BLUE}Server IP: ${GREEN}$server_ip${NC}"
    echo -e "${BLUE}SSL Port: ${GREEN}443${NC}"
    echo -e "${BLUE}SSH Port: ${GREEN}22${NC}"
    echo -e "${BLUE}Connection: ${GREEN}$server_ip:443 → localhost:22${NC}"
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Generate UUID for V2Ray
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        # Fallback UUID generation
        cat /proc/sys/kernel/random/uuid 2>/dev/null || \
        od -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}'
    fi
}

# Setup V2Ray
setup_v2ray() {
    echo -e "\n${CYAN}=== Configure and Start V2Ray ===${NC}"
    
    # Check if V2Ray is installed
    if [[ ! -f "/usr/local/bin/v2ray" ]]; then
        echo -e "${RED}V2Ray is not installed. Please run 'Install Dependencies' first.${NC}"
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
        return 1
    fi
    
    # Get server IP
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    # Generate UUIDs
    local vmess_uuid=$(generate_uuid)
    local vless_uuid=$(generate_uuid)
    
    echo -e "${BLUE}Generated UUIDs:${NC}"
    echo -e "${CYAN}Vmess UUID: ${GREEN}$vmess_uuid${NC}"
    echo -e "${CYAN}Vless UUID: ${GREEN}$vless_uuid${NC}"
    
    # Create V2Ray configuration directory
    mkdir -p /usr/local/etc/v2ray
    
    # Create V2Ray configuration
    echo -e "${BLUE}Creating V2Ray configuration...${NC}"
    
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
                        "email": "vmess@example.com"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "none"
                    }
                }
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
                        "email": "vmess-ws@example.com"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/vmess",
                    "headers": {}
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
                        "email": "vless@example.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "none"
                    }
                }
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
                        "email": "vless-ws@example.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/vless",
                    "headers": {}
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "ip": [
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "100.64.0.0/10",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.0.0.0/24",
                    "192.0.2.0/24",
                    "192.168.0.0/16",
                    "198.18.0.0/15",
                    "198.51.100.0/24",
                    "203.0.113.0/24",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ V2Ray configuration created${NC}"
        log_message "INFO" "V2Ray configuration created"
    else
        echo -e "${RED}✗ Failed to create V2Ray configuration${NC}"
        log_message "ERROR" "Failed to create V2Ray configuration"
        return 1
    fi
    
    # Create log directory
    mkdir -p /var/log/v2ray
    
    # Create systemd service file
    echo -e "${BLUE}Creating V2Ray systemd service...${NC}"
    
    cat > /etc/systemd/system/v2ray.service << 'EOF'
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and start service
    systemctl daemon-reload
    
    if systemctl enable v2ray && systemctl restart v2ray; then
        sleep 3
        if systemctl is-active --quiet v2ray; then
            echo -e "${GREEN}✓ V2Ray service started successfully${NC}"
            log_message "INFO" "V2Ray service started"
        else
            echo -e "${RED}✗ V2Ray service failed to start${NC}"
            echo -e "${YELLOW}Checking logs...${NC}"
            systemctl status v2ray --no-pager
            log_message "ERROR" "V2Ray service failed to start"
            return 1
        fi
    else
        echo -e "${RED}✗ Failed to enable/start V2Ray service${NC}"
        log_message "ERROR" "Failed to enable/start V2Ray service"
        return 1
    fi
    
    # Generate connection strings
    echo -e "\n${GREEN}V2Ray Setup Completed Successfully!${NC}"
    echo -e "${CYAN}=== V2Ray Configuration Details ===${NC}"
    
    # Vmess TCP configuration
    local vmess_tcp_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-TCP-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8080\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}" | base64 -w 0)
    
    # Vmess WS configuration
    local vmess_ws_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-WS-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8081\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w 0)
    
    echo -e "\n${BLUE}1. Vmess TCP (Port 8080):${NC}"
    echo -e "${GREEN}vmess://$vmess_tcp_config${NC}"
    
    echo -e "\n${BLUE}2. Vmess WebSocket (Port 8081):${NC}"
    echo -e "${GREEN}vmess://$vmess_ws_config${NC}"
    
    echo -e "\n${BLUE}3. Vless TCP (Port 8082):${NC}"
    echo -e "${GREEN}vless://$vless_uuid@$server_ip:8082?type=tcp&security=none#Vless-TCP-$server_ip${NC}"
    
    echo -e "\n${BLUE}4. Vless WebSocket (Port 8083):${NC}"
    echo -e "${GREEN}vless://$vless_uuid@$server_ip:8083?type=ws&security=none&path=/vless#Vless-WS-$server_ip${NC}"
    
    # Save configurations to file
    local config_file="/tmp/v2ray-configs.txt"
    cat > "$config_file" << EOF
V2Ray Configuration Details
Generated on: $(date)
Server IP: $server_ip

Vmess UUID: $vmess_uuid
Vless UUID: $vless_uuid

1. Vmess TCP (Port 8080):
vmess://$vmess_tcp_config

2. Vmess WebSocket (Port 8081):
vmess://$vmess_ws_config

3. Vless TCP (Port 8082):
vless://$vless_uuid@$server_ip:8082?type=tcp&security=none#Vless-TCP-$server_ip

4. Vless WebSocket (Port 8083):
vless://$vless_uuid@$server_ip:8083?type=ws&security=none&path=/vless#Vless-WS-$server_ip
EOF
    
    echo -e "\n${CYAN}Configuration saved to: ${GREEN}$config_file${NC}"
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Show connection information
show_connection_info() {
    echo -e "\n${CYAN}=== Connection Information ===${NC}"
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo -e "${BLUE}Server IP Address: ${GREEN}$server_ip${NC}"
    echo -e "${BLUE}Server Hostname: ${GREEN}$(hostname)${NC}"
    echo -e "\n${CYAN}=== Service Status ===${NC}"
    
    # Check SSH service
    if systemctl is-active --quiet ssh; then
        echo -e "${GREEN}✓ SSH Service: Running (Port 22)${NC}"
    else
        echo -e "${RED}✗ SSH Service: Not running${NC}"
    fi
    
    # Check Stunnel service
    if systemctl is-active --quiet stunnel4; then
        echo -e "${GREEN}✓ Stunnel Service: Running (Port 443 → 22)${NC}"
    else
        echo -e "${RED}✗ Stunnel Service: Not running${NC}"
    fi
    
    # Check V2Ray service
    if systemctl is-active --quiet v2ray; then
        echo -e "${GREEN}✓ V2Ray Service: Running${NC}"
        echo -e "  ${CYAN}- Vmess TCP: Port 8080${NC}"
        echo -e "  ${CYAN}- Vmess WS: Port 8081${NC}"
        echo -e "  ${CYAN}- Vless TCP: Port 8082${NC}"
        echo -e "  ${CYAN}- Vless WS: Port 8083${NC}"
    else
        echo -e "${RED}✗ V2Ray Service: Not running${NC}"
    fi
    
    echo -e "\n${CYAN}=== Active SSH Connections ===${NC}"
    local ssh_connections=$(ss -tn state established '( dport = :22 or sport = :22 )' | grep -c ":22" 2>/dev/null || echo "0")
    echo -e "${BLUE}Current SSH connections: ${GREEN}$ssh_connections${NC}"
    
    # Show port usage
    echo -e "\n${CYAN}=== Port Usage ===${NC}"
    local ports=(22 443 8080 8081 8082 8083)
    for port in "${ports[@]}"; do
        if ss -tlnp | grep -q ":$port "; then
            echo -e "${GREEN}✓ Port $port: In use${NC}"
        else
            echo -e "${RED}✗ Port $port: Available${NC}"
        fi
    done
    
    # Show recent connections from logs
    echo -e "\n${CYAN}=== Recent SSH Login Attempts ===${NC}"
    if [[ -f "/var/log/auth.log" ]]; then
        tail -10 /var/log/auth.log | grep "sshd" | grep -E "(Accepted|Failed)" | tail -5 | while read -r line; do
            if echo "$line" | grep -q "Accepted"; then
                echo -e "${GREEN}✓ $line${NC}"
            else
                echo -e "${RED}✗ $line${NC}"
            fi
        done
    else
        echo -e "${YELLOW}Auth log not available${NC}"
    fi
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Generate config templates for HTTP Custom/Injector
generate_config_templates() {
    echo -e "\n${CYAN}=== Generate Config Templates ===${NC}"
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    local template_dir="/tmp/vpn-configs"
    
    mkdir -p "$template_dir"
    
    echo -e "${BLUE}Generating configuration templates...${NC}"
    
    # HTTP Custom .ehi template
    cat > "$template_dir/http-custom.ehi" << EOF
{
    "name": "SSH-Stunnel-$server_ip",
    "proxy_type": 2,
    "proxy_host": "$server_ip",
    "proxy_port": 443,
    "proxy_user": "",
    "proxy_pass": "",
    "ssh_host": "127.0.0.1",
    "ssh_port": 22,
    "ssh_user": "USERNAME_HERE",
    "ssh_pass": "PASSWORD_HERE",
    "use_http_proxy": true,
    "http_proxy_host": "$server_ip",
    "http_proxy_port": 443,
    "use_ssl": true,
    "payload": "GET / HTTP/1.1[crlf]Host: $server_ip[crlf]Upgrade: websocket[crlf][crlf]",
    "sni": "$server_ip"
}
EOF
    
    # HTTP Injector .ehi template
    cat > "$template_dir/http-injector.ehi" << EOF
{
    "name": "SSH-Stunnel-Injector-$server_ip",
    "proxy_type": 1,
    "proxy_host": "$server_ip",
    "proxy_port": 443,
    "ssh_host": "127.0.0.1",
    "ssh_port": 22,
    "ssh_user": "USERNAME_HERE",
    "ssh_pass": "PASSWORD_HERE",
    "payload": "GET wss://$server_ip/ HTTP/1.1[crlf]Host: $server_ip[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]",
    "use_ssl": true,
    "sni": "$server_ip"
}
EOF
    
    # OpenVPN template
    cat > "$template_dir/client.ovpn" << EOF
# OpenVPN Client Configuration Template
# For use with SSH tunnel setup

client
dev tun
proto tcp
remote $server_ip 443
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3
cipher AES-256-CBC
auth SHA256

# SSH tunnel configuration
# Use this with SSH SOCKS proxy through Stunnel

# Example usage:
# 1. Connect using SSH: ssh -D 1080 username@$server_ip -p 443
# 2. Configure your applications to use SOCKS proxy: 127.0.0.1:1080

# Note: This is a template. You need to add proper certificates
# and configure according to your OpenVPN server setup.

# Uncomment and configure if you have proper OpenVPN server:
# ca ca.crt
# cert client.crt
# key client.key
# tls-auth ta.key 1
EOF
    
    # Shadowsocks-like template for manual configuration
    cat > "$template_dir/shadowsocks-manual.json" << EOF
{
    "server": "$server_ip",
    "server_port": 443,
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "password": "YOUR_SSH_PASSWORD",
    "timeout": 300,
    "method": "aes-256-gcm",
    "fast_open": false,
    "workers": 1,
    "prefer_ipv6": false,
    "plugin": "obfs-local",
    "plugin_opts": "obfs=tls;obfs-host=$server_ip",
    "_comment": "This is a template for SSH over Stunnel SSL tunnel"
}
EOF
    
    # Create a comprehensive connection guide
    cat > "$template_dir/connection-guide.txt" << EOF
=== VPN/SSH Connection Guide ===
Generated on: $(date)
Server IP: $server_ip

=== SSH Direct Connection ===
Host: $server_ip
Port: 22
Protocol: SSH

Command: ssh username@$server_ip

=== SSH over SSL (Stunnel) ===
Host: $server_ip
Port: 443
Protocol: SSH over SSL

Command: ssh username@$server_ip -p 443
(Configure your SSH client to use SSL/TLS)

=== V2Ray Connections ===
Vmess TCP: Port 8080
Vmess WebSocket: Port 8081
Vless TCP: Port 8082
Vless WebSocket: Port 8083

=== HTTP Custom/Injector Setup ===
1. Import the .ehi files in your HTTP Custom or HTTP Injector app
2. Replace USERNAME_HERE and PASSWORD_HERE with your actual credentials
3. Connect using the imported configuration

=== Configuration Files Generated ===
- http-custom.ehi: HTTP Custom configuration
- http-injector.ehi: HTTP Injector configuration
- client.ovpn: OpenVPN template
- shadowsocks-manual.json: Manual proxy configuration
- connection-guide.txt: This guide

=== Security Notes ===
- Change default passwords immediately
- Use strong, unique passwords for each account
- Enable SSH key authentication when possible
- Monitor connection logs regularly
- Update system packages frequently

=== Troubleshooting ===
- If connection fails, check if services are running
- Verify firewall settings allow required ports
- Check server logs for error messages
- Ensure correct credentials are being used
EOF
    
    echo -e "${GREEN}✓ Configuration templates generated successfully!${NC}"
    echo -e "${CYAN}Templates saved to: ${GREEN}$template_dir/${NC}"
    echo -e "\n${BLUE}Generated files:${NC}"
    echo -e "${CYAN}- http-custom.ehi${NC}"
    echo -e "${CYAN}- http-injector.ehi${NC}"
    echo -e "${CYAN}- client.ovpn${NC}"
    echo -e "${CYAN}- shadowsocks-manual.json${NC}"
    echo -e "${CYAN}- connection-guide.txt${NC}"
    
    log_message "INFO" "Config templates generated in $template_dir"
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Generate QR codes for V2Ray configurations
generate_qr_codes() {
    echo -e "\n${CYAN}=== Generate QR Codes ===${NC}"
    
    # Check if qrencode is installed
    if ! command -v qrencode &> /dev/null; then
        echo -e "${RED}qrencode is not installed. Please run 'Install Dependencies' first.${NC}"
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
        return 1
    fi
    
    # Check if V2Ray config exists
    if [[ ! -f "$V2RAY_CONF" ]]; then
        echo -e "${RED}V2Ray is not configured. Please run 'Configure and Start V2Ray' first.${NC}"
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r
        return 1
    fi
    
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    local qr_dir="/tmp/v2ray-qrcodes"
    
    mkdir -p "$qr_dir"
    
    # Extract UUIDs from existing config
    local vmess_uuid=$(grep -o '"id": *"[^"]*"' "$V2RAY_CONF" | head -1 | sed 's/"id": *"\([^"]*\)"/\1/')
    local vless_uuid=$(grep -o '"id": *"[^"]*"' "$V2RAY_CONF" | tail -1 | sed 's/"id": *"\([^"]*\)"/\1/')
    
    if [[ -z "$vmess_uuid" || -z "$vless_uuid" ]]; then
        echo -e "${RED}Could not extract UUIDs from V2Ray configuration${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Generating QR codes...${NC}"
    
    # Generate Vmess configurations
    local vmess_tcp_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-TCP-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8080\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}" | base64 -w 0)
    local vmess_ws_config=$(echo -n "{\"v\":\"2\",\"ps\":\"Vmess-WS-$server_ip\",\"add\":\"$server_ip\",\"port\":\"8081\",\"id\":\"$vmess_uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w 0)
    
    # Generate Vless configurations
    local vless_tcp_config="vless://$vless_uuid@$server_ip:8082?type=tcp&security=none#Vless-TCP-$server_ip"
    local vless_ws_config="vless://$vless_uuid@$server_ip:8083?type=ws&security=none&path=/vless#Vless-WS-$server_ip"
    
    # Generate QR codes
    echo -e "${YELLOW}1. Generating Vmess TCP QR code...${NC}"
    if qrencode -o "$qr_dir/vmess-tcp.png" "vmess://$vmess_tcp_config"; then
        echo -e "${GREEN}✓ Vmess TCP QR code saved${NC}"
    else
        echo -e "${RED}✗ Failed to generate Vmess TCP QR code${NC}"
    fi
    
    echo -e "${YELLOW}2. Generating Vmess WebSocket QR code...${NC}"
    if qrencode -o "$qr_dir/vmess-ws.png" "vmess://$vmess_ws_config"; then
        echo -e "${GREEN}✓ Vmess WS QR code saved${NC}"
    else
        echo -e "${RED}✗ Failed to generate Vmess WS QR code${NC}"
    fi
    
    echo -e "${YELLOW}3. Generating Vless TCP QR code...${NC}"
    if qrencode -o "$qr_dir/vless-tcp.png" "$vless_tcp_config"; then
        echo -e "${GREEN}✓ Vless TCP QR code saved${NC}"
    else
        echo -e "${RED}✗ Failed to generate Vless TCP QR code${NC}"
    fi
    
    echo -e "${YELLOW}4. Generating Vless WebSocket QR code...${NC}"
    if qrencode -o "$qr_dir/vless-ws.png" "$vless_ws_config"; then
        echo -e "${GREEN}✓ Vless WS QR code saved${NC}"
    else
        echo -e "${RED}✗ Failed to generate Vless WS QR code${NC}"
    fi
    
    # Generate ASCII QR codes for terminal display
    echo -e "\n${BLUE}Generating ASCII QR codes for display...${NC}"
    
    echo -e "\n${CYAN}=== Vmess TCP QR Code ===${NC}"
    qrencode -t ANSIUTF8 "vmess://$vmess_tcp_config" 2>/dev/null || echo -e "${YELLOW}ASCII QR display not available${NC}"
    
    # Create summary file
    cat > "$qr_dir/qr-summary.txt" << EOF
V2Ray QR Codes Summary
Generated on: $(date)
Server IP: $server_ip

QR Code Files:
- vmess-tcp.png: Vmess TCP configuration
- vmess-ws.png: Vmess WebSocket configuration  
- vless-tcp.png: Vless TCP configuration
- vless-ws.png: Vless WebSocket configuration

Configuration Strings:
1. Vmess TCP: vmess://$vmess_tcp_config
2. Vmess WS: vmess://$vmess_ws_config
3. Vless TCP: $vless_tcp_config
4. Vless WS: $vless_ws_config

Usage:
1. Save QR code images to your device
2. Open V2Ray client app (V2RayNG, V2RayN, etc.)
3. Scan QR code or import configuration string
4. Connect using the imported configuration
EOF
    
    echo -e "\n${GREEN}QR codes generated successfully!${NC}"
    echo -e "${CYAN}QR codes saved to: ${GREEN}$qr_dir/${NC}"
    echo -e "\n${BLUE}Generated files:${NC}"
    echo -e "${CYAN}- vmess-tcp.png${NC}"
    echo -e "${CYAN}- vmess-ws.png${NC}"
    echo -e "${CYAN}- vless-tcp.png${NC}"
    echo -e "${CYAN}- vless-ws.png${NC}"
    echo -e "${CYAN}- qr-summary.txt${NC}"
    
    log_message "INFO" "QR codes generated in $qr_dir"
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Main execution
main() {
    check_root
    init_logging
    
    while true; do
        show_header
        show_menu
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
            0) 
                echo -e "\n${GREEN}Thank you for using SSH/VPN Manager!${NC}"
                log_message "INFO" "SSH Manager exited"
                exit 0
                ;;
            *)
                echo -e "\n${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Start the script
main "$@" 