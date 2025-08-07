#!/bin/bash

#==============================================================================
# Xray-core VLESS+WebSocket+TLS Installation Script
# Description: Professional Xray setup with Let's Encrypt TLS and CDN support
# Compatible with: Debian 11/12, Ubuntu 20.04+
# Author: MK VPN Solutions
# Version: 1.0
#==============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_CONFIG_FILE="$XRAY_CONFIG_DIR/config.json"
XRAY_LOG_DIR="/var/log/xray"
ACME_HOME="/root/.acme.sh"
DOMAIN="vpn.example.com"
WS_PATH="/vpn"
TLS_PORT=443
HTTP_PORT=80

# Show banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Xray-core VLESS+WS+TLS Installer               ║"
    echo "║                Professional VPN Solution                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$XRAY_LOG_DIR/install.log"
    
    case $level in
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        echo -e "${YELLOW}Please run: ${GREEN}sudo $0${NC}"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        log_message "ERROR" "Cannot detect operating system"
        exit 1
    fi
    
    case $OS in
        ubuntu)
            if [[ $VER != "20.04" && $VER != "22.04" && $VER != "24.04" ]]; then
                log_message "WARNING" "Ubuntu $VER may not be fully supported"
            fi
            ;;
        debian)
            if [[ $VER != "11" && $VER != "12" ]]; then
                log_message "WARNING" "Debian $VER may not be fully supported"
            fi
            ;;
        *)
            log_message "ERROR" "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    log_message "SUCCESS" "Detected: $OS $VER"
}

# Get user input
get_domain() {
    echo -e "${YELLOW}Enter your domain name:${NC}"
    echo -e "${CYAN}Example: vpn.yourdomain.com${NC}"
    echo -en "${WHITE}Domain: ${NC}"
    read -r DOMAIN
    
    if [[ -z "$DOMAIN" ]]; then
        log_message "ERROR" "Domain cannot be empty"
        exit 1
    fi
    
    # Validate domain format
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
        log_message "ERROR" "Invalid domain format"
        exit 1
    fi
    
    log_message "INFO" "Domain set to: $DOMAIN"
}

# Update system
update_system() {
    log_message "INFO" "Updating system packages..."
    
    apt update -qq
    apt upgrade -y -qq
    apt install -y curl wget unzip tar socat cron jq ufw net-tools
    
    log_message "SUCCESS" "System updated successfully"
}

# Install Xray-core
install_xray() {
    log_message "INFO" "Installing latest Xray-core..."
    
    # Get latest version
    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    if [[ -z "$XRAY_VERSION" ]]; then
        log_message "ERROR" "Failed to get Xray version"
        exit 1
    fi
    
    log_message "INFO" "Installing Xray-core $XRAY_VERSION"
    
    # Download and install
    cd /tmp
    wget -q "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-64.zip"
    unzip -q Xray-linux-64.zip
    
    # Install binaries
    mkdir -p /usr/local/bin
    mv xray /usr/local/bin/
    chmod +x /usr/local/bin/xray
    
    # Create directories
    mkdir -p "$XRAY_CONFIG_DIR"
    mkdir -p "$XRAY_LOG_DIR"
    mkdir -p /usr/local/share/xray
    
    # Install geoip and geosite
    mv geoip.dat geosite.dat /usr/local/share/xray/
    
    # Clean up
    rm -f Xray-linux-64.zip
    
    log_message "SUCCESS" "Xray-core $XRAY_VERSION installed"
}

# Install acme.sh for Let's Encrypt
install_acme() {
    log_message "INFO" "Installing acme.sh for SSL certificates..."
    
    if [[ ! -f "$ACME_HOME/acme.sh" ]]; then
        curl https://get.acme.sh | sh -s email=admin@$DOMAIN
        source ~/.bashrc
        log_message "SUCCESS" "acme.sh installed"
    else
        log_message "INFO" "acme.sh already installed"
    fi
}

# Issue SSL certificate
issue_certificate() {
    log_message "INFO" "Issuing SSL certificate for $DOMAIN..."
    
    # Stop any service using port 80
    systemctl stop nginx 2>/dev/null
    systemctl stop apache2 2>/dev/null
    
    # Issue certificate using standalone mode
    $ACME_HOME/acme.sh --issue -d $DOMAIN --standalone --force
    
    if [[ $? -eq 0 ]]; then
        # Install certificate
        mkdir -p /usr/local/etc/xray/ssl
        $ACME_HOME/acme.sh --install-cert -d $DOMAIN \
            --key-file /usr/local/etc/xray/ssl/private.key \
            --fullchain-file /usr/local/etc/xray/ssl/cert.crt \
            --reloadcmd "systemctl restart xray"
        
        chmod 644 /usr/local/etc/xray/ssl/cert.crt
        chmod 644 /usr/local/etc/xray/ssl/private.key
        chown nobody:nogroup /usr/local/etc/xray/ssl/private.key
        chown nobody:nogroup /usr/local/etc/xray/ssl/cert.crt
        
        log_message "SUCCESS" "SSL certificate issued and installed"
    else
        log_message "ERROR" "Failed to issue SSL certificate"
        log_message "WARNING" "Please ensure:"
        echo -e "${YELLOW}  1. Domain $DOMAIN points to this server's IP${NC}"
        echo -e "${YELLOW}  2. Port 80 is accessible from the internet${NC}"
        echo -e "${YELLOW}  3. No other web server is running${NC}"
        exit 1
    fi
}

# Generate UUID
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Create Xray configuration
create_xray_config() {
    log_message "INFO" "Creating Xray configuration..."
    
    # Generate UUID
    local uuid=$(generate_uuid)
    
    # Create main config with VLESS+WS+TLS on 443 and fallback HTTP on 80
    cat > "$XRAY_CONFIG_FILE" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "$XRAY_LOG_DIR/access.log",
    "error": "$XRAY_LOG_DIR/error.log"
  },
  "inbounds": [
    {
      "port": $TLS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0,
            "email": "user@$DOMAIN"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/cert.crt",
              "keyFile": "/usr/local/etc/xray/ssl/private.key"
            }
          ],
          "serverName": "$DOMAIN",
          "alpn": ["h2", "http/1.1"]
        },
        "wsSettings": {
          "path": "$WS_PATH",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": $HTTP_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0,
            "email": "user-http@$DOMAIN"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "$WS_PATH",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
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
    
    # Save UUID for later use
    echo "$uuid" > /usr/local/etc/xray/uuid.txt
    
    log_message "SUCCESS" "Xray configuration created with UUID: $uuid"
}

# Create systemd service
create_systemd_service() {
    log_message "INFO" "Creating systemd service..."
    
    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable xray
    
    log_message "SUCCESS" "Systemd service created and enabled"
}

# Configure firewall
configure_firewall() {
    log_message "INFO" "Configuring firewall..."
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (current session)
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Enable firewall
    ufw --force enable
    
    log_message "SUCCESS" "Firewall configured - only ports 22, 80, 443 open"
}

# Apply system tuning
apply_system_tuning() {
    log_message "INFO" "Applying system tuning for high performance..."
    
    # Backup original files
    cp /etc/security/limits.conf /etc/security/limits.conf.bak
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
    # Set ulimits for high connection count
    cat >> /etc/security/limits.conf << 'EOF'

# Xray performance tuning
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
root soft nproc 1000000
root hard nproc 1000000
EOF
    
    # Set kernel parameters
    cat >> /etc/sysctl.conf << 'EOF'

# Xray performance tuning
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
vm.swappiness = 10
fs.file-max = 2000000
EOF
    
    # Apply sysctl settings
    sysctl -p
    
    log_message "SUCCESS" "System tuning applied for 50+ concurrent devices"
}

# Start Xray service
start_xray() {
    log_message "INFO" "Starting Xray service..."
    
    systemctl start xray
    
    if systemctl is-active --quiet xray; then
        log_message "SUCCESS" "Xray service started successfully"
    else
        log_message "ERROR" "Failed to start Xray service"
        echo -e "${YELLOW}Checking logs...${NC}"
        journalctl -u xray --no-pager -l
        exit 1
    fi
}

# Generate connection info
generate_connection_info() {
    local uuid=$(cat /usr/local/etc/xray/uuid.txt)
    local server_ip=$(curl -s ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo
    log_message "SUCCESS" "Xray installation completed successfully!"
    
    echo -e "\n${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              XRAY CONNECTION INFORMATION              ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    
    echo -e "${YELLOW}Server Details:${NC}"
    echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "  Server IP: ${GREEN}$server_ip${NC}"
    echo -e "  Protocol: ${GREEN}VLESS${NC}"
    echo -e "  Transport: ${GREEN}WebSocket${NC}"
    echo -e "  Path: ${GREEN}$WS_PATH${NC}"
    echo -e "  UUID: ${GREEN}$uuid${NC}"
    
    echo -e "\n${YELLOW}Connection URLs:${NC}"
    
    # VLESS+WS+TLS (Primary - Port 443)
    local vless_tls="vless://${uuid}@${DOMAIN}:443?type=ws&security=tls&host=${DOMAIN}&path=${WS_PATH}#MKVPN-TLS"
    echo -e "${GREEN}Primary (TLS):${NC}"
    echo -e "${WHITE}$vless_tls${NC}"
    
    # VLESS+WS (Fallback - Port 80)
    local vless_http="vless://${uuid}@${DOMAIN}:80?type=ws&security=none&host=${DOMAIN}&path=${WS_PATH}#MKVPN-HTTP"
    echo -e "\n${GREEN}Fallback (HTTP):${NC}"
    echo -e "${WHITE}$vless_http${NC}"
    
    echo -e "\n${YELLOW}CDN Configuration (Cloudflare):${NC}"
    echo -e "  1. Add DNS record: ${GREEN}$DOMAIN${NC} → ${GREEN}$server_ip${NC}"
    echo -e "  2. Set Cloudflare proxy status: ${GREEN}Proxied (Orange Cloud)${NC}"
    echo -e "  3. SSL/TLS mode: ${GREEN}Full (Strict)${NC}"
    
    echo -e "\n${YELLOW}Client Configuration:${NC}"
    echo -e "  Host/SNI: ${GREEN}$DOMAIN${NC}"
    echo -e "  Port: ${GREEN}443${NC} (TLS) or ${GREEN}80${NC} (HTTP)"
    echo -e "  WebSocket Path: ${GREEN}$WS_PATH${NC}"
    echo -e "  Allow Insecure: ${GREEN}false${NC}"
    
    echo -e "\n${CYAN}════════════════════════════════════════════════════════${NC}"
    
    # Save to file
    cat > /root/xray-connection-info.txt << EOF
XRAY CONNECTION INFORMATION
Generated: $(date)

Domain: $DOMAIN
Server IP: $server_ip
UUID: $uuid

Primary (TLS): $vless_tls
Fallback (HTTP): $vless_http

Configuration saved to: /usr/local/etc/xray/config.json
Logs location: $XRAY_LOG_DIR/
Service control: systemctl {start|stop|restart|status} xray
EOF
    
    echo -e "\n${CYAN}Connection info saved to: ${GREEN}/root/xray-connection-info.txt${NC}"
}

# Main installation function
main() {
    show_banner
    check_root
    detect_os
    
    echo -e "${YELLOW}This script will install Xray-core with:${NC}"
    echo -e "  • ${GREEN}VLESS + WebSocket + TLS${NC}"
    echo -e "  • ${GREEN}Let's Encrypt SSL certificate${NC}"
    echo -e "  • ${GREEN}CDN/Cloudflare support${NC}"
    echo -e "  • ${GREEN}System optimization for 50+ devices${NC}"
    echo
    
    read -p "Do you want to continue? [Y/n]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]?$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    get_domain
    update_system
    install_xray
    install_acme
    issue_certificate
    create_xray_config
    create_systemd_service
    configure_firewall
    apply_system_tuning
    start_xray
    generate_connection_info
    
    echo -e "\n${GREEN}🎉 Xray installation completed successfully!${NC}"
    echo -e "${CYAN}Use the connection URLs above to configure your clients.${NC}"
}

# Run main function
main "$@" 