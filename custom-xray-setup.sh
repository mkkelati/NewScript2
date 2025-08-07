#!/bin/bash

#==============================================================================
# Custom Xray VLESS+WebSocket+TLS Setup
# Domain: book99.chickenkiller.com
# Server IP: 46.62.158.46
# UUID: 02c0d760-f565-4eea-a18a-d0f764395ab0
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Fixed Configuration
DOMAIN="book99.chickenkiller.com"
SERVER_IP="46.62.158.46"
UUID="02c0d760-f565-4eea-a18a-d0f764395ab0"
WS_PATH="/vpn"
TLS_PORT=443
HTTP_PORT=80
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_LOG_DIR="/var/log/xray"
ACME_HOME="/root/.acme.sh"

# Logging function
log_message() {
    local level=$1
    local message=$2
    mkdir -p "$XRAY_LOG_DIR"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$XRAY_LOG_DIR/install.log"
    
    case $level in
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
    esac
}

# Show banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Custom Xray VLESS+WS+TLS Setup                 ║"
    echo "║              book99.chickenkiller.com                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "${YELLOW}Server IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "${YELLOW}UUID: ${GREEN}$UUID${NC}"
    echo -e "${YELLOW}WebSocket Path: ${GREEN}$WS_PATH${NC}"
    echo
}

# Root check
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        echo -e "${YELLOW}Please run: ${GREEN}sudo $0${NC}"
        exit 1
    fi
}

# Add domain to hosts file (bypass Cloudflare for local resolution)
setup_local_dns() {
    log_message "INFO" "Setting up local DNS resolution..."
    
    # Remove existing entries
    sed -i "/$DOMAIN/d" /etc/hosts
    
    # Add new entry
    echo "$SERVER_IP $DOMAIN" >> /etc/hosts
    
    log_message "SUCCESS" "Added $DOMAIN -> $SERVER_IP to /etc/hosts"
}

# Update system and install dependencies
install_dependencies() {
    log_message "INFO" "Installing dependencies..."
    
    apt update -qq
    apt upgrade -y -qq
    apt install -y curl wget unzip tar socat cron jq ufw net-tools openssl
    
    log_message "SUCCESS" "Dependencies installed"
}

# Install latest Xray-core
install_xray() {
    log_message "INFO" "Installing latest Xray-core..."
    
    # Get latest version
    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    if [[ -z "$XRAY_VERSION" ]]; then
        XRAY_VERSION="v1.8.4"  # Fallback version
        log_message "WARNING" "Using fallback version: $XRAY_VERSION"
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
    mv geoip.dat geosite.dat /usr/local/share/xray/ 2>/dev/null || true
    
    # Clean up
    rm -f Xray-linux-64.zip *.dat
    
    log_message "SUCCESS" "Xray-core $XRAY_VERSION installed"
}

# Install acme.sh
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
    
    # Stop services that might use port 80
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    
    # Clear any existing certificates
    $ACME_HOME/acme.sh --remove -d $DOMAIN --ecc 2>/dev/null || true
    
    # Issue new certificate using standalone mode
    $ACME_HOME/acme.sh --issue -d $DOMAIN --standalone --keylength ec-256 --force
    
    if [[ $? -eq 0 ]]; then
        # Install certificate
        mkdir -p /usr/local/etc/xray/ssl
        $ACME_HOME/acme.sh --install-cert -d $DOMAIN --ecc \
            --key-file /usr/local/etc/xray/ssl/private.key \
            --fullchain-file /usr/local/etc/xray/ssl/cert.crt \
            --reloadcmd "systemctl restart xray"
        
        # Set proper permissions for Xray user
        chmod 644 /usr/local/etc/xray/ssl/cert.crt
        chmod 644 /usr/local/etc/xray/ssl/private.key
        chown nobody:nogroup /usr/local/etc/xray/ssl/private.key
        chown nobody:nogroup /usr/local/etc/xray/ssl/cert.crt
        
        log_message "SUCCESS" "SSL certificate issued and installed"
        return 0
    else
        log_message "ERROR" "Failed to issue SSL certificate"
        log_message "WARNING" "Continuing with self-signed certificate..."
        
        # Create self-signed certificate as fallback
        openssl req -new -x509 -days 365 -nodes \
            -out /usr/local/etc/xray/ssl/cert.crt \
            -keyout /usr/local/etc/xray/ssl/private.key \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"
        
        chmod 644 /usr/local/etc/xray/ssl/cert.crt
        chmod 644 /usr/local/etc/xray/ssl/private.key
        chown nobody:nogroup /usr/local/etc/xray/ssl/private.key
        chown nobody:nogroup /usr/local/etc/xray/ssl/cert.crt
        
        log_message "WARNING" "Self-signed certificate created"
        return 1
    fi
}

# Create Xray configuration
create_xray_config() {
    log_message "INFO" "Creating Xray configuration..."
    
    cat > "$XRAY_CONFIG_DIR/config.json" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "$XRAY_LOG_DIR/access.log",
    "error": "$XRAY_LOG_DIR/error.log"
  },
  "inbounds": [
    {
      "tag": "vless-tls",
      "port": $TLS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
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
      "tag": "vless-http",
      "port": $HTTP_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
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
      "settings": {},
      "tag": "direct"
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
    
    log_message "SUCCESS" "Xray configuration created"
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
setup_firewall() {
    log_message "INFO" "Configuring firewall..."
    
    # Disable UFW if active to avoid conflicts
    ufw --force disable 2>/dev/null || true
    
    # Clear existing iptables rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Set default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH, HTTP, HTTPS
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    log_message "SUCCESS" "Firewall configured - ports 22, 80, 443 open"
}

# Apply system optimization
optimize_system() {
    log_message "INFO" "Optimizing system for 30+ devices..."
    
    # Backup original files
    cp /etc/security/limits.conf /etc/security/limits.conf.bak 2>/dev/null || true
    cp /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null || true
    
    # Set ulimits
    cat >> /etc/security/limits.conf << 'EOF'

# Xray optimization for 30+ devices
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
root soft nproc 1000000
root hard nproc 1000000
nobody soft nofile 1000000
nobody hard nofile 1000000
EOF
    
    # Optimize kernel parameters
    cat >> /etc/sysctl.conf << 'EOF'

# Xray optimization for high performance
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
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
vm.swappiness = 10
fs.file-max = 2000000
EOF
    
    # Apply settings
    sysctl -p
    
    log_message "SUCCESS" "System optimized for 30+ concurrent devices"
}

# Start Xray service
start_xray() {
    log_message "INFO" "Starting Xray service..."
    
    systemctl start xray
    sleep 3
    
    if systemctl is-active --quiet xray; then
        log_message "SUCCESS" "Xray service started successfully"
        return 0
    else
        log_message "ERROR" "Failed to start Xray service"
        echo -e "${YELLOW}Checking logs...${NC}"
        journalctl -u xray --no-pager -l --since "5 minutes ago"
        return 1
    fi
}

# Run diagnostic checks
run_diagnostics() {
    log_message "INFO" "Running diagnostic checks..."
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                DIAGNOSTIC REPORT                     ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    # Check ports
    echo -e "\n${YELLOW}🔍 Port Status:${NC}"
    for port in 22 80 443; do
        if ss -tlnp | grep -q ":$port "; then
            echo -e "  ${GREEN}✅ Port $port: Open${NC}"
        else
            echo -e "  ${RED}❌ Port $port: Closed${NC}"
        fi
    done
    
    # Check Xray service
    echo -e "\n${YELLOW}🔍 Xray Service:${NC}"
    if systemctl is-active --quiet xray; then
        echo -e "  ${GREEN}✅ Xray: Running${NC}"
    else
        echo -e "  ${RED}❌ Xray: Not running${NC}"
    fi
    
    # Check SSL certificate
    echo -e "\n${YELLOW}🔍 SSL Certificate:${NC}"
    if [[ -f "/usr/local/etc/xray/ssl/cert.crt" ]]; then
        local cert_info=$(openssl x509 -in /usr/local/etc/xray/ssl/cert.crt -noout -subject -dates 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            echo -e "  ${GREEN}✅ SSL Certificate: Valid${NC}"
            echo -e "  ${CYAN}$(echo "$cert_info" | grep "Not After")${NC}"
        else
            echo -e "  ${RED}❌ SSL Certificate: Invalid${NC}"
        fi
    else
        echo -e "  ${RED}❌ SSL Certificate: Not found${NC}"
    fi
    
    # Check DNS resolution
    echo -e "\n${YELLOW}🔍 DNS Resolution:${NC}"
    local resolved_ip=$(getent hosts $DOMAIN | awk '{print $1}')
    if [[ "$resolved_ip" == "$SERVER_IP" ]]; then
        echo -e "  ${GREEN}✅ DNS: $DOMAIN → $SERVER_IP${NC}"
    else
        echo -e "  ${YELLOW}⚠️  DNS: $DOMAIN → $resolved_ip (different from $SERVER_IP)${NC}"
    fi
    
    # Check WebSocket path
    echo -e "\n${YELLOW}🔍 WebSocket Configuration:${NC}"
    if grep -q "\"path\": \"$WS_PATH\"" "$XRAY_CONFIG_DIR/config.json"; then
        echo -e "  ${GREEN}✅ WebSocket Path: $WS_PATH configured${NC}"
    else
        echo -e "  ${RED}❌ WebSocket Path: Not configured properly${NC}"
    fi
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
}

# Generate connection information
generate_connection_info() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              CONNECTION INFORMATION                   ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${YELLOW}📋 Server Details:${NC}"
    echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "  Server IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "  UUID: ${GREEN}$UUID${NC}"
    echo -e "  WebSocket Path: ${GREEN}$WS_PATH${NC}"
    echo -e "  Ports: ${GREEN}443 (TLS), 80 (HTTP)${NC}"
    
    # VLESS URLs
    local vless_tls="vless://${UUID}@${DOMAIN}:443?type=ws&security=tls&host=${DOMAIN}&path=${WS_PATH}&allowInsecure=false#MKVPN-TLS-${DOMAIN}"
    local vless_http="vless://${UUID}@${DOMAIN}:80?type=ws&security=none&host=${DOMAIN}&path=${WS_PATH}#MKVPN-HTTP-${DOMAIN}"
    
    echo -e "\n${YELLOW}🔗 Connection URLs:${NC}"
    echo -e "\n${GREEN}Primary (TLS - Port 443):${NC}"
    echo -e "${WHITE}$vless_tls${NC}"
    
    echo -e "\n${GREEN}Fallback (HTTP - Port 80):${NC}"
    echo -e "${WHITE}$vless_http${NC}"
    
    echo -e "\n${YELLOW}☁️  Cloudflare CDN Setup:${NC}"
    echo -e "  1. DNS A Record: ${GREEN}$DOMAIN${NC} → ${GREEN}$SERVER_IP${NC}"
    echo -e "  2. Proxy Status: ${GREEN}Proxied (Orange Cloud ON)${NC}"
    echo -e "  3. SSL/TLS Mode: ${GREEN}Full (Strict)${NC}"
    echo -e "  4. Always Use HTTPS: ${GREEN}ON${NC}"
    
    echo -e "\n${YELLOW}📱 Client Settings:${NC}"
    echo -e "  Protocol: ${GREEN}VLESS${NC}"
    echo -e "  Transport: ${GREEN}WebSocket${NC}"
    echo -e "  Host/SNI: ${GREEN}$DOMAIN${NC}"
    echo -e "  Path: ${GREEN}$WS_PATH${NC}"
    echo -e "  Allow Insecure: ${GREEN}false${NC}"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    # Save to file
    cat > /root/xray-connection-info.txt << EOF
XRAY CONNECTION INFORMATION
Generated: $(date)
Domain: $DOMAIN
Server IP: $SERVER_IP
UUID: $UUID
WebSocket Path: $WS_PATH

Primary (TLS): $vless_tls
Fallback (HTTP): $vless_http

Cloudflare Setup:
- DNS A Record: $DOMAIN → $SERVER_IP
- Proxy: ON (Orange Cloud)
- SSL/TLS: Full (Strict)

Configuration: $XRAY_CONFIG_DIR/config.json
Logs: $XRAY_LOG_DIR/
Service: systemctl {start|stop|restart|status} xray
EOF
    
    echo -e "\n${CYAN}💾 Connection info saved to: ${GREEN}/root/xray-connection-info.txt${NC}"
}

# Main installation function
main() {
    show_banner
    check_root
    
    echo -e "${YELLOW}This will set up Xray with your custom configuration.${NC}"
    read -p "Continue? [Y/n]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]?$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    
    setup_local_dns
    install_dependencies
    install_xray
    install_acme
    issue_certificate
    create_xray_config
    create_systemd_service
    setup_firewall
    optimize_system
    
    if start_xray; then
        run_diagnostics
        generate_connection_info
        echo -e "\n${GREEN}🎉 Xray setup completed successfully!${NC}"
        echo -e "${CYAN}Use the connection URLs above in your VLESS clients.${NC}"
    else
        echo -e "\n${RED}⚠️  Setup completed but Xray failed to start.${NC}"
        echo -e "${YELLOW}Check the logs above and fix any issues.${NC}"
    fi
}

# Run main function
main "$@" 