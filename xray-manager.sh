#!/bin/bash

#==============================================================================
# Professional Xray VLESS+WS+TLS Manager
# Advanced User Management & Monitoring System
# Version: 1.0
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration paths
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_LOG_DIR="/var/log/xray"
XRAY_DATA_DIR="/etc/xray-manager"
USER_DB="$XRAY_DATA_DIR/users.db"
CONFIG_DB="$XRAY_DATA_DIR/config.db"
BACKUP_DIR="$XRAY_DATA_DIR/backups"
LOG_FILE="$XRAY_LOG_DIR/manager.log"

# Default configuration
DEFAULT_DOMAIN="book99.chickenkiller.com"
DEFAULT_TLS_PORT="443"
DEFAULT_HTTP_PORT="80"
DEFAULT_WS_PATH="/vpn"

# Initialize directories and databases
init_manager() {
    mkdir -p "$XRAY_DATA_DIR" "$BACKUP_DIR" "$XRAY_LOG_DIR"
    
    # Create user database if not exists
    if [[ ! -f "$USER_DB" ]]; then
        echo "# UUID|USERNAME|EXPIRY_DATE|MAX_IPS|WS_PATH|CREATED_DATE|STATUS" > "$USER_DB"
    fi
    
    # Create config database if not exists
    if [[ ! -f "$CONFIG_DB" ]]; then
        cat > "$CONFIG_DB" << EOF
DOMAIN=$DEFAULT_DOMAIN
TLS_PORT=$DEFAULT_TLS_PORT
HTTP_PORT=$DEFAULT_HTTP_PORT
DEFAULT_WS_PATH=$DEFAULT_WS_PATH
EOF
    fi
    
    # Set proper permissions
    chmod 600 "$USER_DB" "$CONFIG_DB"
    chown -R nobody:nogroup "$XRAY_LOG_DIR"
    chmod 755 "$XRAY_LOG_DIR"
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "SUCCESS") echo -e "${GREEN}✅ $message${NC}" ;;
        "ERROR") echo -e "${RED}❌ $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "INFO") echo -e "${BLUE}ℹ️  $message${NC}" ;;
    esac
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_DB" ]]; then
        source "$CONFIG_DB"
    fi
}

# Save configuration
save_config() {
    cat > "$CONFIG_DB" << EOF
DOMAIN=${DOMAIN:-$DEFAULT_DOMAIN}
TLS_PORT=${TLS_PORT:-$DEFAULT_TLS_PORT}
HTTP_PORT=${HTTP_PORT:-$DEFAULT_HTTP_PORT}
DEFAULT_WS_PATH=${DEFAULT_WS_PATH:-$DEFAULT_WS_PATH}
EOF
}

# Show banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Professional Xray Manager v1.0                 ║"
    echo "║            VLESS+WebSocket+TLS Management System             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    load_config
    echo -e "${YELLOW}Current Domain: ${GREEN}${DOMAIN}${NC}"
    echo -e "${YELLOW}TLS Port: ${GREEN}${TLS_PORT}${NC} | ${YELLOW}HTTP Port: ${GREEN}${HTTP_PORT}${NC}"
    echo -e "${YELLOW}Default WS Path: ${GREEN}${DEFAULT_WS_PATH}${NC}"
    echo
}

# Generate UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Validate UUID format
validate_uuid() {
    local uuid=$1
    if [[ $uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Check if user exists
user_exists() {
    local uuid=$1
    grep -q "^$uuid|" "$USER_DB" 2>/dev/null
}

# Add user
add_user() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    ADD NEW USER                       ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    # Username
    read -p "Enter username: " username
    if [[ -z "$username" ]]; then
        log_message "ERROR" "Username cannot be empty"
        return 1
    fi
    
    # Check if username already exists
    if grep -q "|$username|" "$USER_DB" 2>/dev/null; then
        log_message "ERROR" "Username '$username' already exists"
        return 1
    fi
    
    # UUID
    echo -e "\n${YELLOW}UUID Options:${NC}"
    echo "1. Generate random UUID"
    echo "2. Enter custom UUID"
    read -p "Choose option [1-2]: " uuid_option
    
    case $uuid_option in
        1)
            uuid=$(generate_uuid)
            echo -e "${GREEN}Generated UUID: $uuid${NC}"
            ;;
        2)
            read -p "Enter UUID: " uuid
            if ! validate_uuid "$uuid"; then
                log_message "ERROR" "Invalid UUID format"
                return 1
            fi
            if user_exists "$uuid"; then
                log_message "ERROR" "UUID already exists"
                return 1
            fi
            ;;
        *)
            log_message "ERROR" "Invalid option"
            return 1
            ;;
    esac
    
    # Expiry date
    echo -e "\n${YELLOW}Expiry Options:${NC}"
    echo "1. 30 days from now"
    echo "2. 60 days from now"
    echo "3. 90 days from now"
    echo "4. Custom date (YYYY-MM-DD)"
    echo "5. Never expires"
    read -p "Choose option [1-5]: " expiry_option
    
    case $expiry_option in
        1) expiry_date=$(date -d "+30 days" "+%Y-%m-%d") ;;
        2) expiry_date=$(date -d "+60 days" "+%Y-%m-%d") ;;
        3) expiry_date=$(date -d "+90 days" "+%Y-%m-%d") ;;
        4)
            read -p "Enter expiry date (YYYY-MM-DD): " expiry_date
            if ! date -d "$expiry_date" >/dev/null 2>&1; then
                log_message "ERROR" "Invalid date format"
                return 1
            fi
            ;;
        5) expiry_date="NEVER" ;;
        *)
            log_message "ERROR" "Invalid option"
            return 1
            ;;
    esac
    
    # Max IPs
    read -p "Maximum number of IPs/devices [1-10, default: 2]: " max_ips
    max_ips=${max_ips:-2}
    if ! [[ "$max_ips" =~ ^[1-9]$|^10$ ]]; then
        log_message "ERROR" "Max IPs must be between 1-10"
        return 1
    fi
    
    # WebSocket path
    read -p "WebSocket path [default: $DEFAULT_WS_PATH]: " ws_path
    ws_path=${ws_path:-$DEFAULT_WS_PATH}
    if [[ ! "$ws_path" =~ ^/.+ ]]; then
        log_message "ERROR" "WebSocket path must start with /"
        return 1
    fi
    
    # Save user to database
    local created_date=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$uuid|$username|$expiry_date|$max_ips|$ws_path|$created_date|ACTIVE" >> "$USER_DB"
    
    # Update Xray configuration
    update_xray_config
    
    log_message "SUCCESS" "User '$username' added successfully"
    
    # Generate connection URLs
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              CONNECTION INFORMATION                   ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    generate_user_links "$uuid"
    
    read -p "Press Enter to continue..."
}

# Delete user
delete_user() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    DELETE USER                        ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    if [[ ! -s "$USER_DB" ]] || [[ $(wc -l < "$USER_DB") -le 1 ]]; then
        log_message "WARNING" "No users found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${YELLOW}Current Users:${NC}"
    list_users_simple
    
    echo
    read -p "Enter username or UUID to delete: " identifier
    if [[ -z "$identifier" ]]; then
        log_message "ERROR" "Username/UUID cannot be empty"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Find user by username or UUID
    local user_line
    if validate_uuid "$identifier"; then
        user_line=$(grep "^$identifier|" "$USER_DB" 2>/dev/null)
    else
        user_line=$(grep "|$identifier|" "$USER_DB" 2>/dev/null)
    fi
    
    if [[ -z "$user_line" ]]; then
        log_message "ERROR" "User not found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    local uuid=$(echo "$user_line" | cut -d'|' -f1)
    local username=$(echo "$user_line" | cut -d'|' -f2)
    
    echo -e "${RED}Are you sure you want to delete user '$username'?${NC}"
    read -p "Type 'DELETE' to confirm: " confirm
    if [[ "$confirm" != "DELETE" ]]; then
        log_message "INFO" "Deletion cancelled"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Remove from database
    local temp_file=$(mktemp)
    grep -v "^$uuid|" "$USER_DB" > "$temp_file"
    mv "$temp_file" "$USER_DB"
    
    # Update Xray configuration
    update_xray_config
    
    log_message "SUCCESS" "User '$username' deleted successfully"
    read -p "Press Enter to continue..."
}

# List users (simple format)
list_users_simple() {
    local count=0
    while IFS='|' read -r uuid username expiry max_ips ws_path created status; do
        [[ "$uuid" =~ ^#.* ]] && continue
        ((count++))
        
        local status_icon
        case $status in
            "ACTIVE") status_icon="${GREEN}●${NC}" ;;
            "EXPIRED") status_icon="${RED}●${NC}" ;;
            "DISABLED") status_icon="${YELLOW}●${NC}" ;;
            *) status_icon="${WHITE}●${NC}" ;;
        esac
        
        printf "  %s %-20s %-12s %s\n" "$status_icon" "$username" "$expiry" "$uuid"
    done < "$USER_DB"
    
    if [[ $count -eq 0 ]]; then
        echo "  No users found"
    fi
}

# List users (detailed)
list_users() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    USER LIST                          ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    if [[ ! -s "$USER_DB" ]] || [[ $(wc -l < "$USER_DB") -le 1 ]]; then
        log_message "WARNING" "No users found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    printf "\n%-3s %-20s %-12s %-8s %-12s %-10s %s\n" "St" "Username" "Expiry" "Max IPs" "WS Path" "Status" "UUID"
    echo "────────────────────────────────────────────────────────────────────────────────────────"
    
    local total_users=0
    local active_users=0
    local expired_users=0
    
    while IFS='|' read -r uuid username expiry max_ips ws_path created status; do
        [[ "$uuid" =~ ^#.* ]] && continue
        ((total_users++))
        
        # Check if expired
        local current_status="$status"
        if [[ "$expiry" != "NEVER" ]] && [[ "$expiry" < "$(date +%Y-%m-%d)" ]]; then
            current_status="EXPIRED"
            ((expired_users++))
        elif [[ "$status" == "ACTIVE" ]]; then
            ((active_users++))
        fi
        
        local status_icon
        case $current_status in
            "ACTIVE") status_icon="${GREEN}●${NC}" ;;
            "EXPIRED") status_icon="${RED}●${NC}" ;;
            "DISABLED") status_icon="${YELLOW}●${NC}" ;;
            *) status_icon="${WHITE}●${NC}" ;;
        esac
        
        printf "%s %-20s %-12s %-8s %-12s %-10s %s\n" \
            "$status_icon" "$username" "$expiry" "$max_ips" "$ws_path" "$current_status" "$uuid"
            
    done < "$USER_DB"
    
    echo "────────────────────────────────────────────────────────────────────────────────────────"
    echo -e "${CYAN}Total: $total_users | Active: $active_users | Expired: $expired_users${NC}"
    
    read -p "Press Enter to continue..."
}

# Generate connection links for a user
generate_user_links() {
    local uuid=$1
    local user_line=$(grep "^$uuid|" "$USER_DB" 2>/dev/null)
    
    if [[ -z "$user_line" ]]; then
        log_message "ERROR" "User not found"
        return 1
    fi
    
    load_config
    
    local username=$(echo "$user_line" | cut -d'|' -f2)
    local ws_path=$(echo "$user_line" | cut -d'|' -f5)
    
    echo -e "\n${YELLOW}📋 Connection Details for: ${GREEN}$username${NC}"
    echo -e "  UUID: ${GREEN}$uuid${NC}"
    echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "  WebSocket Path: ${GREEN}$ws_path${NC}"
    
    # VLESS URLs
    local vless_tls="vless://${uuid}@${DOMAIN}:${TLS_PORT}?type=ws&security=tls&host=${DOMAIN}&path=${ws_path}&allowInsecure=false#${username}-TLS"
    local vless_http="vless://${uuid}@${DOMAIN}:${HTTP_PORT}?type=ws&security=none&host=${DOMAIN}&path=${ws_path}#${username}-HTTP"
    
    echo -e "\n${YELLOW}🔗 Connection URLs:${NC}"
    echo -e "\n${GREEN}Primary (TLS - Port $TLS_PORT):${NC}"
    echo -e "${WHITE}$vless_tls${NC}"
    
    echo -e "\n${GREEN}Fallback (HTTP - Port $HTTP_PORT):${NC}"
    echo -e "${WHITE}$vless_http${NC}"
}

# Show user connection links
show_user_links() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                  USER CONNECTIONS                     ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    if [[ ! -s "$USER_DB" ]] || [[ $(wc -l < "$USER_DB") -le 1 ]]; then
        log_message "WARNING" "No users found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${YELLOW}Select User:${NC}"
    list_users_simple
    
    echo
    read -p "Enter username or UUID: " identifier
    if [[ -z "$identifier" ]]; then
        log_message "ERROR" "Username/UUID cannot be empty"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Find user by username or UUID
    local uuid
    if validate_uuid "$identifier"; then
        uuid="$identifier"
    else
        uuid=$(grep "|$identifier|" "$USER_DB" 2>/dev/null | cut -d'|' -f1)
    fi
    
    if [[ -z "$uuid" ]]; then
        log_message "ERROR" "User not found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    generate_user_links "$uuid"
    read -p "Press Enter to continue..."
}

# Update Xray configuration
update_xray_config() {
    load_config
    
    log_message "INFO" "Updating Xray configuration..."
    
    # Create clients array from user database
    local clients_tls=""
    local clients_http=""
    
    while IFS='|' read -r uuid username expiry max_ips ws_path created status; do
        [[ "$uuid" =~ ^#.* ]] && continue
        
        # Skip expired users
        if [[ "$expiry" != "NEVER" ]] && [[ "$expiry" < "$(date +%Y-%m-%d)" ]]; then
            continue
        fi
        
        # Skip disabled users
        if [[ "$status" != "ACTIVE" ]]; then
            continue
        fi
        
        clients_tls+="{\"id\": \"$uuid\", \"level\": 0, \"email\": \"$username@$DOMAIN\"},"
        clients_http+="{\"id\": \"$uuid\", \"level\": 0, \"email\": \"$username-http@$DOMAIN\"},"
        
    done < "$USER_DB"
    
    # Remove trailing commas
    clients_tls=${clients_tls%,}
    clients_http=${clients_http%,}
    
    # Create new configuration
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
        "clients": [$clients_tls],
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
          "path": "$DEFAULT_WS_PATH",
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
        "clients": [$clients_http],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "$DEFAULT_WS_PATH",
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
    
    # Restart Xray service
    systemctl restart xray
    if systemctl is-active --quiet xray; then
        log_message "SUCCESS" "Xray configuration updated and restarted"
    else
        log_message "ERROR" "Failed to restart Xray service"
    fi
}

# Show online users
show_online_users() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                ONLINE USERS MONITOR                   ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    if [[ ! -f "$XRAY_LOG_DIR/access.log" ]]; then
        log_message "WARNING" "No access log found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Get recent connections (last 5 minutes)
    local recent_time=$(date -d "5 minutes ago" "+%Y/%m/%d %H:%M")
    local online_count=0
    
    echo -e "\n${YELLOW}Recent Connections (Last 5 minutes):${NC}"
    printf "%-20s %-15s %-8s %-20s %s\n" "Username" "IP Address" "Port" "Time" "Duration"
    echo "────────────────────────────────────────────────────────────────────────────────────"
    
    # Parse access log for recent connections
    if [[ -f "$XRAY_LOG_DIR/access.log" ]]; then
        tail -n 1000 "$XRAY_LOG_DIR/access.log" | while read -r log_line; do
            if [[ "$log_line" =~ email:.*@.* ]]; then
                local timestamp=$(echo "$log_line" | awk '{print $1" "$2}' | sed 's/\[//' | sed 's/\]//')
                local email=$(echo "$log_line" | grep -o 'email:[^@]*@[^[:space:]]*' | cut -d':' -f2)
                local username=$(echo "$email" | cut -d'@' -f1)
                local ip=$(echo "$log_line" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | head -1)
                local port=$(echo "$log_line" | grep -o ':[0-9]\{1,5\}' | head -1 | sed 's/://')
                
                if [[ "$timestamp" > "$recent_time" ]]; then
                    printf "%-20s %-15s %-8s %-20s %s\n" "$username" "$ip" "$port" "$timestamp" "Active"
                    ((online_count++))
                fi
            fi
        done
    fi
    
    echo "────────────────────────────────────────────────────────────────────────────────────"
    echo -e "${GREEN}Online Users: $online_count${NC}"
    
    # Show port statistics
    echo -e "\n${YELLOW}Port Statistics:${NC}"
    if command -v ss >/dev/null 2>&1; then
        local tls_connections=$(ss -tn sport = :$TLS_PORT | grep -c ESTAB 2>/dev/null || echo "0")
        local http_connections=$(ss -tn sport = :$HTTP_PORT | grep -c ESTAB 2>/dev/null || echo "0")
        echo -e "  TLS Port ($TLS_PORT): ${GREEN}$tls_connections connections${NC}"
        echo -e "  HTTP Port ($HTTP_PORT): ${GREEN}$http_connections connections${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Domain and port management
manage_domain_ports() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              DOMAIN & PORT MANAGEMENT                 ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    load_config
    
    echo -e "\n${YELLOW}Current Configuration:${NC}"
    echo -e "  Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "  TLS Port: ${GREEN}$TLS_PORT${NC}"
    echo -e "  HTTP Port: ${GREEN}$HTTP_PORT${NC}"
    echo -e "  Default WS Path: ${GREEN}$DEFAULT_WS_PATH${NC}"
    
    echo -e "\n${YELLOW}Options:${NC}"
    echo "1. Change domain"
    echo "2. Change TLS port"
    echo "3. Change HTTP port"
    echo "4. Change default WebSocket path"
    echo "5. Apply changes and restart Xray"
    echo "6. Back to main menu"
    
    read -p "Choose option [1-6]: " option
    
    case $option in
        1)
            read -p "Enter new domain: " new_domain
            if [[ -n "$new_domain" ]]; then
                DOMAIN="$new_domain"
                log_message "INFO" "Domain changed to: $DOMAIN"
            fi
            ;;
        2)
            read -p "Enter new TLS port [443]: " new_port
            new_port=${new_port:-443}
            if [[ "$new_port" =~ ^[1-9][0-9]{0,4}$ ]] && [[ $new_port -le 65535 ]]; then
                TLS_PORT="$new_port"
                log_message "INFO" "TLS port changed to: $TLS_PORT"
            else
                log_message "ERROR" "Invalid port number"
            fi
            ;;
        3)
            read -p "Enter new HTTP port [80]: " new_port
            new_port=${new_port:-80}
            if [[ "$new_port" =~ ^[1-9][0-9]{0,4}$ ]] && [[ $new_port -le 65535 ]]; then
                HTTP_PORT="$new_port"
                log_message "INFO" "HTTP port changed to: $HTTP_PORT"
            else
                log_message "ERROR" "Invalid port number"
            fi
            ;;
        4)
            read -p "Enter new default WebSocket path: " new_path
            if [[ "$new_path" =~ ^/.+ ]]; then
                DEFAULT_WS_PATH="$new_path"
                log_message "INFO" "Default WebSocket path changed to: $DEFAULT_WS_PATH"
            else
                log_message "ERROR" "Path must start with /"
            fi
            ;;
        5)
            save_config
            update_xray_config
            log_message "SUCCESS" "Configuration applied and Xray restarted"
            ;;
        6)
            return 0
            ;;
        *)
            log_message "ERROR" "Invalid option"
            ;;
    esac
    
    save_config
    read -p "Press Enter to continue..."
    manage_domain_ports
}

# Backup and restore
backup_users() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                 BACKUP MANAGEMENT                     ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    local backup_file="$BACKUP_DIR/users_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    # Create backup
    tar -czf "$backup_file" -C "$XRAY_DATA_DIR" users.db config.db 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        log_message "SUCCESS" "Backup created: $backup_file"
        
        # Show backup info
        echo -e "\n${YELLOW}Backup Information:${NC}"
        echo -e "  File: ${GREEN}$backup_file${NC}"
        echo -e "  Size: ${GREEN}$(du -h "$backup_file" | cut -f1)${NC}"
        echo -e "  Date: ${GREEN}$(date)${NC}"
        
        # Clean old backups (keep last 10)
        local backup_count=$(ls -1 "$BACKUP_DIR"/users_backup_*.tar.gz 2>/dev/null | wc -l)
        if [[ $backup_count -gt 10 ]]; then
            ls -1t "$BACKUP_DIR"/users_backup_*.tar.gz | tail -n +11 | xargs rm -f
            log_message "INFO" "Cleaned old backups (kept latest 10)"
        fi
    else
        log_message "ERROR" "Failed to create backup"
    fi
    
    read -p "Press Enter to continue..."
}

# Show usage logs
show_usage_logs() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                   USAGE LOGS                         ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    if [[ ! -f "$XRAY_LOG_DIR/access.log" ]]; then
        log_message "WARNING" "No access log found"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "\n${YELLOW}Options:${NC}"
    echo "1. Show today's logs"
    echo "2. Show last 100 entries"
    echo "3. Show logs for specific user"
    echo "4. Show error logs"
    echo "5. Back to main menu"
    
    read -p "Choose option [1-5]: " option
    
    case $option in
        1)
            local today=$(date +%Y/%m/%d)
            echo -e "\n${YELLOW}Today's Access Logs:${NC}"
            grep "$today" "$XRAY_LOG_DIR/access.log" | tail -20
            ;;
        2)
            echo -e "\n${YELLOW}Last 100 Access Log Entries:${NC}"
            tail -100 "$XRAY_LOG_DIR/access.log"
            ;;
        3)
            read -p "Enter username: " username
            if [[ -n "$username" ]]; then
                echo -e "\n${YELLOW}Logs for user '$username':${NC}"
                grep "$username@" "$XRAY_LOG_DIR/access.log" | tail -20
            fi
            ;;
        4)
            echo -e "\n${YELLOW}Error Logs:${NC}"
            if [[ -f "$XRAY_LOG_DIR/error.log" ]]; then
                tail -20 "$XRAY_LOG_DIR/error.log"
            else
                echo "No error log found"
            fi
            ;;
        5)
            return 0
            ;;
        *)
            log_message "ERROR" "Invalid option"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    show_usage_logs
}

# System status
show_system_status() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                  SYSTEM STATUS                       ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    # Xray service status
    echo -e "\n${YELLOW}🔍 Xray Service:${NC}"
    if systemctl is-active --quiet xray; then
        echo -e "  ${GREEN}✅ Status: Running${NC}"
        local uptime=$(systemctl show xray -p ActiveEnterTimestamp --value)
        echo -e "  ${CYAN}📅 Started: $(date -d "$uptime" 2>/dev/null || echo "Unknown")${NC}"
    else
        echo -e "  ${RED}❌ Status: Not Running${NC}"
    fi
    
    # Port status
    echo -e "\n${YELLOW}🔍 Port Status:${NC}"
    load_config
    for port in $TLS_PORT $HTTP_PORT; do
        if ss -tlnp | grep -q ":$port "; then
            echo -e "  ${GREEN}✅ Port $port: Open${NC}"
        else
            echo -e "  ${RED}❌ Port $port: Closed${NC}"
        fi
    done
    
    # SSL certificate
    echo -e "\n${YELLOW}🔍 SSL Certificate:${NC}"
    if [[ -f "/usr/local/etc/xray/ssl/cert.crt" ]]; then
        local cert_info=$(openssl x509 -in /usr/local/etc/xray/ssl/cert.crt -noout -subject -dates 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            echo -e "  ${GREEN}✅ SSL Certificate: Valid${NC}"
            local expiry=$(echo "$cert_info" | grep "Not After" | cut -d'=' -f2)
            echo -e "  ${CYAN}📅 Expires: $expiry${NC}"
        else
            echo -e "  ${RED}❌ SSL Certificate: Invalid${NC}"
        fi
    else
        echo -e "  ${RED}❌ SSL Certificate: Not found${NC}"
    fi
    
    # User statistics
    echo -e "\n${YELLOW}👥 User Statistics:${NC}"
    if [[ -s "$USER_DB" ]]; then
        local total_users=$(grep -v "^#" "$USER_DB" | wc -l)
        local active_users=0
        local expired_users=0
        
        while IFS='|' read -r uuid username expiry max_ips ws_path created status; do
            [[ "$uuid" =~ ^#.* ]] && continue
            
            if [[ "$expiry" != "NEVER" ]] && [[ "$expiry" < "$(date +%Y-%m-%d)" ]]; then
                ((expired_users++))
            elif [[ "$status" == "ACTIVE" ]]; then
                ((active_users++))
            fi
        done < "$USER_DB"
        
        echo -e "  ${CYAN}📊 Total Users: $total_users${NC}"
        echo -e "  ${GREEN}📊 Active Users: $active_users${NC}"
        echo -e "  ${RED}📊 Expired Users: $expired_users${NC}"
    else
        echo -e "  ${YELLOW}📊 No users found${NC}"
    fi
    
    # System resources
    echo -e "\n${YELLOW}💻 System Resources:${NC}"
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    local disk_usage=$(df -h / | awk 'NR==2{print $5}')
    
    echo -e "  ${CYAN}🖥️  CPU Usage: ${cpu_usage}%${NC}"
    echo -e "  ${CYAN}🧠 Memory Usage: ${memory_usage}%${NC}"
    echo -e "  ${CYAN}💾 Disk Usage: ${disk_usage}${NC}"
    
    read -p "Press Enter to continue..."
}

# Remove expired users automatically
cleanup_expired_users() {
    local current_date=$(date +%Y-%m-%d)
    local expired_count=0
    local temp_file=$(mktemp)
    
    # Read header
    head -1 "$USER_DB" > "$temp_file"
    
    # Process users
    while IFS='|' read -r uuid username expiry max_ips ws_path created status; do
        [[ "$uuid" =~ ^#.* ]] && continue
        
        if [[ "$expiry" != "NEVER" ]] && [[ "$expiry" < "$current_date" ]]; then
            ((expired_count++))
            log_message "INFO" "Removing expired user: $username (expired: $expiry)"
        else
            echo "$uuid|$username|$expiry|$max_ips|$ws_path|$created|$status" >> "$temp_file"
        fi
    done < <(tail -n +2 "$USER_DB")
    
    if [[ $expired_count -gt 0 ]]; then
        mv "$temp_file" "$USER_DB"
        update_xray_config
        log_message "SUCCESS" "Removed $expired_count expired users"
    else
        rm -f "$temp_file"
        log_message "INFO" "No expired users found"
    fi
}

# Setup automatic cleanup cron job
setup_cron_cleanup() {
    local cron_job="0 2 * * * /usr/local/bin/xray-manager cleanup-expired"
    
    # Check if cron job already exists
    if ! crontab -l 2>/dev/null | grep -q "xray-manager cleanup-expired"; then
        (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
        log_message "SUCCESS" "Automatic cleanup scheduled (daily at 2 AM)"
    fi
}

# Main menu
show_menu() {
    show_banner
    
    echo -e "${YELLOW}┌─ USER MANAGEMENT ────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} 1. Add New User                                         ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 2. Delete User                                          ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 3. List All Users                                       ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 4. Show User Connection Links                           ${YELLOW}│${NC}"
    echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${YELLOW}┌─ MONITORING & LOGS ──────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} 5. Show Online Users                                    ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 6. View Usage Logs                                      ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 7. System Status                                        ${YELLOW}│${NC}"
    echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${YELLOW}┌─ CONFIGURATION ──────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} 8. Domain & Port Management                             ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 9. Backup Users Database                                ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 10. Cleanup Expired Users                               ${YELLOW}│${NC}"
    echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${YELLOW}┌─ SYSTEM ─────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} 11. Restart Xray Service                                ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 12. Update Configuration                                ${YELLOW}│${NC}"
    echo -e "${YELLOW}│${NC} 0. Exit                                                 ${YELLOW}│${NC}"
    echo -e "${YELLOW}└──────────────────────────────────────────────────────────┘${NC}"
    
    echo
    read -p "Choose option [0-12]: " choice
    
    case $choice in
        1) add_user ;;
        2) delete_user ;;
        3) list_users ;;
        4) show_user_links ;;
        5) show_online_users ;;
        6) show_usage_logs ;;
        7) show_system_status ;;
        8) manage_domain_ports ;;
        9) backup_users ;;
        10) cleanup_expired_users; read -p "Press Enter to continue..." ;;
        11) 
            systemctl restart xray
            if systemctl is-active --quiet xray; then
                log_message "SUCCESS" "Xray service restarted"
            else
                log_message "ERROR" "Failed to restart Xray service"
            fi
            read -p "Press Enter to continue..."
            ;;
        12) update_xray_config; read -p "Press Enter to continue..." ;;
        0) 
            echo -e "\n${GREEN}Thank you for using Xray Manager!${NC}"
            exit 0 
            ;;
        *) 
            log_message "ERROR" "Invalid option"
            read -p "Press Enter to continue..."
            ;;
    esac
}

# Command line interface
case "${1:-}" in
    "cleanup-expired")
        init_manager
        cleanup_expired_users
        exit 0
        ;;
    "add-user")
        init_manager
        add_user
        exit 0
        ;;
    "list-users")
        init_manager
        list_users
        exit 0
        ;;
    *)
        # Check if running as root
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}❌ This script must be run as root${NC}"
            echo -e "${YELLOW}Please run: ${GREEN}sudo $0${NC}"
            exit 1
        fi
        
        # Initialize manager
        init_manager
        
        # Setup automatic cleanup
        setup_cron_cleanup
        
        # Main interactive loop
        while true; do
            show_menu
        done
        ;;
esac 