# SSH/VPN Manager Script

A comprehensive Bash script for managing SSH accounts, Stunnel SSL tunnels, and V2Ray proxy configurations on Ubuntu servers. This script provides an easy-to-use menu-based interface for setting up and managing VPN/proxy services.

## 🚀 Quick Start

**Install and run with one command:**
```bash
sudo apt update && sudo apt upgrade -y && echo -e "\n\033[1;33mSystem updated successfully!\033[0m" && read -p "Do you want to install SSH/VPN Manager? (y/n): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] && curl -O https://raw.githubusercontent.com/mkkelati/NewScript/main/ssh-vpn-manager.sh && chmod +x ssh-vpn-manager.sh && sudo ./ssh-vpn-manager.sh --first-run || echo "Installation cancelled."
```

## Features

### Core Functionality
- **Menu-based Interface**: Easy-to-use interactive menu system
- **SSH Account Management**: Create, delete, and monitor SSH user accounts
- **Stunnel SSL Tunnel**: Configure SSL tunnels from port 443 to SSH port 22
- **V2Ray Proxy Server**: Auto-configure Vmess and Vless protocols with TCP and WebSocket support
- **Dependency Management**: Automated installation of required packages
- **Connection Monitoring**: Real-time monitoring of active connections and services

### Advanced Features
- **Color-coded Output**: Professional interface with emoji indicators and color coding
- **Progress Feedback**: Real-time installation progress with progress bars and spinners
- **User Confirmation**: Explicit confirmation prompts before system changes
- **Comprehensive Logging**: All activities logged to `/var/log/ssh-manager.log` with timestamps
- **Input Validation**: Secure against malformed input and duplicate users
- **QR Code Generation**: Generate QR codes for V2Ray client configurations
- **Config Templates**: Generate `.ehi` files for HTTP Custom/HTTP Injector apps
- **System Health Check**: Real-time monitoring and status reporting
- **Auto Cleanup**: Automatic cleanup of expired SSH accounts
- **Command System**: Type 'menu', 'status', 'help' commands for quick access

### Security Features
- **SSL Certificate Generation**: Auto-generate self-signed certificates
- **Password Validation**: Enforce strong password requirements
- **Account Expiration**: Set automatic account expiration dates
- **Service Isolation**: Proper service configuration and permissions
- **Logging and Monitoring**: Comprehensive activity tracking

## Compatibility

- **Ubuntu 18.04 LTS**
- **Ubuntu 20.04 LTS** 
- **Ubuntu 22.04 LTS**

## Installation

### Prerequisites
- Ubuntu server with root access
- Internet connection for downloading dependencies
- Minimum 1GB RAM and 10GB disk space

### Quick Installation

**One-line installation command (recommended):**
```bash
sudo apt update && sudo apt upgrade -y && echo -e "\n\033[1;33mSystem updated successfully!\033[0m" && read -p "Do you want to install SSH/VPN Manager? (y/n): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] && curl -O https://raw.githubusercontent.com/mkkelati/NewScript/main/ssh-vpn-manager.sh && chmod +x ssh-vpn-manager.sh && sudo ./ssh-vpn-manager.sh --first-run || echo "Installation cancelled."
```

**Alternative with wget:**
```bash
sudo apt update && sudo apt upgrade -y && echo -e "\n\033[1;33mSystem updated successfully!\033[0m" && read -p "Do you want to install SSH/VPN Manager? (y/n): " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] && wget https://raw.githubusercontent.com/mkkelati/NewScript/main/ssh-vpn-manager.sh && chmod +x ssh-vpn-manager.sh && sudo ./ssh-vpn-manager.sh --first-run || echo "Installation cancelled."
```

**Step by step installation:**
1. **Update and upgrade system:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Download the script:**
   ```bash
   wget https://raw.githubusercontent.com/mkkelati/NewScript/main/ssh-vpn-manager.sh
   # OR
   curl -O https://raw.githubusercontent.com/mkkelati/NewScript/main/ssh-vpn-manager.sh
   ```

3. **Make it executable:**
   ```bash
   chmod +x ssh-vpn-manager.sh
   ```

4. **Run as root:**
   ```bash
   sudo ./ssh-vpn-manager.sh --first-run
   ```

### After Installation

Once installed, you can access the script using:
```bash
# Access main menu
sudo ./ssh-vpn-manager.sh

# Quick commands
sudo ./ssh-vpn-manager.sh menu    # Show main menu
sudo ./ssh-vpn-manager.sh status  # System health check
sudo ./ssh-vpn-manager.sh help    # Show help
```

### Manual Installation

1. Copy the `ssh-vpn-manager.sh` script to your Ubuntu server
2. Set execute permissions: `chmod +x ssh-vpn-manager.sh`
3. Run with root privileges: `sudo ./ssh-vpn-manager.sh`

## Usage

### First Time Setup

1. **Run the script:**
   ```bash
   sudo ./ssh-vpn-manager.sh
   ```

2. **Install dependencies (Option 5):**
   - This will install openssh-server, stunnel4, v2ray-core, and other required packages
   - The process may take several minutes depending on your internet connection

3. **Configure services:**
   - Use Option 6 to set up Stunnel SSL tunnel
   - Use Option 7 to configure V2Ray proxy server

### Menu Options

```
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
```

### Detailed Menu Guide

#### 1. Create SSH Account
- **Username**: 3-32 characters, alphanumeric with underscore and dash
- **Password**: Minimum 6 characters with confirmation
- **Expiration**: 1-365 days from creation date
- **Security**: Validates input and checks for existing users

#### 2. Delete SSH Account
- Lists all existing SSH users (excluding system accounts)
- Requires confirmation before deletion
- Safely removes user and home directory

#### 3. List Active SSH Users
- Displays comprehensive user information table
- Shows UID, home directory, and expiration date
- Excludes system and service accounts

#### 4. Monitor Online Users
- Real-time display of logged-in users
- Shows terminal, login time, and source IP
- Displays active SSH connection count

#### 5. Install Dependencies
- **Automatic package installation:**
  - openssh-server (SSH service)
  - stunnel4 (SSL tunnel)
  - openssl (SSL certificates)
  - curl, wget (downloading tools)
  - unzip (archive extraction)
  - qrencode (QR code generation)
  - jq (JSON processing)
  - v2ray-core (V2Ray proxy)

#### 6. Configure and Start Stunnel
- **SSL Certificate**: Auto-generates self-signed certificate
- **Service Configuration**: Creates optimized stunnel.conf
- **Port Mapping**: 443 (SSL) → 22 (SSH)
- **Security Settings**: Modern SSL/TLS configuration
- **Service Management**: Enables and starts systemd service

#### 7. Configure and Start V2Ray
- **Protocol Support**: Vmess and Vless
- **Transport Options**: TCP and WebSocket
- **Port Configuration:**
  - Vmess TCP: 8080
  - Vmess WebSocket: 8081
  - Vless TCP: 8082
  - Vless WebSocket: 8083
- **UUID Generation**: Automatic UUID creation
- **Connection Strings**: Generated for easy client setup

#### 8. Show Connection Information
- **Server Details**: IP address and hostname
- **Service Status**: Real-time status of all services
- **Port Usage**: Active/available port monitoring
- **Connection Statistics**: Current SSH connections
- **Log Analysis**: Recent login attempts from auth logs

#### 9. Generate Config Templates
- **HTTP Custom (.ehi)**: Configuration for HTTP Custom app
- **HTTP Injector (.ehi)**: Configuration for HTTP Injector app
- **OpenVPN (.ovpn)**: Template for OpenVPN client
- **Shadowsocks (.json)**: Manual proxy configuration
- **Connection Guide**: Comprehensive setup instructions

#### 10. Generate QR Codes
- **PNG Images**: High-quality QR codes for all V2Ray configs
- **ASCII Display**: Terminal-friendly QR code display
- **Configuration Strings**: Ready-to-use connection URLs
- **Summary File**: Complete configuration reference

## Configuration Files

### Locations
- **Stunnel**: `/etc/stunnel/stunnel.conf`
- **V2Ray**: `/usr/local/etc/v2ray/config.json`
- **SSL Certificate**: `/etc/stunnel/stunnel.pem`
- **Log File**: `/var/log/ssh-manager.log`

### Generated Files
- **V2Ray Configs**: `/tmp/v2ray-configs.txt`
- **QR Codes**: `/tmp/v2ray-qrcodes/`
- **Config Templates**: `/tmp/vpn-configs/`

## Port Configuration

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| SSH | 22 | TCP | Direct SSH access |
| Stunnel | 443 | TCP/SSL | SSL tunnel to SSH |
| V2Ray Vmess TCP | 8080 | TCP | Vmess protocol |
| V2Ray Vmess WS | 8081 | TCP/WS | Vmess over WebSocket |
| V2Ray Vless TCP | 8082 | TCP | Vless protocol |
| V2Ray Vless WS | 8083 | TCP/WS | Vless over WebSocket |

## Client Setup

### SSH Clients
1. **Direct SSH**: `ssh username@server_ip`
2. **SSH over SSL**: `ssh username@server_ip -p 443`

### V2Ray Clients
1. **V2RayNG (Android)**: Scan QR codes or import URLs
2. **V2RayN (Windows)**: Import configuration strings
3. **V2RayX (macOS)**: Use generated configuration files

### HTTP Custom/Injector
1. Download generated `.ehi` files
2. Import in HTTP Custom or HTTP Injector app
3. Replace USERNAME_HERE and PASSWORD_HERE with actual credentials

## Security Considerations

### Best Practices
- **Change Default Passwords**: Use strong, unique passwords
- **Enable Key Authentication**: Configure SSH key-based auth when possible
- **Regular Updates**: Keep system packages updated
- **Monitor Logs**: Regularly check `/var/log/ssh-manager.log`
- **Firewall Configuration**: Configure UFW or iptables appropriately

### Firewall Rules
```bash
# Allow SSH and VPN ports
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 8080:8083/tcp
ufw enable
```

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service status
systemctl status ssh
systemctl status stunnel4
systemctl status v2ray

# Check logs
journalctl -u ssh -f
journalctl -u stunnel4 -f
journalctl -u v2ray -f
```

#### Connection Problems
1. **Verify server IP**: Use Option 8 to check connection info
2. **Check port availability**: Ensure ports aren't blocked by firewall
3. **Validate credentials**: Confirm username/password are correct
4. **Service status**: Ensure all required services are running

#### SSL Certificate Issues
```bash
# Regenerate certificate
openssl req -new -x509 -days 365 -nodes \
    -out /etc/stunnel/stunnel.pem \
    -keyout /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem
systemctl restart stunnel4
```

### Log Analysis
```bash
# View SSH manager logs
tail -f /var/log/ssh-manager.log

# View SSH authentication logs
tail -f /var/log/auth.log | grep sshd

# View V2Ray logs
tail -f /var/log/v2ray/error.log
```

## Advanced Configuration

### Custom V2Ray Settings
Edit `/usr/local/etc/v2ray/config.json` for advanced configurations:
- Custom routing rules
- DNS settings
- Traffic statistics
- Multiple inbound protocols

### Stunnel Optimization
Edit `/etc/stunnel/stunnel.conf` for performance tuning:
- Connection limits
- Timeout settings
- SSL cipher preferences
- Logging levels

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on Ubuntu 18.04, 20.04, and 22.04
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files for error messages
3. Create an issue on GitHub with:
   - Ubuntu version
   - Error messages
   - Steps to reproduce

## Changelog

### v1.0 - Initial Release
- Menu-based interface implementation
- SSH account management
- Stunnel SSL tunnel configuration
- V2Ray Vmess/Vless setup
- QR code generation
- Config template generation
- Comprehensive logging
- Input validation and security
- Ubuntu 18.04, 20.04, 22.04 support 