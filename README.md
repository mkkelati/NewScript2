# Professional Xray Manager v3.0

A comprehensive VLESS+WebSocket+TLS management system with advanced user management, real-time monitoring, and professional features.

## 🚀 Features

### ✅ Complete User Management System
- **Add/Delete Users**: Full user lifecycle management
- **UUID Management**: Generate random or set custom UUIDs
- **Expiry Control**: Set expiry dates with automatic cleanup
- **Device Limits**: Control max IPs/devices per user
- **Custom Paths**: Individual WebSocket paths per user
- **Connection URLs**: Auto-generate VLESS links (TLS + HTTP)

### ✅ Real-Time Monitoring
- **Online Users**: Live connection tracking
- **Usage Statistics**: Per-user connection logs
- **System Status**: Service health monitoring
- **Port Statistics**: Real-time connection counts

### ✅ Domain & Configuration Management
- **Manual Domain Setting**: No auto-DNS fetching
- **Port Management**: Custom TLS (443) and HTTP (80) ports
- **WebSocket Paths**: Configurable paths per user
- **SSL Certificate**: Maintains existing TLS setup

### ✅ Backup & Logging
- **Daily Backups**: Automatic user database backups
- **Usage Logs**: Detailed connection tracking
- **Expired Cleanup**: Automatic removal of expired users
- **Persistent Storage**: All settings survive reboots

## 📦 Installation

### Quick Installation (Recommended)

```bash
# Install the professional Xray manager
curl -fsSL https://raw.githubusercontent.com/mkkelati/NewScript2/master/xray-manager.sh -o /usr/local/bin/xray-manager && chmod +x /usr/local/bin/xray-manager

# Run the manager
sudo xray-manager
```

### Alternative Installation

```bash
# Download and install
wget https://raw.githubusercontent.com/mkkelati/NewScript2/master/xray-manager.sh
chmod +x xray-manager.sh
sudo mv xray-manager.sh /usr/local/bin/xray-manager

# Run the manager
sudo xray-manager
```

## 🎯 Usage

### Main Menu Interface

Run the manager with:
```bash
sudo xray-manager
```

### Command Line Interface

```bash
# Add a new user
sudo xray-manager add-user

# List all users
sudo xray-manager list-users

# Clean expired users
sudo xray-manager cleanup-expired
```

## 📋 Menu Features

### 1. User Management
- **Add New User**: Create users with custom settings
- **Delete User**: Remove users from system
- **List All Users**: View all users with status
- **Show Connection Links**: Generate VLESS URLs

### 2. Monitoring & Logs
- **Show Online Users**: Real-time active connections
- **View Usage Logs**: Connection history and statistics
- **System Status**: Service and certificate health

### 3. Configuration
- **Domain & Port Management**: Modify server settings
- **Backup Database**: Create user data backups
- **Cleanup Expired**: Remove expired users

### 4. System Operations
- **Restart Service**: Restart Xray service
- **Update Configuration**: Apply config changes

## 🔧 Configuration Files

- **User Database**: `/etc/xray-manager/users.db`
- **Config Database**: `/etc/xray-manager/config.db`
- **Xray Config**: `/usr/local/etc/xray/config.json`
- **Logs**: `/var/log/xray/`
- **Backups**: `/etc/xray-manager/backups/`

## 📊 User Management

### Adding Users
1. Username and UUID (auto-generated or custom)
2. Expiry date (30/60/90 days, custom, or never)
3. Maximum devices (1-10 connections)
4. Custom WebSocket path

### User Status
- **ACTIVE**: User can connect
- **EXPIRED**: Automatically disabled
- **DISABLED**: Manually disabled

### Connection URLs
- **TLS (Primary)**: `vless://UUID@domain:443?type=ws&security=tls...`
- **HTTP (Fallback)**: `vless://UUID@domain:80?type=ws&security=none...`

## 🔍 Monitoring Features

### Real-Time Statistics
- Online user count
- Connection duration tracking
- IP address monitoring
- Port usage statistics

### Usage Logs
- Daily connection logs
- Per-user statistics
- Error log monitoring
- Access pattern analysis

## 🔐 Security Features

- **SSL/TLS Encryption**: Maintains existing certificates
- **User Isolation**: UUID-based access control
- **Device Limiting**: Prevent connection abuse
- **Automatic Cleanup**: Remove expired accounts
- **Secure Storage**: Protected user database

## ☁️ Cloudflare Compatibility

Fully compatible with Cloudflare CDN:
- **DNS A Record**: `domain → server_ip` (Proxied)
- **SSL/TLS Mode**: Full (Strict)
- **WebSocket Support**: Automatic with proxy
- **Headers**: Proper Host/SNI configuration

## 📱 Client Configuration

### For HTTP Injector
```
Protocol: VLESS
Transport: WebSocket
Host/SNI: your-domain.com
Path: /vpn (or custom path)
TLS: Enabled (for port 443)
```

### For V2Ray Clients
Use the generated VLESS URLs directly from the manager.

## 🛠️ Prerequisites

- Ubuntu 18.04+ / Debian 9+
- Root access
- Existing Xray installation (or use custom-xray-setup.sh first)
- Valid SSL certificate

## 🔄 Automatic Features

- **Daily Cleanup**: Removes expired users at 2 AM
- **Config Sync**: Auto-updates Xray configuration
- **Service Management**: Automatic restarts on config changes
- **Backup Rotation**: Keeps last 10 backups

## 📞 Troubleshooting

### Common Issues

1. **Permission Denied**: Run with `sudo`
2. **Service Not Running**: Check `sudo systemctl status xray`
3. **Connection Failed**: Verify domain DNS and SSL certificate
4. **User Not Connecting**: Check expiry date and device limits

### Log Files
```bash
# Manager logs
tail -f /var/log/xray/manager.log

# Access logs
tail -f /var/log/xray/access.log

# Error logs
tail -f /var/log/xray/error.log
```

## 🎉 Quick Start (If Xray Not Installed)

1. **Install Xray first**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/mkkelati/NewScript2/master/custom-xray-setup.sh | sudo bash
   ```

2. **Install Manager**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/mkkelati/NewScript2/master/xray-manager.sh -o /usr/local/bin/xray-manager && chmod +x /usr/local/bin/xray-manager
   ```

3. **Run Manager**:
   ```bash
   sudo xray-manager
   ```

---

## 📄 Version History

### v3.0 - Professional Manager
- Complete user management system
- Real-time monitoring
- Automatic cleanup and backups
- Command-line interface
- Professional menu system

### v2.0 - Enhanced Setup
- Custom domain support
- SSL certificate automation
- System optimization
- CDN compatibility

### v1.0 - Basic Setup
- Initial Xray installation
- Basic VLESS configuration
- Manual setup process

---

**Repository**: [https://github.com/mkkelati/NewScript2](https://github.com/mkkelati/NewScript2)

**Support**: Create an issue on GitHub for support and feature requests. 