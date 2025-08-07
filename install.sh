#!/bin/bash

#==============================================================================
# SSH Manager Easy Installer
# One-command installation for SSH/VPN Manager
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Clear screen and show banner
clear
echo -e "${CYAN}
╔════════════════════════════════════════════════════════════╗
║                SSH/VPN Manager Installer                  ║
║                    Easy Installation                      ║
╚════════════════════════════════════════════════════════════╝
${NC}"

echo -e "${BLUE}🚀 Welcome to SSH Manager Easy Installer!${NC}"
echo -e "${YELLOW}This will install the professional SSH/VPN management tool.${NC}\n"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ This installer must be run as root${NC}"
    echo -e "${YELLOW}Please run: ${GREEN}sudo bash install.sh${NC}"
    exit 1
fi

# Get user confirmation
echo -e "${YELLOW}⚠️  Choose installation type:${NC}"
echo -e "${BLUE}  1) SSH Manager (OpenSSH + Stunnel + V2Ray)${NC}"
echo -e "${BLUE}  2) Xray-core (VLESS + WebSocket + TLS)${NC}"
echo -en "${WHITE}Select [1-2]: ${NC}"
read -r install_type

read -p "Do you want to continue? [Y/n]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]?$ ]]; then
    echo -e "${YELLOW}Installation cancelled.${NC}"
    exit 0
fi

# Update system
echo -e "\n${BLUE}📦 Updating system packages...${NC}"
if apt update -qq && apt upgrade -y -qq; then
    echo -e "${GREEN}✅ System updated successfully!${NC}"
else
    echo -e "${RED}❌ Failed to update system${NC}"
    exit 1
fi

case $install_type in
    1)
        # Download SSH Manager
        echo -e "\n${BLUE}⬇️  Downloading SSH Manager...${NC}"
        if curl -fsSL https://raw.githubusercontent.com/mkkelati/NewScript2/master/ssh-manager.sh -o /usr/local/bin/ssh-manager.sh; then
            echo -e "${GREEN}✅ SSH Manager downloaded successfully!${NC}"
        else
            echo -e "${RED}❌ Failed to download SSH Manager${NC}"
            exit 1
        fi

        # Make executable
        chmod +x /usr/local/bin/ssh-manager.sh

        # Create menu command
        echo -e "\n${BLUE}🔧 Creating 'menu' command...${NC}"
        cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
exec /usr/local/bin/ssh-manager.sh menu
EOF
        chmod +x /usr/local/bin/menu

        # Create sshm alias
        cat > /usr/local/bin/sshm << 'EOF'
#!/bin/bash
exec /usr/local/bin/ssh-manager.sh "$@"
EOF
        chmod +x /usr/local/bin/sshm

        echo -e "${GREEN}✅ SSH Manager installed successfully!${NC}"

        # Run first-time setup
        echo -e "\n${BLUE}🔧 Starting SSH Manager setup...${NC}"
        /usr/local/bin/ssh-manager.sh --first-run

        echo -e "\n${GREEN}🎉 SSH Manager installation completed!${NC}"
        echo -e "${CYAN}You can now use: ${GREEN}menu${NC} or ${GREEN}sshm${NC}"
        ;;
        
    2)
        # Download Xray installer
        echo -e "\n${BLUE}⬇️  Downloading Xray installer...${NC}"
        if curl -fsSL https://raw.githubusercontent.com/mkkelati/NewScript2/master/xray-installer.sh -o xray-installer.sh; then
            echo -e "${GREEN}✅ Xray installer downloaded successfully!${NC}"
        else
            echo -e "${RED}❌ Failed to download Xray installer${NC}"
            exit 1
        fi

        # Make executable and run
        chmod +x xray-installer.sh
        echo -e "\n${BLUE}🔧 Starting Xray installation...${NC}"
        ./xray-installer.sh
        ;;
        
    *)
        echo -e "${RED}❌ Invalid selection${NC}"
        exit 1
        ;;
esac 