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
echo -e "${YELLOW}⚠️  This will:${NC}"
echo -e "${BLUE}  • Update your system packages${NC}"
echo -e "${BLUE}  • Install SSH Manager${NC}"
echo -e "${BLUE}  • Set up the 'menu' command${NC}\n"

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

# Download SSH Manager
echo -e "\n${BLUE}⬇️  Downloading SSH Manager...${NC}"
if curl -fsSL https://raw.githubusercontent.com/mkkelati/NewScript/main/ssh-manager.sh -o /usr/local/bin/ssh-manager.sh; then
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

echo -e "${GREEN}✅ Commands installed successfully!${NC}"

# Run first-time setup
echo -e "\n${BLUE}🔧 Starting SSH Manager setup...${NC}"
echo -e "${YELLOW}Please follow the prompts in the SSH Manager.${NC}\n"

# Add a small delay for user to read
sleep 2

# Launch SSH Manager
/usr/local/bin/ssh-manager.sh --first-run

echo -e "\n${GREEN}🎉 Installation completed!${NC}"
echo -e "${CYAN}You can now use these commands:${NC}"
echo -e "${WHITE}  • ${GREEN}menu${WHITE} - Open SSH Manager menu${NC}"
echo -e "${WHITE}  • ${GREEN}sshm${WHITE} - Run SSH Manager${NC}"
echo -e "${WHITE}  • ${GREEN}sudo ssh-manager.sh${WHITE} - Full path${NC}" 