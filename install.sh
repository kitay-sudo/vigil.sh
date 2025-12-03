#!/bin/bash
#
# Security Monitor Installation Script
# Menu-based installer for server hardening and security monitoring
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/security-monitor"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

#############################################
# Function: Server Initial Setup (SSH Hardening)
#############################################
setup_server() {
    echo -e "${CYAN}======================================${NC}"
    echo -e "${CYAN}  Server Initial Setup${NC}"
    echo -e "${CYAN}  SSH Hardening & User Creation${NC}"
    echo -e "${CYAN}======================================${NC}"
    echo ""

    # Step 1: Create user
    echo -e "${YELLOW}Step 1: Create Admin User${NC}"
    echo "Enter username for admin user (default: kitay):"
    read -p "Username: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-kitay}

    if id "$ADMIN_USER" &>/dev/null; then
        echo -e "${YELLOW}User $ADMIN_USER already exists. Skipping creation.${NC}"
    else
        echo -e "${YELLOW}Creating user $ADMIN_USER...${NC}"
        adduser --gecos "" $ADMIN_USER

        echo -e "${YELLOW}Adding $ADMIN_USER to sudo group...${NC}"
        usermod -aG sudo $ADMIN_USER
        echo -e "${GREEN}✓ User $ADMIN_USER created and added to sudo group${NC}"
    fi

    echo ""
    echo -e "${YELLOW}Step 2: SSH Key Setup${NC}"
    echo ""
    echo -e "${CYAN}ВАЖНО! Перед отключением парольной аутентификации необходимо добавить SSH ключ!${NC}"
    echo ""
    echo -e "${YELLOW}Как создать SSH ключ с YubiKey (на вашем компьютере):${NC}"
    echo -e "  ${BLUE}ssh-keygen -t ed25519-sk -O resident${NC}"
    echo ""
    echo -e "${YELLOW}Как создать обычный SSH ключ (без YubiKey):${NC}"
    echo -e "  ${BLUE}ssh-keygen -t ed25519${NC}"
    echo ""
    echo -e "${YELLOW}Как скопировать ключ на сервер (Windows PowerShell):${NC}"
    echo -e "  ${BLUE}type \$env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh $ADMIN_USER@$(hostname -I | awk '{print $1}') \"mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys\"${NC}"
    echo ""
    echo -e "${YELLOW}Как скопировать ключ на сервер (Linux/Mac):${NC}"
    echo -e "  ${BLUE}ssh-copy-id -i ~/.ssh/id_ed25519.pub $ADMIN_USER@$(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo -e "${RED}⚠️  Если вы НЕ добавите SSH ключ сейчас, то потеряете доступ к серверу!${NC}"
    echo ""

    read -p "Have you already added your SSH key? (y/n): " SSH_KEY_ADDED

    if [[ ! "$SSH_KEY_ADDED" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${YELLOW}Добавьте SSH ключ вручную сейчас:${NC}"
        echo ""
        echo "1. На вашем компьютере выполните команду выше"
        echo "2. Или скопируйте содержимое ~/.ssh/id_ed25519.pub"
        echo "3. И добавьте в файл /home/$ADMIN_USER/.ssh/authorized_keys на сервере"
        echo ""
        read -p "Press Enter after you have added the SSH key..."
    fi

    # Verify SSH key exists
    if [ ! -f "/home/$ADMIN_USER/.ssh/authorized_keys" ]; then
        echo ""
        echo -e "${YELLOW}SSH key file not found. Creating it now...${NC}"
        echo "Paste your public SSH key (entire line from id_ed25519.pub):"
        read -p "Public key: " PUBLIC_KEY

        mkdir -p /home/$ADMIN_USER/.ssh
        echo "$PUBLIC_KEY" > /home/$ADMIN_USER/.ssh/authorized_keys
        chmod 700 /home/$ADMIN_USER/.ssh
        chmod 600 /home/$ADMIN_USER/.ssh/authorized_keys
        chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh
        echo -e "${GREEN}✓ SSH key added${NC}"
    else
        echo -e "${GREEN}✓ SSH key file found: /home/$ADMIN_USER/.ssh/authorized_keys${NC}"
    fi

    echo ""
    echo -e "${YELLOW}Step 3: SSH Security Configuration${NC}"
    echo ""
    echo "The following changes will be made to /etc/ssh/sshd_config:"
    echo "  - PermitRootLogin no (disable root login)"
    echo "  - PasswordAuthentication no (disable password login)"
    echo "  - PubkeyAuthentication yes (enable key-based login)"
    echo ""
    echo -e "${RED}⚠️  After this, you can ONLY login with SSH key!${NC}"
    echo ""
    read -p "Proceed with SSH hardening? (y/n): " PROCEED_SSH

    if [[ "$PROCEED_SSH" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Backing up current sshd_config...${NC}"
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

        echo -e "${YELLOW}Applying SSH security settings...${NC}"

        # Update sshd_config
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

        # Add settings if they don't exist
        grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
        grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
        grep -q "^PubkeyAuthentication" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config

        echo -e "${YELLOW}Testing SSH configuration...${NC}"
        sshd -t

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ SSH configuration is valid${NC}"
            echo ""
            echo -e "${YELLOW}Restarting SSH service...${NC}"

            # Important: Don't disconnect current session
            echo -e "${CYAN}Note: Your current session will NOT be disconnected${NC}"
            systemctl restart sshd

            echo -e "${GREEN}✓ SSH service restarted${NC}"
            echo ""
            echo -e "${GREEN}======================================${NC}"
            echo -e "${GREEN}  SSH Hardening Complete!${NC}"
            echo -e "${GREEN}======================================${NC}"
            echo ""
            echo -e "${CYAN}IMPORTANT: Test SSH login in a NEW terminal before closing this one!${NC}"
            echo ""
            echo "Test login with:"
            echo -e "  ${BLUE}ssh $ADMIN_USER@$(hostname -I | awk '{print $1}')${NC}"
            echo ""
            echo -e "${YELLOW}Backup created: /etc/ssh/sshd_config.backup.*${NC}"
            echo ""
        else
            echo -e "${RED}✗ SSH configuration test failed!${NC}"
            echo -e "${YELLOW}Restoring backup...${NC}"
            cp /etc/ssh/sshd_config.backup.$(ls -t /etc/ssh/sshd_config.backup.* | head -1) /etc/ssh/sshd_config
            systemctl restart sshd
            echo -e "${RED}Changes reverted. Please check the configuration manually.${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}SSH hardening skipped.${NC}"
    fi

    echo ""
    read -p "Press Enter to return to main menu..."
}

#############################################
# Function: Install Security Monitor
#############################################
install_watchdog() {
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}  Security Monitor Installation${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""

    # Install Python3 if not present
    echo -e "${YELLOW}Checking Python3...${NC}"
    apt-get update -qq
    apt-get install -y python3 python3-pip

    # Create installation directory
    echo -e "${YELLOW}Creating installation directory...${NC}"
    mkdir -p $INSTALL_DIR
    mkdir -p $INSTALL_DIR/docs
    cp "$SCRIPT_DIR/security_monitor.py" $INSTALL_DIR/
    cp "$SCRIPT_DIR/requirements.txt" $INSTALL_DIR/
    [ -f "$SCRIPT_DIR/docs/security-commands.md" ] && cp "$SCRIPT_DIR/docs/security-commands.md" $INSTALL_DIR/docs/

    # Install Python dependencies
    echo -e "${YELLOW}Installing Python dependencies...${NC}"
    if ! pip3 install --break-system-packages -r $INSTALL_DIR/requirements.txt 2>/dev/null; then
        echo -e "${YELLOW}Retrying without --break-system-packages...${NC}"
        pip3 install -r $INSTALL_DIR/requirements.txt
    fi

    # Configure server name
    echo ""
    echo -e "${YELLOW}Configure Server Name${NC}"
    echo "Enter a friendly name for this server (for notifications):"
    echo "Example: Production API, Web Server 1, Database Master"
    read -p "Server Name: " SERVER_NAME
    SERVER_NAME=${SERVER_NAME:-$(hostname)}

    # Configure whitelist
    echo ""
    echo -e "${YELLOW}Configure SSH Whitelist (Admin IPs)${NC}"
    echo "Enter IP addresses for SSH access (comma-separated):"
    echo "Example: 94.241.174.106,YOUR_HOME_IP"
    read -p "SSH Whitelist IPs: " SSH_WHITELIST_INPUT

    # Parse SSH whitelist
    IFS=',' read -ra SSH_WHITELIST_ARRAY <<< "$SSH_WHITELIST_INPUT"
    SSH_WHITELIST_JSON=""
    for ip in "${SSH_WHITELIST_ARRAY[@]}"; do
        ip=$(echo "$ip" | tr -d ' ' | LC_ALL=C tr -cd '0-9.')
        if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            if [ -n "$SSH_WHITELIST_JSON" ]; then
                SSH_WHITELIST_JSON="$SSH_WHITELIST_JSON,"
            fi
            SSH_WHITELIST_JSON="$SSH_WHITELIST_JSON\"$ip\""
        fi
    done

    # Service whitelist
    echo ""
    echo -e "${YELLOW}Configure Service Whitelist (Internal services)${NC}"
    echo "Enter IPs for internal services like MongoDB, Redis (comma-separated):"
    echo "Example: 89.223.64.38,10.0.0.5,192.168.1.100"
    read -p "Service Whitelist IPs (or press Enter for default 127.0.0.1): " SERVICE_WHITELIST_INPUT

    SERVICE_WHITELIST_JSON="\"127.0.0.1\""
    if [ -n "$SERVICE_WHITELIST_INPUT" ]; then
        IFS=',' read -ra SERVICE_WHITELIST_ARRAY <<< "$SERVICE_WHITELIST_INPUT"
        for ip in "${SERVICE_WHITELIST_ARRAY[@]}"; do
            ip=$(echo "$ip" | tr -d ' ' | LC_ALL=C tr -cd '0-9.')
            if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                SERVICE_WHITELIST_JSON="$SERVICE_WHITELIST_JSON,\"$ip\""
            fi
        done
    fi

    # Configure Telegram
    echo ""
    echo -e "${YELLOW}Configure Telegram Notifications${NC}"
    echo "To create a Telegram bot:"
    echo "1. Message @BotFather on Telegram"
    echo "2. Send /newbot and follow instructions"
    echo "3. Copy the bot token"
    echo "4. Send any message to your bot"
    echo "5. Open https://api.telegram.org/bot<TOKEN>/getUpdates"
    echo "6. Find chat.id in the response"
    echo ""
    read -p "Telegram Bot Token (or press Enter to skip): " BOT_TOKEN
    read -p "Telegram Chat ID (or press Enter to skip): " CHAT_ID

    BOT_TOKEN=${BOT_TOKEN:-"YOUR_BOT_TOKEN_HERE"}
    CHAT_ID=${CHAT_ID:-"YOUR_CHAT_ID_HERE"}

    # Configure SSH Monitoring
    echo ""
    echo -e "${YELLOW}Configure SSH Monitoring${NC}"
    echo "Do you want to enable SSH monitoring and brute-force protection?"
    echo "Note: If you use SSH keys only and disabled password auth, you may not need this."
    echo ""
    read -p "Enable SSH monitoring? (y/n, default: y): " ENABLE_SSH_MONITORING
    ENABLE_SSH_MONITORING=${ENABLE_SSH_MONITORING:-"y"}

    if [[ "$ENABLE_SSH_MONITORING" =~ ^[Yy]$ ]]; then
        SSH_MONITORING_ENABLED="true"

        echo ""
        echo -e "${YELLOW}Detecting SSH port...${NC}"
        DETECTED_SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oP ':\K[0-9]+' | head -1)
        if [ -z "$DETECTED_SSH_PORT" ]; then
            DETECTED_SSH_PORT=$(netstat -tlnp 2>/dev/null | grep sshd | grep -oP ':\K[0-9]+' | head -1)
        fi

        if [ -n "$DETECTED_SSH_PORT" ]; then
            echo "Detected SSH port: $DETECTED_SSH_PORT"
            read -p "Use this port? (press Enter to confirm or type different port): " SSH_PORT_INPUT
            SSH_PORT=${SSH_PORT_INPUT:-$DETECTED_SSH_PORT}
        else
            echo "Could not auto-detect SSH port."
            read -p "Enter SSH port (default: 22): " SSH_PORT
            SSH_PORT=${SSH_PORT:-22}
        fi

        echo "SSH monitoring: ENABLED on port $SSH_PORT"
    else
        SSH_MONITORING_ENABLED="false"
        SSH_PORT="22"
        echo "SSH monitoring: DISABLED"
        echo "Only SYN flood and DDoS protection will be active."
    fi

    # Configure HTTP API
    echo ""
    echo -e "${YELLOW}Configure HTTP API${NC}"
    echo "HTTP API provides JSON endpoints for statistics and monitoring."
    echo "Access secured with API key (X-API-Key header required)."
    echo "Endpoints: /watchdog/health, /watchdog/stats, /watchdog/status"
    echo ""
    read -p "Enable HTTP API? (y/n, default: y): " ENABLE_API
    ENABLE_API=${ENABLE_API:-"y"}

    if [[ "$ENABLE_API" =~ ^[Yy]$ ]]; then
        API_ENABLED="true"
        read -p "API Port (default: 8765): " API_PORT
        API_PORT=${API_PORT:-8765}

        # Generate secure random API key (32 characters)
        API_KEY=$(openssl rand -hex 16)

        echo ""
        echo -e "${GREEN}HTTP API: ENABLED on port $API_PORT${NC}"
        echo -e "${GREEN}API Key generated: ${YELLOW}$API_KEY${NC}"
        echo ""
        echo -e "${YELLOW}IMPORTANT: Save this API key!${NC}"
        echo "Usage: curl -H \"X-API-Key: $API_KEY\" http://localhost:$API_PORT/watchdog/stats"
        echo ""
        read -p "Press Enter to continue..."
    else
        API_ENABLED="false"
        API_PORT="8765"
        API_KEY=""
        echo "HTTP API: DISABLED"
    fi

    # Create config file
    echo -e "${YELLOW}Creating configuration...${NC}"
    cat > $INSTALL_DIR/config.json << EOF
{
  "server_name": "$SERVER_NAME",
  "ssh_port": $SSH_PORT,
  "enable_ssh_monitoring": $SSH_MONITORING_ENABLED,
  "ssh_whitelist": [$SSH_WHITELIST_JSON],
  "service_whitelist": [$SERVICE_WHITELIST_JSON],
  "telegram": {
    "bot_token": "$BOT_TOKEN",
    "chat_id": "$CHAT_ID"
  },
  "thresholds": {
    "syn_recv_max": 50,
    "syn_recv_per_ip_min": 15,
    "failed_ssh_max": 5,
    "http_connections_per_ip_max": 100,
    "ssh_connections_per_ip_max": 3
  },
  "protection": {
    "block_ssh_bruteforce": $SSH_MONITORING_ENABLED,
    "block_unknown_ssh": $SSH_MONITORING_ENABLED,
    "block_syn_flood": true,
    "block_excessive_http": false,
    "notify_excessive_http": true
  },
  "check_interval_seconds": 60,
  "auto_block": true,
  "log_file": "/var/log/security-monitor.log",
  "blocked_ips_file": "/var/log/blocked-ips.log",
  "api": {
    "enabled": $API_ENABLED,
    "host": "0.0.0.0",
    "port": $API_PORT,
    "api_key": "$API_KEY"
  }
}
EOF

    # Create systemd service
    echo -e "${YELLOW}Creating systemd service...${NC}"
    cat > /etc/systemd/system/security-monitor.service << EOF
[Unit]
Description=Security Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/security_monitor.py -c $INSTALL_DIR/config.json
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10
StandardOutput=append:/var/log/security-monitor.log
StandardError=append:/var/log/security-monitor.log

[Install]
WantedBy=multi-user.target
EOF

    # Create convenience script
    echo -e "${YELLOW}Creating convenience commands...${NC}"
    cat > /usr/local/bin/security-monitor << EOF
#!/bin/bash
/usr/bin/python3 $INSTALL_DIR/security_monitor.py -c $INSTALL_DIR/config.json "\$@"
EOF
    chmod +x /usr/local/bin/security-monitor

    # Enable SYN cookies
    echo -e "${YELLOW}Enabling kernel protections...${NC}"
    sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_synack_retries=2 > /dev/null 2>&1 || true

    if ! grep -q "Security Monitor" /etc/sysctl.conf 2>/dev/null; then
        cat >> /etc/sysctl.conf << EOF

# Security Monitor - SYN flood protection
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_max_syn_backlog=2048
EOF
    fi

    # Create log files
    touch /var/log/security-monitor.log
    touch /var/log/blocked-ips.log

    # Reload systemd
    systemctl daemon-reload

    # Start service
    echo -e "${YELLOW}Starting service...${NC}"
    systemctl enable security-monitor
    systemctl start security-monitor

    echo ""
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""
    echo -e "Service status: ${YELLOW}systemctl status security-monitor${NC}"
    echo -e "View logs: ${YELLOW}tail -f /var/log/security-monitor.log${NC}"
    echo -e "Stop service: ${YELLOW}systemctl stop security-monitor${NC}"
    echo -e "Edit config: ${YELLOW}nano $INSTALL_DIR/config.json${NC}"
    echo ""
    echo -e "${YELLOW}Quick commands:${NC}"
    echo -e "  security-monitor --show-status"
    echo -e "  security-monitor --check-once"
    echo -e "  security-monitor --add-ssh-whitelist YOUR_IP"
    echo ""

    # Show current status
    sleep 2
    systemctl status security-monitor --no-pager || true

    echo ""
    read -p "Press Enter to return to main menu..."
}

#############################################
# Main Menu
#############################################
show_menu() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Security Monitor Setup Menu        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}1)${NC} Server Initial Setup (SSH Hardening)"
    echo -e "   ${YELLOW}→${NC} Create admin user"
    echo -e "   ${YELLOW}→${NC} Disable password authentication"
    echo -e "   ${YELLOW}→${NC} Enable SSH key-only access"
    echo ""
    echo -e "${GREEN}2)${NC} Install Security Monitor (Watchdog)"
    echo -e "   ${YELLOW}→${NC} Install monitoring service"
    echo -e "   ${YELLOW}→${NC} Configure protection rules"
    echo -e "   ${YELLOW}→${NC} Setup HTTP API"
    echo ""
    echo -e "${GREEN}3)${NC} Exit"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo ""
}

#############################################
# Main Loop
#############################################
while true; do
    show_menu
    read -p "Select option (1-3): " choice

    case $choice in
        1)
            setup_server
            ;;
        2)
            install_watchdog
            ;;
        3)
            echo ""
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please select 1-3.${NC}"
            sleep 2
            ;;
    esac
done
