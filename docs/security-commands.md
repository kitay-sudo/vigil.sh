# Security Commands Reference

## 1. Network Monitoring Commands

### Check all open ports and connections
```bash
netstat -tulnp
# or
ss -tulnp
```

### Check active connections with state
```bash
netstat -an | grep ESTABLISHED
netstat -an | grep SYN_RECV
```

### Count connections by state
```bash
netstat -an | awk '{print $6}' | sort | uniq -c | sort -rn
```

### Find connections from specific IP
```bash
netstat -an | grep <IP_ADDRESS>
ss -tnp | grep <IP_ADDRESS>
```

---

## 2. SSH Security Commands

### Check who is logged in
```bash
who
w
```

### Check login history
```bash
last | head -30
lastb | head -30  # failed logins
```

### Check auth logs for specific IP
```bash
grep "<IP_ADDRESS>" /var/log/auth.log | tail -20
```

### Check failed SSH attempts
```bash
grep "Failed password" /var/log/auth.log | tail -50
```

### Check successful SSH logins
```bash
grep "Accepted" /var/log/auth.log | tail -20
```

### Count failed attempts by IP
```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20
```

---

## 3. SYN Flood Detection

### Count SYN_RECV connections (potential attack)
```bash
netstat -an | grep SYN_RECV | wc -l
```

### Show SYN_RECV by source IP
```bash
netstat -an | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

### Enable SYN cookies protection
```bash
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
```

---

## 4. Firewall (iptables) Commands

### Block specific IP
```bash
iptables -A INPUT -s <IP_ADDRESS> -j DROP
```

### Block subnet
```bash
iptables -A INPUT -s <IP_ADDRESS>/24 -j DROP
iptables -A INPUT -s <IP_ADDRESS>/16 -j DROP
```

### Allow specific IP (whitelist)
```bash
iptables -I INPUT -s <IP_ADDRESS> -j ACCEPT
```

### Show all rules
```bash
iptables -L -n -v
iptables -L INPUT -n --line-numbers
```

### Delete rule by number
```bash
iptables -D INPUT <RULE_NUMBER>
```

### Save rules (persist after reboot)
```bash
iptables-save > /etc/iptables.rules
# Restore
iptables-restore < /etc/iptables.rules
```

### Block IP and log
```bash
iptables -A INPUT -s <IP_ADDRESS> -j LOG --log-prefix "BLOCKED IP: "
iptables -A INPUT -s <IP_ADDRESS> -j DROP
```

---

## 5. Kill Connections

### Kill connection from specific IP
```bash
ss -K dst <IP_ADDRESS>
```

### Kill all connections from IP
```bash
tcpkill -i eth0 host <IP_ADDRESS>
```

---

## 6. Process Investigation

### Find process by connection
```bash
# Get PID from connection
ss -tnp | grep <IP_ADDRESS>
lsof -i :22 | grep <IP_ADDRESS>

# Investigate process
ps aux | grep <PID>
ls -la /proc/<PID>/exe
cat /proc/<PID>/cmdline
```

---

## 7. SSH Hardening

### Check authorized keys for suspicious entries
```bash
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

### Change root password
```bash
passwd root
```

### Disable root SSH login (edit /etc/ssh/sshd_config)
```
PermitRootLogin no
```

### Allow only specific users
```
AllowUsers your_username
```

### Change SSH port
```
Port 2222
```

### Restart SSH after changes
```bash
systemctl restart sshd
```

---

## 8. Fail2ban Commands

### Install
```bash
apt install fail2ban -y
```

### Check status
```bash
fail2ban-client status
fail2ban-client status sshd
```

### Unban IP
```bash
fail2ban-client set sshd unbanip <IP_ADDRESS>
```

### Ban IP manually
```bash
fail2ban-client set sshd banip <IP_ADDRESS>
```

---

## 9. Useful One-liners

### Top 10 IPs with most connections
```bash
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
```

### Find brute force attackers
```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10
```

### Check for suspicious processes
```bash
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20
```

### Check listening ports
```bash
ss -tlnp
lsof -i -P -n | grep LISTEN
```

---

## 10. Emergency Response

### Quick block attacker
```bash
# 1. Identify attacker IP
netstat -an | grep ESTABLISHED | grep -v "YOUR_IP"

# 2. Block immediately
iptables -I INPUT -s <ATTACKER_IP> -j DROP

# 3. Kill existing connections
ss -K dst <ATTACKER_IP>

# 4. Check if blocked
iptables -L INPUT -n | grep <ATTACKER_IP>
```

### During SYN Flood attack
```bash
# Enable protections
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_synack_retries=1
sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Block attacking subnet
netstat -an | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5
# Then block top offenders
iptables -A INPUT -s <SUBNET>/16 -j DROP
```
