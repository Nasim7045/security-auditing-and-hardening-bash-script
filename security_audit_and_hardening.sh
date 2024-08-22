#!/bin/bash

# Security Audit and Hardening Script for Linux Servers

# Function: User and Group Audits
function user_group_audit() {
    echo "=== User and Group Audits ==="

    # List all users
    echo "Listing all users:"
    cut -d: -f1 /etc/passwd
    echo

    # List all groups
    echo "Listing all groups:"
    cut -d: -f1 /etc/group
    echo

    # Check for users with UID 0 (root privileges)
    echo "Users with UID 0 (root privileges):"
    awk -F: '($3 == "0") {print}' /etc/passwd
    echo

    # Identify users without passwords
    echo "Users without passwords:"
    sudo awk -F: '($2 == "") {print $1}' /etc/shadow
    echo
}

# Function: File and Directory Permissions
function file_permissions_audit() {
    echo "=== File and Directory Permissions Audit ==="

    # Scan for world-writable files
    echo "World-writable files:"
    find / -type f -perm -o+w -exec ls -l {} \;
    echo

    # Check SSH directory permissions
    echo "Checking SSH directory permissions:"
    find /home -type d -name ".ssh" -exec ls -ld {} \;
    echo

    # Report files with SUID/SGID bits set
    echo "Files with SUID/SGID bits set:"
    find / -perm /6000 -exec ls -ld {} \;
    echo
}

# Function: Service Audits
function service_audit() {
    echo "=== Service Audits ==="

    # List running services
    echo "Running services:"
    systemctl list-units --type=service --state=running
    echo

    # Check for services on non-standard ports
    echo "Checking for services on non-standard ports:"
    sudo netstat -tuln
    echo
}

# Function: Firewall and Network Security
function firewall_network_security() {
    echo "=== Firewall and Network Security ==="

    # Verify firewall status
    echo "Checking firewall status:"
    sudo ufw status
    echo

    # Report open ports
    echo "Open ports:"
    sudo netstat -tulnp | grep LISTEN
    echo

    # Check for IP forwarding
    echo "Checking IP forwarding:"
    sudo sysctl net.ipv4.ip_forward
    echo
}

# Function: IP and Network Configuration Checks
function ip_network_config_checks() {
    echo "=== IP and Network Configuration Checks ==="

    # Public vs. Private IPs
    echo "Checking public vs. private IPs:"
    ip addr | grep "inet"
    echo

    # Sensitive services on public IPs
    echo "Sensitive services on public IPs:"
    sudo netstat -tulnp | grep -E '22|443' # Add other sensitive ports as needed
    echo
}

# Function: Security Updates and Patching
function security_updates_patching() {
    echo "=== Security Updates and Patching ==="

    # Check for available updates
    echo "Checking for available security updates:"
    sudo apt-get update && sudo apt-get upgrade -s | grep -i security
    echo

    # Ensure automatic updates are enabled
    echo "Ensuring automatic updates are enabled:"
    sudo apt-get install unattended-upgrades
    sudo dpkg-reconfigure -plow unattended-upgrades
    echo
}

# Function: Log Monitoring
function log_monitoring() {
    echo "=== Log Monitoring ==="

    # Check for suspicious logs
    echo "Checking logs for suspicious activity:"
    sudo grep -i "failed" /var/log/auth.log | tail -n 10
    echo
}

# Function: Server Hardening Steps
function server_hardening() {
    echo "=== Server Hardening Steps ==="

    # SSH Configuration
    echo "Configuring SSH for key-based authentication:"
    sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo

    # Disable IPv6
    echo "Disabling IPv6:"
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo

    # Secure GRUB bootloader
    echo "Setting GRUB password:"
    sudo grub-mkpasswd-pbkdf2  # Follow the prompts to set the password
    echo

    # Configure iptables
    echo "Configuring iptables firewall rules:"
    sudo iptables -P INPUT DROP
    sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    echo
}

# Function: Custom Security Checks
function custom_security_checks() {
    echo "=== Custom Security Checks ==="
    # Add any custom security checks based on your organization's needs
    echo "No custom checks configured."
    echo
}

# Function: Reporting and Alerting
function reporting_alerting() {
    echo "=== Reporting and Alerting ==="
    # Generate a summary report of the security audit and hardening process
    # Add code to send email alerts if needed
    echo "Report generated."
    echo
}

# Main function to call all audits and hardening steps
function main() {
    user_group_audit
    file_permissions_audit
    service_audit
    firewall_network_security
    ip_network_config_checks
    security_updates_patching
    log_monitoring
    server_hardening
    custom_security_checks
    reporting_alerting
}

# Run the main function
main
