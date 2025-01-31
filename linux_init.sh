#!/bin/bash

# Update and upgrade the system
sudo apt-get update -y
sudo apt-get upgrade -y

# Install essential security tools
sudo apt-get install -y ufw fail2ban clamav rkhunter

# Configure UFW (Uncomplicated Firewall)
sudo ufw allow ssh
sudo ufw enable

# Configure Fail2Ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Install and configure ClamAV
sudo freshclam
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-freshclam

# Run Rootkit Hunter
sudo rkhunter --checkall

# Harden SSH configuration
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Set up automatic security updates
sudo apt-get install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades

# Disable unnecessary services
sudo systemctl disable avahi-daemon
sudo systemctl stop avahi-daemon

# Add a new user with sudo privileges
sudo adduser secureuser
sudo usermod -aG sudo secureuser

echo "Linux system initialization and hardening complete."
