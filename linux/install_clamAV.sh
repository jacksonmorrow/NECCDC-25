#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or using sudo."
  exit 1
fi

# Update the system
echo "Updating the system..."
apt-get update -y
apt-get upgrade -y

# Install ClamAV and its tools
echo "Installing ClamAV..."
apt-get install -y clamav clamav-daemon clamav-freshclam clamtk

# Stop the ClamAV services to configure them
echo "Stopping ClamAV services for configuration..."
systemctl stop clamav-freshclam
systemctl stop clamav-daemon

# Update the ClamAV virus database
echo "Updating ClamAV virus database..."
freshclam

# Configure ClamAV to scan system directories
echo "Configuring ClamAV..."
# Create a custom scan configuration
cat > /etc/clamav/clamd.conf <<EOF
LogFile /var/log/clamav/clamav.log
LogTime yes
LogSyslog yes
LogRotate yes
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket yes
MaxConnectionQueueLength 30
MaxThreads 50
ReadTimeout 300
User clamav
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanArchive yes
ArchiveBlockEncrypted no
EOF

# Restart ClamAV services
echo "Starting ClamAV services..."
systemctl start clamav-freshclam
systemctl start clamav-daemon

# Enable ClamAV services to start on boot
echo "Enabling ClamAV services to start on boot..."
systemctl enable clamav-freshclam
systemctl enable clamav-daemon

# Perform a full system scan
echo "Performing a full system scan..."
clamscan -r --bell -i /

# Schedule daily scans using cron
echo "Scheduling daily scans with cron..."
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/clamscan -r --bell -i / >> /var/log/clamav/daily_scan.log") | crontab -

echo "ClamAV installation, configuration, and initial scan complete."
