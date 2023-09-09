#!/bin/bash

start_time=$(date +%s) #Start time

#Taking the Backup before starting the Script.

sudo cp /etc/login.defs /etc/login_backup_file.defs

sudo cp /etc/modprobe.d/blacklist.conf /etc/modprobe.d/blacklist_backup_file.conf

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backup_file

sudo cp /etc/hosts /etc/hosts_backup_file

sudo cp /etc/security/limits.conf /etc/security/limits_backup_file.conf

sudo cp /etc/sysctl.conf /etc/sysctl_backup_file.conf

sudo cp /etc/default/grub /etc/default/grub_backup_file

cp /etc/issue /etc/issue_backup_file

cp /etc/issue.net /etc/issue_backup_file.net

#Perform Update and Upgrade opertaions in ubuntu

sudo apt update -y

sudo apt upgrade -y

#Install debsums utility for the verification of packages with a known good database 

if dpkg -l | grep -q 'ii  debsums'; then
    echo "debsums is already installed."
else
    echo "debsums is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y debsums
    echo "debsums has been installed."
fi

#Install the malware Scanner rkhunter

if dpkg -l | grep -q 'ii  rkhunter'; then
    echo "rkhunter is already installed."
else
    echo "rkhunter is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y rkhunter
    echo "rkhunter has been installed."
fi

#wget https://sourceforge.net/projects/rkhunter/files/latest/download -O rkhunter.tar.gz

#tar -xzvf rkhunter.tar.gz

#cd rkhunter*

#sudo ./installer.sh --install

#sudo apt-get install chkrootkit -y

#chkrootkit -V  #--> to check the version

#chrootkit --> Perform Complete Scan

#chrootkit -q--> Scan Only infected

#Perform Installation of apt-show-versions

if dpkg -l | grep -q 'ii  apt-show-versions'; then
    echo "apt-show-versions is already installed."
else
    echo "apt-show-versions is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt -y install apt-show-versions
    echo "apt-show-versions has been installed."
fi

#Installation Start File Integrity tool Aide We need to follow below

#sudo DEBIAN_FRONTEND=noninteractive apt-get install -y aide

if dpkg -l | grep -q 'ii  aide'; then
    echo "aide is already installed."
else
    echo "aide is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y aide
    echo "aide has been installed."
fi

#Version of Aide 

sudo aide -v

#Cretaing AIDE Database It Takes time more than 7 min

sudo aideinit

#Instalation Start Automation Tool cfEngine

#wget -O- http://cfengine.package-repos.s3.amazonaws.com/quickinstall/quick-install-cfengine-community.sh | sudo bash

if [ -x "$(command -v cf-agent)" ]; then
    echo "CFEngine Community is already installed."
else
    echo "CFEngine Community is not installed. Installing now..."
    wget -O- http://cfengine.package-repos.s3.amazonaws.com/quickinstall/quick-install-cfengine-community.sh | sudo bash
    echo "CFEngine Community has been installed."
fi

#for Enable Process Accounting we need to Install acct

#sudo DEBIAN_FRONTEND=noninteractive apt install acct -y

# Check and install acct
if dpkg -l | grep -q 'ii  acct'; then
    echo "acct is already installed."
else
    echo "acct is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y acct
    echo "acct has been installed."
fi

sudo /usr/sbin/accton on

#Installation start sysstat
#sudo DEBIAN_FRONTEND=noninteractive apt install sysstat -y

# Check and install sysstat
if dpkg -l | grep -q 'ii  sysstat'; then
    echo "sysstat is already installed."
else
    echo "sysstat is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y sysstat
    echo "sysstat has been installed."
fi

sudo cp /etc/default/sysstat /etc/default/sysstat_backup_file

sed -i -e 's/false/true/g' /etc/default/sysstat

sudo systemctl enable sysstat

sudo systemctl start sysstat

#Start Disabling the Protocols like dccp,sctp,tipc,rds

sudo cat <<EOF > /etc/modprobe.d/dccp.conf
install dccp /bin/true
EOF

chmod +x /etc/modprobe.d/dccp.conf

sudo cat <<EOF > /etc/modprobe.d/sctp.conf
install sctp /bin/true
EOF

chmod +x /etc/modprobe.d/sctp.conf

sudo cat <<EOF > /etc/modprobe.d/rds.conf
install rds /bin/true
EOF

chmod +x /etc/modprobe.d/rds.conf

sudo cat <<EOF > /etc/modprobe.d/tipc.conf
install tipc /bin/true
EOF

chmod +x /etc/modprobe.d/tipc.conf

#Start Disabling the USB Storage

echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

#Consider hardening SSH configuration

echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config

echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config

echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config

echo "MaxAuthTries 3" >> /etc/ssh/sshd_config

echo "MaxSessions 2" >> /etc/ssh/sshd_config

echo "Port 2030" >> /etc/ssh/sshd_config

echo "TCPKeepAlive no" >> /etc/ssh/sshd_config

echo "AllowAgentForwarding no" >> /etc/ssh/sshd_config

sed -i '/X11Forwarding yes/s/^/#/g' /etc/ssh/sshd_config

echo "X11Forwarding no" >> /etc/ssh/sshd_config

echo "PermitRootLogin no" >> /etc/ssh/sshd_config

echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config

echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

echo "LoginGraceTime 60" >> /etc/ssh/sshd_config

echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

echo "maxstartups 10:30:60" >> /etc/ssh/sshd_config

chown root:root /etc/ssh/sshd_config

chmod og-rwx /etc/ssh/sshd_config

service sshd reload

#Disabling Core Dumps

echo "* hard core 0
* soft core 0" >> /etc/security/limits.conf

echo "fs.suid_dumpable=0
kernel.core_pattern=|/bin/false" >> /etc/sysctl.conf

#command to activate changes

sudo sysctl -p /etc/sysctl.conf

#Install apparmor and configure 
#sudo DEBIAN_FRONTEND=noninteractive apt install apparmor-profiles apparmor-utils -y

if dpkg -l | grep -q 'ii  apparmor-profiles' && dpkg -l | grep -q 'ii  apparmor-utils'; then
    echo "apparmor-profiles and apparmor-utils are already installed."
else
    echo "apparmor-profiles and apparmor-utils are not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y apparmor-profiles apparmor-utils
    echo "apparmor-profiles and apparmor-utils have been installed."
fi

sudo aa-enforce /etc/apparmor.d/*

#Changing 022 to 027 UMASK Value

sed -i 's/UMASK.*/UMASK            027/' /etc/login.defs

#Changing the Pass Max Days value 

sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   120/' /etc/login.defs

#Changing the Pass_Min Days Value

sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   30/' /etc/login.defs

#Put SHA_CRYPT_MAX_ROUNDS and SHA_CRYPT_MIN_ROUNDS Value 5000 to Any

echo "SHA_CRYPT_MAX_ROUNDS 88888888" >> /etc/login.defs

echo "SHA_CRYPT_MIN_ROUNDS 88888888" >> /etc/login.defs

#Set the Password Expiry

chage -M 150 $(whoami)

chage -m 6 $(whoami)

chage -E 2023-06-05 $(whoami)

chage -I 8 $(whoami)

chage -l $(whoami)

useradd -D -f 30

chage --inactive 30 $(whoami)

#Remove DHCP Installed, if it installed

#sudo DEBIAN_FRONTEND=noninteractive apt purge isc-dhcp-server -y

# Check if isc-dhcp-server package is installed
if dpkg -l | grep -q "ii  isc-dhcp-server"; then
    echo "isc-dhcp-server is installed. Purging..."
    sudo DEBIAN_FRONTEND=noninteractive apt purge isc-dhcp-server -y
    echo "Package purged successfully."
else
    echo "isc-dhcp-server is not installed."
fi

#Remove Telnet installed, if it installed 

#sudo DEBIAN_FRONTEND=noninteractive apt purge telnet -y

# Check if telnet package is installed
if dpkg -l | grep -q "ii  telnet"; then
    echo "telnet is installed. Purging..."
    sudo DEBIAN_FRONTEND=noninteractive apt purge telnet -y
    echo "Package purged successfully."
else
    echo "telnet is not installed."
fi

#Run the following command to remove the rsync package

#sudo DEBIAN_FRONTEND=noninteractive apt purge rsync -y

# Check if rsync package is installed
if dpkg -l | grep -q "ii  rsync"; then
    echo "rsync is installed. Purging..."
    sudo DEBIAN_FRONTEND=noninteractive apt purge rsync -y
    echo "Package purged successfully."
else
    echo "rsync is not installed."
fi

#Ensure rsyslog is installed. 

#sudo DEBIAN_FRONTEND=noninteractive apt install rsyslog -y
 
echo "GRUB_CMDLINE_LINUX="audit=1"" >> /etc/default/grub

update-grub

#Disabling cramfs, freevxfs, jffs2, hfs, hfsplus, udf

sudo cat <<EOF > /etc/modprobe.d/cramfs.conf
install cramfs /bin/true
EOF

chmod +x /etc/modprobe.d/cramfs.conf

sudo cat <<EOF > /etc/modprobe.d/freevxfs.conf
install freevxfs /bin/true
EOF

chmod +x /etc/modprobe.d/freevxfs.conf

sudo cat <<EOF > /etc/modprobe.d/jffs2.conf
install jffs2 /bin/true
EOF

chmod +x /etc/modprobe.d/jffs2.conf

sudo cat <<EOF > /etc/modprobe.d/hfs.conf
install hfs /bin/true
EOF

chmod +x /etc/modprobe.d/hfs.conf

sudo cat <<EOF > /etc/modprobe.d/hfsplus.conf
install hfsplus /bin/true
EOF

chmod +x /etc/modprobe.d/hfsplus.conf

sudo cat <<EOF > /etc/modprobe.d/udf.conf
install udf /bin/true
EOF

chmod +x /etc/modprobe.d/udf.conf

echo "============= + Disabling the usb-storage + ======================"

sudo cat <<EOF > /etc/modprobe.d/usb_storage.conf
install usb-storage /bin/true
EOF

chmod +x /etc/modprobe.d/usb_storage.conf

#Installat auditd

#sudo DEBIAN_FRONTEND=noninteractive apt install auditd audispd-plugins -y

if dpkg -l | grep -q 'ii  auditd' && dpkg -l | grep -q 'ii  audispd-plugins'; then
    echo "auditd and audispd-plugins are already installed."
else
    echo "auditd and audispd-plugins are not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y auditd audispd-plugins
    echo "auditd and audispd-plugins have been installed."
fi

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

#Ensure packet redirect sending is disabled. 

echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf

echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.send_redirects=0

sysctl -w net.ipv4.conf.default.send_redirects=0 

sysctl -w net.ipv4.route.flush=1

#Ensure source routed packets are not accepted

echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf

echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf

echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.accept_source_route=0

sysctl -w net.ipv4.conf.default.accept_source_route=0

sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv6.conf.all.accept_source_route=0

sysctl -w net.ipv6.conf.default.accept_source_route=0

sysctl -w net.ipv6.route.flush=1

#Ensure ICMP redirects are not accepted. 

echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf

echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf

echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.accept_redirects=0

sysctl -w net.ipv4.conf.default.accept_redirects=0

sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv6.conf.all.accept_redirects=0

sysctl -w net.ipv6.conf.default.accept_redirects=0

sysctl -w net.ipv6.route.flush=1

#Ensure secure ICMP redirects are not accepted.

echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf

echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.secure_redirects=0

sysctl -w net.ipv4.conf.default.secure_redirects=0

sysctl -w net.ipv4.route.flush=1

#Ensure suspicious packets are logged 

echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf

echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.log_martians=1

sysctl -w net.ipv4.conf.default.log_martians=1

sysctl -w net.ipv4.route.flush=1

#Ensure broadcast ICMP requests are ignored. 

echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

sysctl -w net.ipv4.route.flush=1

#Ensure bogus ICMP responses are ignored

echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 

sysctl -w net.ipv4.route.flush=1

#Ensure Reverse Path Filtering is enabled.

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf

echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.rp_filter=1

sysctl -w net.ipv4.conf.default.rp_filter=1

sysctl -w net.ipv4.route.flush=1

#Ensure TCP SYN Cookies is enabled. 

echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

sysctl -w net.ipv4.tcp_syncookies=1

sysctl -w net.ipv4.route.flush=1

#Ensure IPv6 router advertisements are not accepted. 

echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf

echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

sysctl -w net.ipv6.conf.all.accept_ra=0

sysctl -w net.ipv6.conf.default.accept_ra=0

sysctl -w net.ipv6.route.flush=1

cp /etc/audit/auditd.conf /etc/audit/auditd_backup_file.conf

echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

Ensure core dumps are restricted

echo "* hard core 0" >> /etc/security/limits.conf

echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

sysctl -w fs.suid_dumpable=0

#Ensure address space layout randomization (ASLR) is enabled. 

echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

sysctl -w kernel.randomize_va_space=2

#Set your root password below 

passwd root

#Ensure authentication required for single user mode 

echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change | -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change | -a always,exit -F arch=b64 -S clock_settime -k time-change -a always,exit -F arch=b32 -S clock_settime -k time-change | -w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules

#Installation of FirewallD And Adding the rules 

#sudo DEBIAN_FRONTEND=noninteractive apt install firewalld -y

if dpkg -l | grep -q 'ii  firewalld'; then
    echo "firewalld is already installed."
else
    echo "firewalld is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y firewalld
    echo "firewalld has been installed."
fi

sudo systemctl enable firewalld

sudo systemctl start firewalld

sudo firewall-cmd --state

sudo firewall-cmd --add-port=2030/tcp --permanent 

sudo firewall-cmd --add-port=22/tcp --permanent 

sudo firewall-cmd --add-port=80/tcp --permanent

sudo firewall-cmd --add-port=443/tcp --permanent

sudo firewall-cmd --add-port=9630/tcp --permanent

sudo firewall-cmd --add-port=4500/udp --permanent

sudo firewall-cmd --add-port=500/udp --permanent

firewall-cmd --add-rich-rule=rule family="ipv6" drop --permanent

sudo firewall-cmd --reload

#To install the libpam-pwquality module + =========================="

#sudo DEBIAN_FRONTEND=noninteractive apt install libpam-pwquality -y

if dpkg -l | grep -q 'ii  libpam-pwquality'; then
    echo "libpam-pwquality is already installed."
else
    echo "libpam-pwquality is not installed. Installing now..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y libpam-pwquality
    echo "libpam-pwquality has been installed."
fi

cp /etc/security/pwquality.conf /etc/security/pwquality_backupfile.conf

echo "minlen = 14" >> /etc/security/pwquality.conf

echo "dcredit = -1" >> /etc/security/pwquality.conf

echo "ucredit = -1" >> /etc/security/pwquality.conf

echo "ocredit = -1" >> /etc/security/pwquality.conf

echo "lcredit = -1" >> /etc/security/pwquality.conf

#Ensure lockout for failed password attempts is configured 

#cp /etc/pam.d/common-auth /etc/pam.d/common-auth_backupfile

#echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth

#cp /etc/pam.d/common-account /etc/pam.d/common-account_backupfile

#echo "account requisite pam_deny.so account required pam_tally2.so" >> /etc/pam.d/common-account

#echo " Note: If a user has been locked out because they have reached the maximum consecutive failure count defined by deny= in the pam_tally2.so module, the user can be unlocked by issuing the command"

#/sbin/pam_tally2 -u <username> --reset

#sudo pam_tally2

#Ensure permissions on /etc/motd are configured

#chown root:root /etc/motd

#chmod u-x,go-wx /etc/motd

#Ensure sudo commands use pty.

cp /etc/sudoers /etc/sudoers_backupfile

echo "Defaults use_pty" >> /etc/sudoers

#Ensure sudo log file exists 

echo "Defaults logfile="/home/sudo.log"" >> /etc/sudoers

#Ensure default user shell timeout is 900 seconds or less.

#cp /etc/profile /etc/profile_backupfile

#echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile

#Ensure permissions on /etc/passwd- are configured

chown root:root /etc/passwd- 
chmod u-x,go-rwx /etc/passwd-

#Ensure permissions on /etc/group- are configured. 

chown root:root /etc/group- 
chmod u-x,go-rwx /etc/group-

#Ensure permissions on bootloader config are configured

chown root:root /boot/grub/grub.cfg

chmod og-rwx /boot/grub/grub.cfg

#Ensure permissions on all logfiles are configured. 

sudo find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

#Ensure only strong MAC algorithms are used.

echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config

echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config

#Again Perform Update and Upgrade At the end of the script 

sudo apt update -y

sudo apt upgrade -y

end_time=$(date +%s)

echo "Total Time Taken by the script is : " Execution time was $(($end_time - $start_time)) seconds.

echo "******************************** + END of the Script + ********************************************"
