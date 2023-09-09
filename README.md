# System-Hardening-Script
# Ubuntu Hardening Script 

# Description
This script is designed to enhance the security of an Ubuntu system by implementing various hardening measures. It automates the process of configuring and securing the system to reduce vulnerabilities and potential security risks.

# Features
This script performs a number of hardening measures on an Ubuntu server. The steps performed by the script are:

  - Update the system to the latest security patches
  - Disable unnecessary services like dccp, sctp, tipc, rds, usb storage, core dumps, cramfs, freevxfs, jffs2, hfs, hfsplus, udf, etc.
  - Configure firewallD rules to restrict access to the server
  - Install and configure AppArmor, rkhunter, aide, apt-show-versions, automation tool cfEngine, sysstat, Accounting Process acct, auditd, etc.
  - Enable SSH key-based authentication and make changes in the sshd_config files to restrict access through ssh
  - Set a strong password for the root user and also set the expiry of password of host
  - Add the Banner also To Access the Authorized uses only
  - Ensure packet redirect sending is disabled
  - Ensure source routed packets are not accepted
  - Ensure ICMP and Secure ICMP redirects are not accepted, Ensure broadcast ICMP requests are ignored, Ensure bogus ICMP responses are ignored
  - Ensure suspicious packets are logged, 
  - Ensure Reverse Path Filtering is enabled, 
  - Ensure TCP SYN Cookies is enabled, Ensure IPv6 router advertisements are not accepted
  - Ensure permissions on /etc/passwd-, /etc/group-, bootloader config, all logfiles are configured

  This Ubuntu hardening script follows industry-recognized security standards and guidelines to enhance system security. The script aligns with the following security standards:

- [CIS (Center for Internet Security) Ubuntu Linux Benchmark](https://www.cisecurity.org/cis-benchmarks/): The script incorporates recommendations from the CIS benchmark to ensure a secure Ubuntu configuration.
  
 - [Lynis Security Controls](https://cisofy.com/lynis/controls/): The script incorporates controls and recommendations from Lynis, a widely recognized open-source security auditing tool, to perform system assessments and improve security posture.

Please note that this script can be customized to meet specific compliance needs based on your organization's requirements.

# Usage

### Prerequisites

Before running the Ubuntu hardening script, ensure that you have the following prerequisites in place:

- **A Fresh Ubuntu Installation:** This script is intended for use on a clean Ubuntu system. Make sure you have a fresh installation to avoid conflicts with existing configurations.

- **Root or Sudo Access:** You should have root access or sudo privileges on the target system to execute the script effectively.

- **Internet Connectivity:** Ensure that the system has internet connectivity to download necessary packages and updates during the hardening process.

### Dependencies

The script leverages the following tools to perform system assessments and security improvements:

- **Lynis:** We utilize Lynis, an open-source security auditing tool, to analyze the system's security posture and suggest improvements. You can learn more about Lynis [here](https://cisofy.com/lynis/).

- **Wazuh Agent:** Wazuh is an open-source security monitoring platform. The Wazuh agent is used to enhance security monitoring and threat detection capabilities. More information about Wazuh can be found [here](https://wazuh.com/).

### Running the Script

Follow these steps to run the Ubuntu hardening script:

1. **Clone the Repository:**
   ```shell
   git clone https://github.com/vinit992/System-Hardening-Script.git

- Navigate to the Script Directory:
  cd System-Hardening-Script
  
- Execute the Script:
  ./Hardening.sh
  
The script may prompt you for specific configuration options or provide recommendations based on Lynis and Wazuh assessments. Follow the on-screen instructions to complete the hardening process.
