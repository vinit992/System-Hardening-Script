# System-Hardening-Script
# Ubuntu Hardening Script 

## Description
This script is designed to enhance the security of an Ubuntu system by implementing various hardening measures. It automates the process of configuring and securing the system to reduce vulnerabilities and potential security risks.

## Features
This script performs a number of hardening measures on an Ubuntu server. The steps performed by the script are:

  Update the system to the latest security patches
  Disable unnecessary services like dccp, sctp, tipc, rds, usb storage, core dumps, cramfs, freevxfs, jffs2, hfs, hfsplus, udf, etc.
  Configure firewallD rules to restrict access to the server
  Install and configure AppArmor, rkhunter, aide, apt-show-versions, automation tool cfEngine, sysstat, Accounting Process acct, auditd, etc.
  Enable SSH key-based authentication and make changes in the sshd_config files to restrict access through ssh
  Set a strong password for the root user and also set the expiry of password of host
  Add the Banner also To Access the Authorized uses only
  Ensure packet redirect sending is disabled
  Ensure source routed packets are not accepted
  Ensure ICMP and Secure ICMP redirects are not accepted, Ensure broadcast ICMP requests are ignored, Ensure bogus ICMP responses are ignored
  Ensure suspicious packets are logged, 
  Ensure Reverse Path Filtering is enabled, 
  Ensure TCP SYN Cookies is enabled, Ensure IPv6 router advertisements are not accepted
  Ensure permissions on /etc/passwd-, /etc/group-, bootloader config, all logfiles are configured

  This Ubuntu hardening script follows industry-recognized security standards and guidelines to enhance system security. The script aligns with the following security standards:

- [CIS (Center for Internet Security) Ubuntu Linux Benchmark](https://www.cisecurity.org/cis-benchmarks/): The script incorporates recommendations from the CIS benchmark to ensure a secure Ubuntu configuration.
  
 - [Lynis Security Controls](https://cisofy.com/lynis/controls/): The script incorporates controls and recommendations from Lynis, a widely recognized open-source security auditing tool, to perform system assessments and improve security posture.

Please note that this script can be customized to meet specific compliance needs based on your organization's requirements.

## Usage
1. [Provide step-by-step instructions on how to use your script]
2. [Include any prerequisites or dependencies]
3. [Provide examples of command usage]
