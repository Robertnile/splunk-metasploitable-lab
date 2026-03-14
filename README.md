# Splunk SIEM Home Lab – Attack Simulation & Detection

This project shows how I set up a small security lab, ran real attacks on Metasploitable3, forwarded logs to Splunk, and built detections, dashboards, and alerts.

**Created by:** Nwodu Robert  
GitHub: @Robertnile  
Location: Port Harcourt, Nigeria  

**Tools used**  
- Victim: Metasploitable3 (Ubuntu)  
- Attacker: Kali Linux  
- Network Monitoring: Zeek  
- SIEM: Splunk Enterprise + Universal Forwarder  

**Note:** All IP addresses (192.168.122.x), credentials, and hostnames are from an isolated lab environment. No real systems or data were used.

## 1. Lab Network Diagram
![Network Diagram - Kali Attacker](screenshots/01_lab-network-topology.png)  
![Network Diagram - Metasploitable Victim](screenshots/04_Lab-network-topology.png.png)

(More topology images in the screenshots folder)

## 2. Setting Up Splunk & Forwarding Logs
![Splunk Started](screenshots/05_splunk started.png)  
![Splunk Status Running](screenshots/06_splunk status running terminal.png)  
![Splunk Login Page](screenshots/07_splunk login page.png)  
![Splunk Welcome Page](screenshots/08_splunk welcome page.png)  
![Created Linux Index](screenshots/09_created Linux Index.png)  
![Linux Index Appears](screenshots/10_linux index appears.png)  
![props.conf on Forwarder](screenshots/11_Creating props.conf on the Splunk forwarder.png)  
![transforms.conf on Forwarder](screenshots/12_Creating transforms.conf.png)  
![Receiving Port 9997 Enabled](screenshots/13_Receiving port 9997 eneabled.png)

## 3. Normal Traffic (Baseline)
![Baseline DNS Absent](screenshots/14_baseline-dns-absent.png)  
![Baseline HTTP](screenshots/15_baseline-http.png)  
![Baseline ICMP](screenshots/16_baseline-icmp.png)

## 4. Attacks Performed

**Nmap Scan**  
![Nmap Recon Scan on Kali](screenshots/15_nmap-recon-scan.png)  
![Nmap Scan on Target](screenshots/18_nmap-scan-on-target.png)

**SSH Brute Force**  
![SSH Brute Force Attack](screenshots/25_ssh brute force attack.png)  
![Permission Denied](screenshots/24_ssh-brute-force-permission-denied.png)  
![Failed SSH Logs on Metasploitable](screenshots/22_metasploitable-logs-failed-ssh-brute-force.png)  
![Brute Force Logs in Splunk](screenshots/23_brute-force-ingested-in-splunk.png)

## 5. Detections & Alerts

**Linux Account & Privilege Monitoring Dashboard**  
![Privilege Monitoring Dashboard](screenshots/29_Linux-Account-&-Privilelge-Monitoring---Metasploitable.png)

**Useradd / Privilege Abuse Detection**  
![Useradd Detection](screenshots/28_Splunk_Useradd_Privilege_Abuse_Detection.png)

**SSH Brute Force Alert**  
![Triggered Alert](screenshots/27_Splunk_Triggered_SSH_Brute_Force_Alert.png)

**Zeek Reverse Shell Detection**  
![Reverse Shell Detection](screenshots/31_Zeek_Reverse_Shell_Network_Detection.png)

**Nmap Scan Detection in Zeek**  
![Nmap Detection](screenshots/20_nmap_scan_detection_splunk_zeek_conn_log.png)

## All Screenshots
See every screenshot from the project here:  
→ [screenshots folder](screenshots/)

Thanks for checking out my lab!
