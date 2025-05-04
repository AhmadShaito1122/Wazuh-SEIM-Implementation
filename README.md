Wazuh SIEM Implementation and Testing 🔍
Author: Ahmad Shaito
Technology: Wazuh SIEM + Docker + PowerShell

📝 Executive Summary
This project implements and tests the Wazuh Security Information and Event Management (SIEM) system in a simulated environment. The goal was to evaluate Wazuh's effectiveness in detecting and responding to cyber threats, including brute force attacks, failed logins, and malware. The implementation features real-time monitoring, custom rule configurations, automated responses, and integration with VirusTotal for malware detection.

🎯 Introduction
The project aimed to:

Deploy Wazuh SIEM using container technology.

Configure custom rules for threat detection (e.g., SSH failures, USB device alerts).

Test Wazuh's detection capabilities against simulated attacks (e.g., Red Atomic tests, EICAR malware file).

Analyze false positives/negatives and suggest improvements.

Wazuh's open-source nature and comprehensive features (log analysis, FIM, compliance management) make it ideal for defensive security testing.

⚙️ Implementation Details
a. Setup & Configuration
Wazuh Server:

Installed on a Kali/Ubuntu VM using Docker.

Integrated with ELK stack for log visualization.

bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh --a
Wazuh Agent:

Deployed on Windows/Ubuntu VMs.

Configured to communicate with the server via IP.

b. Rule Configuration
Custom Rules:

Example: Block IP 1.1.1.1 after repeated SSH failures (Rule ID 100001).

Active response to block IPs for 10 minutes:

xml
<active-response>
  <command>host-deny</command>
  <rules_id>100001</rules_id>
  <timeout>600</timeout>
</active-response>
File Integrity Monitoring (FIM):

Monitored critical directories for unauthorized changes.

Alerts triggered on file modifications.

c. Threat Detection
VirusTotal Integration:

Scanned files in monitored directories using VirusTotal API.

xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_API_KEY</api_key>
</integration>
USB Device Alerts:

Configured rules to detect USB insertions on Windows agents.

🕵️ Attack Scenarios & Results
1. Simulated Failed Login
Tool: PowerShell script.

Result: Wazuh detected the event (Alert Level 5, MITRE T1078).

powershell
$credential = New-Object PSCredential("NonExistentUser", (ConvertTo-SecureString "WrongPassword!" -AsPlainText -Force))
Start-Process "cmd.exe" -Credential $credential
2. Brute Force Attack
Tool: PowerShell loop with common credentials.

Result: Wazuh triggered a Level 10 alert (MITRE T1110).

3. Red Atomic Tests
Goal: Simulate advanced attacks (e.g., credential dumping).

Result: Wazuh did not detect these tests (limitation noted).

4. EICAR Malware Test
Action: Downloaded EICAR test file to a monitored directory.

Result: Detected by FIM but no malware alert (needed deeper integration).

✅ Conclusion
Wazuh successfully:
✔ Detected brute force attacks and failed logins.
✔ Automated responses (e.g., IP blocking).
✔ Monitored file integrity and USB devices.

Limitations:

Missed Red Atomic tests and EICAR file alerts.

Required manual tuning for advanced threat detection.

💡 Recommendations for Future Work
Enhance Detection:

Add rules for Red Atomic test patterns.

Improve malware detection (e.g., YARA integration).

Usability:

Develop a high-level dashboard for SOC teams.

Implement automated report generation.

Scalability:

Test in cloud environments (AWS/Azure).

🚀 How to Run the Project
Prerequisites:

Linux VM for Wazuh server.

Windows/Ubuntu VM for agents.

Docker installed.

Deploy Wazuh Server:

bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh --a
Add Agents:

Use the Wazuh dashboard to generate agent installation commands.

Configure Rules:

Modify /var/ossec/etc/ossec.conf for custom rules.

🔗 Full Report: Project_Report.docx
