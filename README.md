# Data-Exfiltration

## **Data Exfiltration from PIP'd Employee** 

## **Scenario:**  
An employee named John Doe, working in a sensitive department, was recently placed on a performance improvement plan (PIP). After displaying concerning behavior, management suspects John may be planning to steal proprietary information and leave the company. The investigation involves analyzing activities on John’s corporate device (`badactor`) using Microsoft Defender for Endpoint (MDE).  

## **Incident Summary and Findings**  

### **Timeline Overview**  
1. **Archiving Activity:**  
   - **Observed Behavior:** Frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  
![image](https://github.com/user-attachments/assets/dd243128-ea15-4bbb-82bb-ccb091e78f95)

   - **Defender for Endpoint**

![image](https://github.com/user-attachments/assets/6703c855-6bab-4c73-bf4f-39efcb09e4df)

2. **Process Analysis:**  
   - **Observed Behavior:** Took one of the instances of a zip file being created, searched under thattime frame in DeviceProcessEvents table for anything happening 2 minutes before the archive was created and 2 mintutes after. I discoverd around the same time. a powershellscript silently installed 7zip and then used 7zip to zip up employee data into an archive.
   - **Detection Query (KQL):**  

![image](https://github.com/user-attachments/assets/47b1d237-7cbd-46cf-834d-9d38c5c6bd30)

3. **Network Exfiltration Check:**  
   - **Observed Behavior:** No evidence of data exfiltration via network logs during the time frame.  
   - **Detection Query (KQL):**  
![image](https://github.com/user-attachments/assets/242d7cda-a7d8-4b2a-957e-71c6c0b4cc66)

4. **Response:**  
   - Shared findings with the manager, highlighting automated archive creation and no immediate signs of exfiltration. The device was isolated, awaiting further instructions.

## **MITRE ATT&CK Framework TTPs**  

| **Tactic**           | **Technique**                                                                                     | **ID**            | **Description**                                                                                                                                                 |  
|-----------------------|---------------------------------------------------------------------------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| **Execution**      | PowerShell                                                                                       | T1059.001         | PowerShell scripts were used to silently install 7-Zip and execute file compression commands.                                                                   |  
| **Collection**      | Archive Collected Data                                                                           | T1560.001         | Employee data was compressed into `.zip` files using 7-Zip, possibly for easier handling or exfiltration.                                                       |  
| **Exfiltration**    | Exfiltration Over Alternative Protocol                                                           | T1048             | Although no network exfiltration was detected, the technique aligns with the potential misuse of alternate protocols for stealthy data transfer.                |  
| **Discovery**       | Process Discovery                                                                                | T1057             | Processes were reviewed to identify activities surrounding the installation and use of 7-Zip for archiving.                                                     |  

---

### **Next Steps**  
1. Monitor John’s account activity for unusual access or privilege escalation.  
2. Implement DLP (Data Loss Prevention) measures to alert on potential data exfiltration.  
3. Escalate findings to management and recommend a follow-up review of John's device for additional forensic artifacts.  

## Steps to Reproduce:
1. Provision a virtual machine within Azure.
2. Ensure the device is actively communicating or available on the internet. 
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs, network traffic logs, exposure alert are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---
