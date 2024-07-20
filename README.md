# Phishing Investigation

## Objective

Conducted a thorough investigation of a phishing email incident, identifying and mitigating threats by leveraging advanced tools and techniques for comprehensive analysis and response.

### Skills Learned

- Data Extraction: Using Apache Hive to query and retrieve email data.
- Email Analysis: Employing EML Analyzer to scrutinize email content and metadata.
- Threat Intelligence: Utilizing VirusTotal for virus and malware scans.
- Dynamic Analysis: Leveraging Any.run for sandbox analysis of suspicious files.
- Incident Response: Implementing Wazuh to identify and manage compromised devices.

### Tools Used

- Apache Hive: For querying and extracting relevant ticket data.
- EML Analyzer: For detailed examination of email contents and headers.
- VirusTotal: For scanning and analyzing URLs and attachments for malware.
- Any.run: For sandbox analysis to observe the behavior of suspicious attachments.
- Wazuh: For endpoint detection and response to find and mitigate compromised devices.

### Outcome
This project successfully demonstrated the ability to identify, analyze, and mitigate phishing threats. It showcased fundamental skills in data extraction, email analysis, threat intelligence, dynamic analysis, and incident response using a combination of specialized tools and techniques.

## Steps

Open the phishing email ticket

![Screenshot 2024-07-19 160546](https://github.com/user-attachments/assets/a23eb3fa-7285-43c0-a46f-bfb096b69341)

-------------------------------------------------------------------------------------------------------

Download the phishing attatchment

![Screenshot 2024-07-19 160622](https://github.com/user-attachments/assets/b6bfe965-0b58-4e0d-8d70-fd7d0567f304)

-------------------------------------------------------------------------------------------------------

Investgate the email on eml analyzer 

![Screenshot 2024-07-19 160959](https://github.com/user-attachments/assets/7ef8c3e8-322e-4ba4-9203-b52b23a69311)

-------------------------------------------------------------------------------------------------------

![Screenshot 2024-07-19 161229](https://github.com/user-attachments/assets/ec0dece3-9577-4fa2-83ab-fe4e096c161c)

-------------------------------------------------------------------------------------------------------

![Screenshot 2024-07-19 161315](https://github.com/user-attachments/assets/62c35199-97b7-47b6-937f-46cc554c6808)

-------------------------------------------------------------------------------------------------------

input the reply to email domain into virus total

![Screenshot 2024-07-19 161526](https://github.com/user-attachments/assets/a60fddfe-38e8-448a-be7d-930cf2af4d2f)

-------------------------------------------------------------------------------------------------------

Check the MX Records for the domain

![Screenshot 2024-07-19 161657](https://github.com/user-attachments/assets/6921b89f-0930-4485-85d2-0cdb73e07040)

-------------------------------------------------------------------------------------------------------

input the domain into anyrun

![Screenshot 2024-07-19 161929](https://github.com/user-attachments/assets/d5e79f41-4330-4129-9cb3-b80fb7a9876b)

-------------------------------------------------------------------------------------------------------

Investigate domain in anyrun

![Screenshot 2024-07-19 161948](https://github.com/user-attachments/assets/c3ff1ac8-427d-4e4e-9ae7-1e2821043dec)

-------------------------------------------------------------------------------------------------------

Find the compromised device inside of Wazuh(SIEM)

![Screenshot 2024-07-19 162426](https://github.com/user-attachments/assets/1b544165-c87b-49e6-be20-1b504011f5a6)

-------------------------------------------------------------------------------------------------------

![Screenshot 2024-07-19 162849](https://github.com/user-attachments/assets/ba0f9c94-6c65-4494-bcb5-d4a322b17fac)
