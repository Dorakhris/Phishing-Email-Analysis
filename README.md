### Phishing Email Analysis: Detecting a Spoofed Microsoft Notification

# Introduction
This project documents my analysis of a suspicious email with the subject “Microsoft account unusual signin activity,” claiming to originate from Microsoft. As a SOC analyst at CyberTech Solutions, I systematically investigated the email’s legitimacy to determine if it was a genuine notification or a phishing attempt. Using MXToolbox, VirusTotal, and AbuseIPDB, I analyzed email headers, IP origins, authentication protocols, and content, identifying multiple indicators of spoofing. This report details my methodology, findings, and recommendations, highlighting my expertise in email spoofing analysis and Digital Forensics and Incident Response (DFIR).

# Objective
The objective was to evaluate the email’s authenticity by examining its headers, IP origins, authentication status, and content, confirming its malicious nature and proposing mitigation strategies to strengthen email security.

# Methodology
I followed a structured approach to analyze the email:

Header Analysis: Parsed email headers to trace the message’s path and identify anomalies.
IP and Domain Analysis: Verified the originating IP and sender domain using MXToolbox and AbuseIPDB.
Authentication Verification: Checked SPF, DKIM, and DMARC results for sender authenticity.
Content Examination: Inspected the reply-to address and embedded tracking pixel for malicious indicators.
Timestamp Analysis: Evaluated hop timestamps for irregularities suggesting manipulation.

# Tools Used

MXToolbox: Traced server paths and analyzed headers.
VirusTotal: Assessed the tracking pixel’s domain reputation.
AbuseIPDB: Geolocated and evaluated the originating IP.
Manual Parsing: Extracted authentication and sender details from headers.

# Key Findings
The analysis confirmed the email as a spoofed phishing attempt, based on the following indicators:
# 1. Suspicious Originating IP

IP: 89.144.44.41
Location: Frankfurt am Main, Germany (via AbuseIPDB)
Issue: The IP, tied to a non-Microsoft server, contradicted the email’s claimed Russia-based sign-in, indicating spoofing.

# 2. Email Path Analysis
The email passed through five servers:
| Hop | Server | IP Address | Note |
|-----|-----------------------------|------------|------------|
| 1   | atujpdfghher.co.uk | 89.144.44.41 | Suspicious origin |
| 2   | MW2NAM04FT048.mail.protection.outlook.com | 10.13.30.233 | Microsoft EOP |
| 3   | MW2NAM04FT048.cop-NAM04.prod.protection.outlook.com | 2603:10b6:303:85:cafe::78 | Microsoft EOP |
| 4   | MW4PR04CA0179.outlook.office365.com | 2603:10b6:303:85::34 | Internal server |
| 5   | IA1PR19MB6449.namprd19.prod.outlook.com | 2603:10b6:208:38b::5 | Delivery server |



Why Significant: The origin server (atujpdfghher.co.uk) differs from the sender domain (access-accsecurity.com), a phishing tactic to mask the source.
Timestamp Anomaly: A 2-second mismatch (00:15:46 to 00:15:44) between hops 2 and 3 suggests header manipulation, uncommon in Microsoft’s synchronized infrastructure.

# 3. Authentication Failures

SPF: spf=none
Why: The sending server was not authorized for atujpdfghher.co.uk, failing sender verification.

DKIM: dkim=none
Why: No digital signature, preventing authenticity confirmation.

DMARC: dmarc=permerror
Why: A misconfigured DMARC record caused validation failure, bypassing strict filtering.


# Summary: 
Complete authentication failure is a strong phishing indicator, unlike Microsoft’s authenticated emails.

# 4. Sender and Reply-To Mismatch
From: Microsoft account team no-reply@access-accsecurity.com
Issue: access-accsecurity.com is not Microsoft-affiliated and recently registered.

Reply-To: solutionteamrecognizd03@gmail.com
Issue: A Gmail address is inconsistent with Microsoft’s corporate practices, suggesting an attacker-controlled account.

# 5. Tracking Pixel
Domain: thebandalisty.com
Issue: Flagged as suspicious by VirusTotal, indicating intent to track user interactions, a common phishing technique.

# 6. Anonymous Authentication
Header: X-MS-Exchange-Organization-AuthAs: Anonymous
Issue: The sender was unauthenticated, verified by MW2NAM04FT048.eop-NAM04.prod.protection.outlook.com, unlike legitimate Microsoft emails.

# 7. Urgency in Subject

Subject: “Microsoft account unusual signin activity”
Issue: Creates urgency to prompt user action, a phishing tactic to exploit trust.

# Header Snippet
Received: from atujpdfghher.co.uk (89.144.44.41) by MW2NAM04FT048.mail.protection.outlook.com (10.13.30.233); 00:15:46
Received: from MW2NAM04FT048.cop-NAM04.prod.protection.outlook.com (2603:10b6:303:85:cafe::78) by MW4PR04CA0179.outlook.office365.com (2603:10b6:303:85::34); 00:15:44
From: Microsoft account team <no-reply@access-accsecurity.com>
Reply-To: solutionteamrecognizd03@gmail.com
Subject: Microsoft account unusual signin activity
Authentication-Results: spf=none; dkim=none; dmarc=permerror
X-MS-Exchange-Organization-AuthAs: Anonymous

This illustrates the suspicious origin, authentication failures, and mismatched addresses.

### Recommended Actions
To mitigate email spoofing, I recommend:

# Authentication Protocols:
Configure strict SPF records for authorized servers.
Implement DKIM signing for email integrity.
Deploy DMARC with a p=reject policy to block unauthenticated emails.

# Security Enhancements:
Use Advanced Threat Protection for header and content analysis.
Apply heuristic analysis to detect sophisticated phishing.

# Training:
Train employees to verify sender addresses and avoid suspicious links.

# Tools:
Equip SOC teams with MXToolbox and VirusTotal for efficient analysis.

# Audits:
Regularly audit SPF, DKIM, and DMARC configurations.



# Replicating the Analysis
To perform similar analysis:

Access Headers: View raw headers in your email client (e.g., Outlook’s “View Source”).
Trace IPs: Use AbuseIPDB to geolocate IPs (e.g., 89.144.44.41).
Analyze Path: Parse “Received” headers with MXToolbox to map server hops.
Check Authentication: Extract SPF/DKIM/DMARC from Authentication-Results using MXToolbox or dig (e.g., dig txt access-accsecurity.com).
Inspect Content: Verify “From” and “Reply-To” addresses; scan URLs with VirusTotal.
Verify Timestamps: Check “Received” timestamps for anomalies.

# Conclusion
This project highlights my ability to detect email spoofing through systematic header analysis, IP verification, and authentication checks. By identifying a phishing attempt masquerading as a Microsoft notification, I demonstrated proficiency in DFIR, threat detection, and log analysis. The report serves as a portfolio piece for my GitHub, showcasing my SOC analyst skills. I invite feedback to refine this analysis and am eager to contribute these capabilities to cybersecurity roles.

# References
MXToolbox

VirusTotal

AbuseIPDB



