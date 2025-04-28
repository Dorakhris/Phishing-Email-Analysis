### Phishing Email Analysis: Detecting a Spoofed Microsoft Notification

# Introduction
This project involved a detailed analysis of a suspicious email claiming to originate from Microsoft, with the subject “Microsoft account unusual signin activity.” As a SOC analyst, I investigated the email’s legitimacy to determine if it was a genuine notification or a phishing attempt. Using tools like MXToolbox, VirusTotal, and AbuseIPDB, I examined email headers, authentication protocols, and sender details, uncovering multiple indicators of spoofing. This report documents my methodology, findings, and recommendations, showcasing my skills in email spoofing analysis and threat detection. The project aligns with my expertise in Digital Forensics and Incident Response (DFIR), focusing on log analysis and threat identification.

# Objective
The goal was to assess the email’s authenticity by analyzing its headers, IP origins, authentication status, and content. The analysis aimed to identify spoofing indicators, confirm the email’s malicious nature, and propose mitigation strategies to enhance organizational email security.

# Methodology
I conducted a structured analysis of the email, focusing on the following steps:

Header Analysis: Extracted and examined email headers to trace the message’s path and identify discrepancies.
IP and Domain Analysis: Used MXToolbox and AbuseIPDB to verify the originating IP and sender domain.
Authentication Checks: Evaluated SPF, DKIM, and DMARC results to assess sender authenticity.
Content Inspection: Identified suspicious elements, such as the reply-to address and tracking pixel.
Timestamp Verification: Analyzed hop timestamps for anomalies indicating manipulation.

# Tools Used
MXToolbox: For tracing the email’s server path and analyzing headers.
VirusTotal: To check the reputation of the tracking pixel’s domain (thebandalisty.com).
AbuseIPDB: To geolocate and assess the originating IP (89.144.44.41).
Manual Header Parsing: To extract authentication results and sender details.

# Key Findings
The analysis confirmed the email as a spoofed phishing attempt, based on the following indicators:

# 1. Suspicious Originating IP
IP Address: 89.144.44.41
Location: Frankfurt am Main, Hesse, Germany (verified via AbuseIPDB).
Discrepancy: The email claimed a Russia-based sign-in, but the IP traced to a German server, not Microsoft’s infrastructure. This mismatch suggests spoofing, as legitimate Microsoft emails originate from authorized servers.

# 2. Email Path Analysis
The email traversed five servers, detailed below:
| Hop | Server | IP Address | Note |
|-----|-----------------------------|------------|------------|
| 1   | atujpdfghher.co.uk | 89.144.44.41 | Origin - suspicious domain |
| 2   | MW2NAM04FT048.mail.protection.outlook.com | 10.13.30.233 | Microsoft EOP protection |
| 3   | MW2NAM04FT048.cop-NAM04.prod.protection.outlook.com | 2603:10b6:303:85:cafe::78 | Microsoft EOP server|
| 4   | MW4PR04CA0179.outlook.office365.com | 2603:10b6:303:85::34 | Internal Microsoft server |
| 5   | IA1PR19MB6449.namprd19.prod.outlook.com | 2603:10b6:208:38b::5 | Final delivery server |


Why Significant: The origin server (atujpdfghher.co.uk) differs from the sender domain (access-accsecurity.com), a common phishing tactic to obscure the true source.
Timestamp Anomaly: A 2-second mismatch between hops 2 and 3 (00:15:46 vs. 00:15:44) suggests header manipulation or clock skew, leaning toward intentional obfuscation given other spoofing indicators.

# 3. Authentication Failures

SPF: spf=none
Why: Indicates the sending server (89.144.44.41) was not authorized for the domain atujpdfghher.co.uk, failing sender verification.

DKIM: dkim=none
Why: No digital signature was present, preventing authenticity verification.

DMARC: dmarc=permerror
Why: A misconfigured or missing DMARC record caused validation failure, allowing the email to bypass strict filtering.

Summary: The complete lack of authentication (SPF, DKIM, DMARC) is a hallmark of phishing emails, as legitimate Microsoft emails consistently pass these checks


# Summary: 
Complete authentication failure is a strong phishing indicator, unlike Microsoft’s authenticated emails.

# 4. Sender and Reply-To Mismatch
From: Microsoft account team no-reply@access-accsecurity.com
Why Suspicious: The domain access-accsecurity.com is not Microsoft-affiliated and was recently registered, a common phishing trait.

Reply-To: solutionteamrecognizd03@gmail.com
Why Suspicious: A public Gmail address is inconsistent with Microsoft’s corporate email practices, indicating an attacker-controlled account for redirecting responses.

# 5. Tracking Pixel
Domain: thebandalisty.com
Finding: VirusTotal flagged this domain as suspicious, suggesting the pixel was embedded to track user interactions, a tactic used in phishing to confirm active targets.
Why Significant: Tracking pixels are rare in legitimate corporate emails but common in malicious campaigns.

# 6. Anonymous Authentication
Header: X-MS-Exchange-Organization-AuthAs: Anonymous
Finding: The sender was unauthenticated by Microsoft’s Exchange servers, confirmed by the authentication source (MW2NAM04FT048.eop-NAM04.prod.protection.outlook.com).
Why Significant: Legitimate Microsoft emails are authenticated, not marked as anonymous.

# 7. Urgency in Subject

Subject: “Microsoft account unusual signin activity”
Finding: The subject creates a sense of urgency, a psychological tactic to prompt users to click malicious links or respond hastily.
Why Significant: Phishing emails often exploit urgency to bypass critical thinking.

# Header Snippet
Below is a sanitized excerpt of the email headers analyzed:
Received: from atujpdfghher.co.uk (89.144.44.41) by MW2NAM04FT048.mail.protection.outlook.com (10.13.30.233) at 00:15:46
Received: from MW2NAM04FT048.cop-NAM04.prod.protection.outlook.com (2603:10b6:303:85:cafe::78) by MW4PR04CA0179.outlook.office365.com (2603:10b6:303:85::34) at 00:15:44
From: Microsoft account team <no-reply@access-accsecurity.com>
Reply-To: solutionteamrecognizd03@gmail.com
Subject: Microsoft account unusual signin activity
Authentication-Results: spf=none; dkim=none; dmarc=permerror
X-MS-Exchange-Organization-AuthAs: Anonymous

This snippet highlights the suspicious origin, authentication failures, and mismatched sender/reply-to addresses.

### Recommended Actions
Based on the findings, I propose the following measures to mitigate email spoofing risks:

# Strengthen Authentication Protocols:
SPF: Configure strict SPF records to list authorized sending servers, preventing unauthorized use of your domain.
DKIM: Implement DKIM signing for all outgoing emails to ensure message integrity.
DMARC: Deploy a DMARC policy (e.g., p=reject) to instruct recipients to block or quarantine unauthenticated emails.

# Enhance Email Security:
Deploy Advanced Threat Protection (ATP) to analyze headers, content, and attachments for phishing patterns.
Use heuristic analysis to detect sophisticated spoofing attempts that bypass standard checks.

# Employee Training:
Conduct regular training on identifying phishing emails, focusing on verifying sender addresses and avoiding suspicious links.

# Security Tools:
Equip SOC teams with tools like MXToolbox and VirusTotal for efficient header and domain analysis.

# Routine Audits:
Perform periodic audits of SPF, DKIM, and DMARC configurations to ensure robust email security.

# Replicating the Analysis
To perform similar analysis:

Access Headers: View raw headers in your email client (e.g., Outlook’s “View Source”).
Trace IPs: Use AbuseIPDB to geolocate IPs (e.g., 89.144.44.41).
Analyze Path: Parse “Received” headers with MXToolbox to map server hops.
Check Authentication: Extract SPF/DKIM/DMARC from Authentication-Results using MXToolbox or dig (e.g., dig txt access-accsecurity.com).
Inspect Content: Verify “From” and “Reply-To” addresses; scan URLs with VirusTotal.
Verify Timestamps: Check “Received” timestamps for anomalies.

# Conclusion
This phishing email analysis project demonstrated my ability to detect and analyze spoofed emails using industry-standard tools and methodologies. By identifying critical indicators—suspicious IP origins, authentication failures, mismatched domains, and tracking pixels—I confirmed the email as a phishing attempt. The findings underscore the importance of robust email authentication and proactive security measures. This project enhances my portfolio as a SOC analyst, showcasing my expertise in threat detection, log analysis, and DFIR. I welcome feedback or contributions to improve this analysis, and I’m eager to apply these skills in SOC or incident response roles.

# References
MXToolbox: mxtoolbox.com

VirusTotal: virustotal.com

AbuseIPDB: abuseipdb.com



