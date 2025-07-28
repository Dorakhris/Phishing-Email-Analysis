# Project Title
Forensic Analysis of a Microsoft-Impersonating Phishing Email



## Case Summary
- **Objective:** My objective was to perform a deep forensic analysis of a suspected phishing email impersonating a Microsoft security alert. I aimed to definitively determine its legitimacy, dissect the attacker's techniques, and extract actionable intelligence for defense.
- **Scope:** The scope was a single suspicious email file (`.eml`) purported to be from Microsoft, including its full headers and body content.
- **Tools Used:** MXToolbox, VirusTotal, and various email header analyzers.
- **Outcome:** I conclusively identified the email as a malicious phishing attempt based on a complete failure of authentication protocols and the use of deceptive infrastructure. I provided clear Indicators of Compromise (IoCs) and strategic recommendations to prevent similar attacks.



## Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Email Header Analyzer** | Parsing and visualizing the complex email headers to trace the message path and check authentication results. |
| **MXToolbox** | Looking up DNS records (SPF, DKIM, DMARC) and checking the reputation of the sending IP address. |
| **VirusTotal** | Checking the reputation of all IPs and domains found within the email headers and body. |
| **OS/VM Used** | Windows 11 analysis workstation. |



## Case Background
I was tasked with investigating a suspicious email that had been reported by an employee. The email, bearing the subject "Microsoft account unusual signin activity," was engineered to create a sense of urgency and alarm. My role as the analyst was to deconstruct this email from its raw source, analyze every component from the headers down to the payload, and provide a definitive verdict on its legitimacy to prevent a potential security incident.



## Methodology
My investigation followed a standard email threat analysis workflow to ensure a thorough and accurate verdict.

1.  **Header Isolation and Analysis:** I began by extracting the full, raw email headers. I meticulously traced the `Received:` path to understand the email's journey from the source server to our inbox.
2.  **Authentication Protocol Verification:** I examined the `Authentication-Results` header. I then used MXToolbox to manually query the SPF, DKIM, and DMARC policies for the purported sender domains to verify the automated check results.
3.  **Infrastructure Reputation Check:** I extracted every IP address and domain name from the headers and email body. Each artifact was cross-referenced in VirusTotal and other OSINT sources to check for prior associations with malicious activity.
4.  **Content and Payload Analysis:** I carefully inspected the email's body, looking for social engineering tactics, grammatical errors, and hidden elements. I identified an embedded tracking pixel and analyzed its source domain.
5.  **Reporting and IoC Extraction:** After confirming the email's malicious nature, I compiled my findings, extracted a clear list of Indicators of Compromise (IoCs), and formulated a set of actionable recommendations for defense.



## Findings & Evidence
My analysis revealed multiple, independent indicators of malicious intent. The attacker layered several deceptive techniques, from technical spoofing to social engineering, to craft a convincing lure.

| Indicator | Finding | Implication (Why it Matters) |
| :--- | :--- | :--- |
| **Authentication Failure** | SPF, DKIM, and DMARC all failed or returned an error. | The sender's identity could not be verified, and the message lacked integrity checks. This is the strongest technical indicator of a spoofed email. |
| **Suspicious Sender IP** | Originated from `89.144.44.41` (Germany), not Microsoft infrastructure. | Legitimate Microsoft emails originate from their known servers. An unrelated server IP proves the sender is not who they claim to be. |
| **Sender & Reply-To Mismatch** | `From:` a non-Microsoft domain (`access-accsecurity.com`). <br> `Reply-To:` a generic Gmail address. | Attackers use fake "From" addresses for deception and a separate "Reply-To" address they control to capture responses from victims. |
| **Malicious Tracking Pixel** | Embedded pixel linked to `thebandalisty.com`, a suspicious domain. | This is used to verify that a victim's email address is active and that they have opened the message, flagging them for further targeting. |
| **Anonymous Authentication** | The `X-MS-Exchange-Organization-AuthAs` header was `Anonymous`. | Microsoft's own internal systems did not authenticate the sender, treating it as an untrusted, external message. |



##  Logs
Below is a snippet representing the `Authentication-Results` header from the analyzed email. This single block of text contains definitive proof of the spoofing attempt.


```
Authentication-Results
       dkim=none;
       spf=none (sender IP is 89.144.44.41);
       dmarc=permerror (domain=atujpdfghher.co.uk) header.from=access-accsecurity.com;
```

This log clearly shows the failure of all three major email authentication protocols.



## Conclusion
The investigation confirmed that the email was a targeted phishing attempt designed to harvest user credentials or trick users into engaging with the attacker. The complete failure of SPF, DKIM, and DMARC, combined with the use of non-corporate infrastructure, provided an undeniable technical verdict.

**Impact:** A successful attack would lead to user account compromise, granting an attacker a foothold in the organization. This could result in data theft, financial fraud, or be used as a launchpad for more sophisticated attacks.

**Recommendations:**
1.  **Immediate Containment:** Block the sending IP (`89.144.44.41`) and all associated domains (`access-accsecurity.com`, `thebandalisty.com`, `atujpdfghher.co.uk`) at the email gateway and network firewall.
2.  **Architectural Hardening:** Enforce a strict DMARC policy (`p=reject`) to instruct mail servers to reject any email that fails authentication checks, preventing such messages from ever reaching a user's inbox.
3.  **Human Defense:** Continue to invest in security awareness training that empowers users to spot phishing red flags and reinforces the procedure for reporting suspicious emails.



## Lessons Learned / Reflection
This case was a perfect example of why a defense-in-depth security model is crucial. While the email's content was crafted to appear legitimate to an end-user, the technical evidence contained within the headers provided a clear and indisputable verdict of "malicious." It reinforced that even without a malicious attachment, a well-crafted phishing email is a significant threat.

Moving forward, I would focus on automating the extraction and analysis of these indicators. A simple Python script could parse email headers, extract all IPs and domains, and query APIs like VirusTotal to significantly accelerate the triage process for future incidents.



## References
- [RFC 7208 - Sender Policy Framework (SPF)](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 6376 - DomainKeys Identified Mail (DKIM)](https://datatracker.ietf.org/doc/html/rfc6376)
- [DMARC.org - DMARC Overview](https://dmarc.org/overview/)



#PhishingAnalysis #EmailSecurity #DFIR #ThreatAnalysis #SOC #Cybersecurity #ThreatIntelligence
