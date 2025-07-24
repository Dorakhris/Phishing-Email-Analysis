# Phishing Incident Analysis

## Executive Summary
This report details the forensic analysis of a suspicious email engineered to impersonate a "Microsoft account unusual signin activity" notification. The investigation determined that the email was **unequivocally a malicious phishing attempt**, designed to deceive the recipient through social engineering and spoofing tactics.

The verdict is based on a complete failure of standard email authentication protocols (SPF, DKIM, DMARC), the use of non-Microsoft infrastructure for sending and tracking, and a clear mismatch between the claimed sender identity and the actual reply-to address.

Using tools like MXToolbox and VirusTotal, I traced the email's path, analyzed its headers, and deconstructed its components to expose the attacker's methods. This case study demonstrates a methodical approach to email threat analysis and highlights the critical importance of a defense-in-depth security posture.

## Threat Assessment at a Glance
The email was confirmed as malicious based on multiple, high-confidence indicators.

| Indicator | Finding | Implication (Why it Matters) |
| :--- | :--- | :--- |
| **Authentication Failure** | SPF, DKIM, and DMARC all failed or returned an error. | The sender's identity could not be verified, and the message lacked integrity checks. This is the strongest technical indicator of a spoofed email. |
| **Suspicious Sender IP** | Originated from `89.144.44.41` (Germany), not a Microsoft server. | Legitimate Microsoft emails originate from their known infrastructure. An unrelated server IP proves the sender is not who they claim to be. |
| **Sender & Reply-To Mismatch** | `From:` a non-Microsoft domain (`access-accsecurity.com`). <br> `Reply-To:` a generic Gmail address. | Attackers use fake "From" addresses for deception and a separate "Reply-To" address they control to capture responses from victims. |
| **Malicious Tracking Pixel** | Embedded pixel linked to `thebandalisty.com`, a suspicious domain. | This is used to verify that a victim's email address is active and that they have opened the message, flagging them for further targeting. |
| **Anonymous Authentication** | The `X-MS-Exchange-Organization-AuthAs` header was marked as `Anonymous`. | Microsoft's internal systems did not authenticate the sender, treating it as an untrusted, external message. |

---

## Detailed Analysis of Attacker Techniques

### 1. Failure of Email Authentication Protocols
The email failed all three core authentication checks, which is a hallmark of a phishing campaign.
*   **SPF (Sender Policy Framework):** `spf=none`. This means the domain (`atujpdfghher.co.uk`) had no published SPF record, so the receiving server could not verify if the sending IP (`89.144.44.41`) was authorized to send emails on its behalf.
*   **DKIM (DomainKeys Identified Mail):** `dkim=none`. The email lacked a DKIM digital signature, meaning its content integrity could not be verified. An attacker could have modified the message in transit without detection.
*   **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** `dmarc=permerror`. The DMARC check failed due to a misconfiguration or missing policy. A properly configured DMARC policy would have instructed the receiving server to quarantine or reject this unauthenticated email.

### 2. Deceptive Sender Identity & Infrastructure
The attacker constructed a deceptive identity using disposable and untrustworthy infrastructure.
*   **IP Origin:** The sending IP `89.144.44.41` geolocates to Germany, which contradicts the email's claim of a sign-in from Russia and is not associated with Microsoft's email services.
*   **Sender Domain:** The "From" address used `access-accsecurity.com`, a domain unaffiliated with Microsoft and likely registered recently for the sole purpose of this campaign.
*   **Reply-To Address:** The reply-to address (`solutionteamrecognizd03@gmail.com`) was a generic Gmail account, a tactic used to ensure any replies from victims are sent directly to the attacker, not to Microsoft.

### 3. Malicious Content and Social Engineering
The email's content was designed to manipulate the user into taking immediate, unsafe action.
*   **Urgency:** The subject line "Microsoft account unusual signin activity" creates a sense of alarm, pressuring the user to react quickly without scrutinizing the email's legitimacy.
*   **Tracking Pixel:** The hidden pixel hosted on `thebandalisty.com` (flagged as suspicious by VirusTotal) serves as a reconnaissance tool for the attacker, confirming which email addresses are active and which users are susceptible to opening phishing messages.

---

## Strategic Recommendations
Based on this analysis, the following actions are recommended to strengthen defenses against similar attacks.

| Strategy | Action Items |
| :--- | :--- |
| **Immediate Containment** | Block the sending IP (`89.144.44.41`) and domains (`access-accsecurity.com`, `thebandalisty.com`, `atujpdfghher.co.uk`) at the email gateway and firewall. |
| **Architectural Hardening** | 1. Implement a strict **DMARC policy** (`p=reject`) to prevent unauthenticated emails from reaching user inboxes. <br> 2. Ensure **SPF** and **DKIM** records are correctly configured and enforced for all domains. <br> 3. Deploy an **Advanced Threat Protection (ATP)** solution that performs deep header analysis and sandboxing of URLs/attachments. |
| **Human Layer Defense** | Conduct regular, mandatory security awareness training that specifically teaches employees how to identify phishing red flags, such as sender mismatches and grammatical errors, and how to report suspicious emails. |

---

## Conclusion
This investigation successfully deconstructed a sophisticated phishing email, confirming its malicious nature through methodical analysis of its headers, infrastructure, and content. The complete failure of authentication protocols, combined with multiple deceptive tactics, provided definitive proof of a spoofing attempt. This project highlights my ability to apply DFIR principles and use standard SOC tools to analyze threats, protect organizational assets, and provide actionable recommendations for improving security posture.
