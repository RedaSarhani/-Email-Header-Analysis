# Email Header Analysis - SPF/DKIM/DMARC Verification

## Scenario
A domain renewal notice was received at `rachel.jones@cosmicfusiontech.com`,
claiming to be from Namecheap and warning that `cosmicfusiontech.com` would
expire in 7 days. The subject line and body use urgency-based language
("You've Only Got 7 Days Left") — a pattern commonly seen in phishing.
Rather than judge by appearance, I traced the full authentication chain
in the raw headers to determine whether this was legitimate or spoofed.

## Objective
Determine email authenticity using SPF, DKIM, and DMARC header analysis —
without relying on visual inspection alone.

## Tools Used
- Raw email source (.eml headers)
- `dig` / `nslookup` for manual DNS TXT record verification
- Online header analyzer (MXToolbox / Google Admin Toolbox)

## 1. SPF Analysis

**Header finding:**
- spf=pass smtp.mailfrom="bounces+...@mailserviceemailout1.namecheap.com"
- Received-SPF: pass ... designates 149.72.142.11 as permitted sender
<img width="945" height="155" alt="image" src="https://github.com/user-attachments/assets/8f2eb9c8-150f-4818-94d5-e4268e230302" />

**Process:**
- The envelope sender (`smtp.mailfrom`) domain is `mailserviceemailout1.namecheap.com`
- Google checked the SPF record for that domain against the connecting IP `149.72.142.11`
- Manually verified via `dig txt mailserviceemailout1.namecheap.com +short` → SPF record includes `sendgrid.net`
- Checked SendGrid's SPF record → contains `149.72.0.0/16`, which covers `149.72.142.11`

<img width="945" height="790" alt="image" src="https://github.com/user-attachments/assets/91155d35-5bc9-40b1-9506-f282d054903e" />

- Manual Verification: SPF record includes `sendgrid.net`
<img width="945" height="94" alt="image" src="https://github.com/user-attachments/assets/1651598d-6437-48c9-b633-2f871a5fc839" />

- SendGrid's SPF records contain `149.72.0.0/16`
<img width="945" height="80" alt="image" src="https://github.com/user-attachments/assets/4e2b612b-adad-49f9-a11f-7b86fc1dff6f" />


