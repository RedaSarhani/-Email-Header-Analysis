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

**Result:** SPF PASS — the sending IP is authorized by the envelope domain's policy, which delegates authority to SendGrid.

## 2. DKIM Analysis

**Header finding:** Two DKIM signatures present:

- DKIM-Signature: d=namecheap.com; s=s1; 
- DKIM-Signature: d=sendgrid.info; s=smtpapi; 
<img width="945" height="399" alt="image" src="https://github.com/user-attachments/assets/e573a87b-86f6-4cfb-ace9-b46dd19c6a1b" />

**Process:**
- Signature was verified against its domain's public key, retrieved via:
  `dig txt s1._domainkey.namecheap.com +short`
- Signatures validated (body hash and header hash matched the public key)
<img width="945" height="241" alt="image" src="https://github.com/user-attachments/assets/0936b363-4e4e-4082-b15a-712ee7c31b45" />

<img width="861" height="409" alt="image" src="https://github.com/user-attachments/assets/198d36e5-1dc7-4b56-bc07-1ce31208823c" />

**Result:** DKIM PASS for both `namecheap.com` and `sendgrid.info` — confirms the message content wasn't altered in transit and was genuinely signed by holders of both domains' private keys.

## 3. DMARC Analysis

**Header finding:**

dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=namecheap.com
<img width="945" height="138" alt="image" src="https://github.com/user-attachments/assets/d8dee1fb-cd54-4712-8cde-a7b6a1a46ec3" />

**Process:**
- Visible From domain: `namecheap.com`
- DKIM `d=namecheap.com` → matches From domain exactly → **aligned**
- SPF domain `mailserviceemailout1.namecheap.com` → subdomain of `namecheap.com` → **aligned** (relaxed mode)
- Since at least one mechanism passed *and* aligned, DMARC passes
- Policy is `p=REJECT` — meaning if this had failed, Google would have blocked it outright, not just flagged it

Header analyzer:
<img width="877" height="411" alt="image" src="https://github.com/user-attachments/assets/4542f1de-e5e9-4969-8f7e-899d9efc6432" />

**Result:** DMARC PASS — full authentication chain is legitimate and aligned.

## Conclusion
**Sender authentication: PASS.** SPF, DKIM, and DMARC all pass and align
correctly under a strict `p=REJECT` policy — confirming this message was
genuinely sent through Namecheap's and SendGrid's authorized infrastructure,
and headers/body were not altered in transit.

Authentication passing does **not** by itself confirm the email is safe —
it only confirms sender identity and message integrity. Before closing
this as normal, additional checks would be needed:
- URL reputation check on the "Renew Now" link destination to confirm it resolves to Namecheap's real renewal flow
- Confirm no prior abuse reports against the sending IP (149.72.142.11)
  or SendGrid subuser
- Cross-reference against known phishing campaigns impersonating domain
  registrars

## SOC Action
Authentication checks are clean. Escalate for URL/link verification
before final closure. If link destination and sender reputation are
also clean, close as false positive. Do not close solely on
SPF/DKIM/DMARC pass.
