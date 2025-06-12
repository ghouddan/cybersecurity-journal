# Room 1
## Phishing Analysis Fundamentals
#### Email Protocol
- **SMTP** (**Simple Mail Transfer Protocol)** - It is utilized to handle the sending of emails. 587
- **POP3 (Post Office Protocol)** - Is responsible transferring email between a client and a mail server. 995
- **IMAP (Internet Message Access Protocol)** - Is responsible transferring email between a client and a mail server. 993
**POP3**
- Emails are downloaded and stored on a single device.
- Sent messages are stored on the single device from which the email was sent.
- Emails can only be accessed from the single device the emails were downloaded to.
- If you want to keep messages on the server, make sure the setting "Keep email on server" is enabled, or all messages are deleted from the server once downloaded to the single device's app or software.

**IMAP**
- Emails are stored on the server and can be downloaded to multiple devices.
- Sent messages are stored on the server.
- Messages can be synced and accessed across multiple devices

#### Phishing type 
- **[Spam](https://www.proofpoint.com/us/threat-reference/spam)** - unsolicited junk emails sent out in bulk to a large number of recipients. The more malicious variant of Spam is known as **MalSpam**.
- **[Phishing](https://www.proofpoint.com/us/threat-reference/phishing)** -  emails sent to a target(s) purporting to be from a trusted entity to lure individuals into providing sensitive information. 
- **[Spear phishing](https://www.proofpoint.com/us/threat-reference/spear-phishing) -** takes phishing a step further by targeting a specific individual(s) or organization seeking sensitive information.  
- **[Whaling](https://www.rapid7.com/fundamentals/whaling-phishing-attacks/)** - is similar to spear phishing, but it's targeted specifically to C-Level high-position individuals (CEO, CFO, etc.), and the objective is the same. 
- [**Smishing**](https://www.proofpoint.com/us/threat-reference/smishing) - takes phishing to mobile devices by targeting mobile users with specially crafted text messages. 
- [**Vishing**](https://www.proofpoint.com/us/threat-reference/vishing) - is similar to smishing, but instead of using text messages for the social engineering attack, the attacks are based on voice calls.
#### what to collect from the email 
- Sender email address
- Sender IP address
- Reverse lookup of the sender IP address
- Email subject line
- Recipient email address (this information might be in the CC/BCC field)
- Reply-to email address (if any)
- Date/time
Afterward, we draw our attention to the email body and attachment(s) (if any).
- Any URL links (if an URL shortener service was used, then we'll need to obtain the real URL link)
- The name of the attachment
	- The hash value of the attachment (hash type MD5 or SHA256, preferably the latter) 
#### Phishing prevention 
##### **Sender Policy Framework (SPF)**
	_Sender Policy Framework (SPF) is used to authenticate the sender of an email. With an SPF record in place, Internet Service Providers can verify that a mail server is authorized to send email for a specific domain. An SPF record is a DNS TXT record containing a list of the IP addresses that are allowed to send email on behalf of your domain._
How does a basic SPF record look like?
`v=spf1 ip4:127.0.0.1 include:_spf.google.com -all`
An explanation for the above record:
- `v=spf1` -> This is the start of the SPF record
- `ip4:127.0.0.1` -> This specifies which IP (in this case version IP4 & not IP6) can send mail
- `include:_spf.google.com` -> This specifies which domain can send mail
- `-all` -> non-authorized emails will be rejected
#### **DKIM (DomainKeys Identified Mail)**
	_DKIM stands for DomainKeys Identified Mail and is used for the authentication of an email that’s being sent. Like SPF, DKIM is an open standard for email authentication that is used for DMARC alignment. A DKIM record exists in the DNS, but it is a bit more complicated than SPF. DKIM’s advantage is that it can survive forwarding, which makes it superior to SPF and a foundation for securing your email.
`v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTQIC7vZAHHZ7WVv/5x/qH1RAgMQI+y6Xtsn73rWOgeBQjHKbmIEIlgrebyWWFCXjmzIP0NYJrGehenmPWK5bF/TRDstbM8uVQCUWpoRAHzuhIxPSYW6k/w2+HdCECF2gnGmmw1cT6nHjfCyKGsM0On0HDvxP8I5YQIIlzNigP32n1hVnQP+UuInj0wLIdOBIWkHdnFewzGK2+qjF2wmEjx+vqHDnxdUTay5DfTGaqgA9AKjgXNjLEbKlEWvy0tj7UzQRHd24a5+2x/R4Pc7PF/y6OxAwYBZnEPO0sJwio4uqL9CYZcvaHGCLOIMwQmNTPMKGC9nt3PSjujfHUBX3wIDAQAB`

An explanation of the above record:
- `v=DKIM1` -> This is the version of the DKIM record. This is optional. 
- `k=rsa` -> This is the key type. The default value is RSA. RSA is an encryption algorithm (cryptosystem).
- `p=` -> This is the public key that will be matched to the private key, which was created during the DKIM setup process.
#### **DMARC (Domain-Based Message Authentication, Reporting, and Conformance)**
	 _DMARC, (Domain-based  Message Authentication Reporting, & Conformance) an open source standard, uses a concept called alignment to tie the result of two other open source standards, SPF (a published list of servers that are authorized to send email on behalf of a domain) and DKIM (a tamper-evident domain seal associated with a piece of email), to the content of an email. If not already deployed, putting a DMARC record into place for your domain will give you feedback that will allow you to troubleshoot your SPF and DKIM configurations if needed.
How does a basic DMARC record look like?
`v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com` 

An explanation of the above record:
- `v=DMARC1` -> Must be in all caps, and it's not optional
- `p=quarantine` -> If a check fails, then an email will be sent to the spam folder (DMARC Policy)
- `rua=mailto:postmaster@website.com` -> Aggregate reports will be sent to this email address

#### **S/MIME (Secure/Multipurpose Internet Mail Extensions)**
	Per Microsoft, "_S/MIME (Secure/Multipurpose internet Mail Extensions) is a widely accepted protocol for sending digitally signed and encrypted messages_."

