# Room 1
#### Tier 1 
The role of a Tier 1 security analyst is as a triage specialist, with responsibilities including monitoring system logs, creating tickets, and configuring tools.

### What is SOC
The core function of a **Security Operations Center** is to monitor, investigate, and respond to any threats. It is also charged with the protection of different assets through:
- Preparation and investigation 
- Monitoring and investigation 
- Response

# Room 2
## The Pyramid of Pain 
![Pyramid of Pain Diagram](./../images/Pasted_image_20250504162722.png)
![Additional Pyramid Diagram](./../images/Pasted_image_20250504170939.png)

#### The MITRE ATT&CK

#### Hash
A hash is a numeric value of fixed length that uniquely represents data. It is the result of a hash function and is used to check the integrity of data.
- MD5: 128 bits
- SHA-1: 160 bits
- SHA-2: 256 bits

#### Punycode
Punycode is a way of converting words that cannot be written in ASCII into a Unicode ASCII encoding.

#### Host Artifacts 
Host artifacts are the traces or observables that attackers leave on the system, such as registry values, suspicious process execution, attack patterns or IOCs (Indicators of Compromise), files dropped by malicious applications, or anything exclusive to the current threat.

#### Network Artifacts 
A network artifact can be a user-agent string, C2 information, or URI patterns followed by HTTP POST requests. An attacker might use a User-Agent string that hasn't been observed in your environment before or seems out of the ordinary. The User-Agent is defined by [RFC2616](https://datatracker.ietf.org/doc/html/rfc2616#page-145) as the request-header field that contains information about the user agent originating the request.

##### User-Agent
In an HTTP header, a User-Agent is a string that identifies the client application, operating system, vendor, and version. User agents help web servers identify what type of device or browser is making the request, allowing them to serve optimized content or handle compatibility issues.

#### Tools 
- [MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) are good resources that provide access to samples, malicious feeds, and YARA results - these can be very helpful for threat hunting and incident response
- For detection rules, [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) is a great platform where security professionals share their detection rules for different kinds of threats, including the latest CVEs being exploited in the wild by adversaries
- Fuzzy hashing, also known as "Context Triggered Piecewise Hashing," is used for computing the similarity between files

#### TTP: Tactics, Techniques & Procedures 

# Room 3
## The Cyber Kill Chain 

![Cyber Kill Chain Diagram](./../images/Pasted_image_20250505082914.png)

This term is derived from the military and means the structure of an attack. It was developed by Lockheed Martin. Completing the kill chain means that the attack was successful.

#### Reconnaissance
This is the first part of the attack, which involves gathering information about the target using different tools and social networks for the purpose of knowing your target and their infrastructure.

#### Weaponization
This is the crafting of the weapon for use in the attack - the 'weapon of destruction.' This weapon is a combination of 'malware' and 'exploit':
- Malware is a program designed to cause damage 
- Exploit is a program that takes advantage of a flaw or vulnerability in the system 

#### Delivery
This is choosing the method of transmission of the malware or payload:
- Phishing email
- Infected USB
- Watering hole attack (drive-by download)

#### Exploitation 
This involves exploiting the vulnerability in the system to escalate privileges and gain access to deeper data:
- The victim triggers the exploit by opening the email attachment or clicking on a malicious link
- Using a zero-day exploit
- Exploiting software, hardware, or even human vulnerabilities
- An attacker triggers the exploit for server-based vulnerabilities

#### Installation 
This involves creating a backdoor that will allow access to the system even after patching.

#### Command & Control (C&C)
Command & Control or C2 is done by creating a tunnel from the victim machine to the attacker's server to remotely control and manipulate the victim:
- The protocols HTTP on port 80 and HTTPS on port 443 - this type of beaconing blends malicious traffic with legitimate traffic and can help the attacker evade firewalls
- DNS (Domain Name Server) - the infected machine makes constant DNS requests to the DNS server that belongs to an attacker; this type of C2 communication is also known as DNS Tunneling

#### Actions on Objectives 
After going through the six previous phases, the attacker can now achieve their goals with hands-on-keyboard access.

# Room 4 
## Unified Kill Chain
#### Kill Chain 
This is a term belonging to the military that describes the strategy and methodology an attacker takes.

#### Threat Modeling 
This is a series of steps that allow us to improve the security of a system by identifying risks and flaws in it:
1. Identifying what systems and applications need to be secured and what function they serve in the environment. For example, is the system critical to normal operations, and does a system hold sensitive information like payment info or addresses?
2. Assessing what vulnerabilities and weaknesses these systems and applications may have and how they could be potentially exploited
3. Creating a plan of action to secure these systems and applications from the vulnerabilities highlighted
4. Putting in policies to prevent these vulnerabilities from occurring again where possible (for example, implementing a software development life cycle (SDLC) for an application or training employees on phishing awareness)

#### The Unified Kill Chain
This is a new model that complements the older kill chain model.

![Unified Kill Chain Diagram](./../images/Pasted_image_20250506170345.png)

##### Phase In
Setting the foothold in the system.

![Phase In Diagram](./../images/Pasted_image_20250506171634.png)

**Reconnaissance ([MITRE Tactic TA0043](https://attack.mitre.org/tactics/TA0043/))**

This phase of the UKC describes techniques that an adversary employs to gather information relating to their target. This can be achieved through means of passive and active reconnaissance. The information gathered during this phase is used throughout the later stages of the UKC (such as the initial foothold).

Information gathered from this phase can include:
- Discovering what systems and services are running on the target; this is beneficial information in the weaponization and exploitation phases of this section
- Finding contact lists or lists of employees that can be impersonated or used in either a social engineering or phishing attack
- Looking for potential credentials that may be useful in later stages, such as pivoting or initial access
- Understanding the network topology and other networked systems that can be used to pivot to

**Weaponization ([MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/))**

This phase of the UKC describes the adversary setting up the necessary infrastructure to perform the attack. For example, this could be setting up a command and control server, or a system capable of catching reverse shells and delivering payloads to the system.

**Social Engineering ([MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/))**

This phase of the UKC describes techniques that an adversary can employ to manipulate employees to perform actions that will aid in the adversary's attack. For example, a social engineering attack could include:
- Getting a user to open a malicious attachment
- Impersonating a web page and having the user enter their credentials
- Calling or visiting the target and impersonating a user (for example, requesting a password reset) or being able to gain access to areas of a site that the attacker would not previously be capable of (for example, impersonating a utility engineer)

**Exploitation ([MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/))**

This phase of the UKC describes how an attacker takes advantage of weaknesses or vulnerabilities present in a system. The UKC defines "Exploitation" as abuse of vulnerabilities to perform code execution. For example:
- Uploading and executing a reverse shell to a web application
- Interfering with an automated script on the system to execute code
- Abusing a web application vulnerability to execute code on the system it is running on

**Persistence ([MITRE Tactic TA0003](https://attack.mitre.org/tactics/TA0003/))**  

This phase of the UKC is rather short and simple. Specifically, this phase describes the techniques an adversary uses to maintain access to a system they have gained an initial foothold on. For example:
- Creating a service on the target system that will allow the attacker to regain access
- Adding the target system to a Command & Control server where commands can be executed remotely at any time
- Leaving other forms of backdoors that execute when a certain action occurs on the system (i.e., a reverse shell will execute when a system administrator logs in)

**Defense Evasion ([MITRE Tactic TA0005](https://attack.mitre.org/tactics/TA0005/))**  

The "Defense Evasion" section of the UKC is one of the more valuable phases. This phase specifically is used to understand the techniques an adversary uses to evade defensive measures put in place in the system or network. For example, this could be:
- Web application firewalls
- Network firewalls
- Anti-virus systems on the target machine
- Intrusion detection systems

This phase is valuable when analyzing an attack as it helps form a response and, better yet, gives the defensive team information on how they can improve their defense systems in the future.

**Command & Control ([MITRE Tactic TA0011](https://attack.mitre.org/tactics/TA0011/))**

The "Command & Control" phase of the UKC combines the efforts an adversary made during the "Weaponization" stage to establish communications between the adversary and target system.

An adversary can establish command and control of a target system to achieve its actions on objectives. For example, the adversary can:
- Execute commands
- Steal data, credentials, and other information
- Use the controlled server to pivot to other systems on the network

**Pivoting ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))**

"Pivoting" is the technique an adversary uses to reach other systems within a network that are not otherwise accessible (for example, they are not exposed to the internet). There are often many systems in a network that are not directly reachable and often contain valuable data or have weaker security.

For example, an adversary can gain access to a web server that is publicly accessible to attack other systems that are within the same network (but are not accessible via the internet).

##### Phase Through
After having the foothold, the adversary will try to access higher levels and expand to other systems.

![Phase Through Diagram](./../images/Pasted_image_20250506171755.png)

**Pivoting** ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))
Once the attacker has access to the system, they would use it as their staging site and a tunnel between their command operations and the victim's network. The system would also be used as the distribution point for all malware and backdoors at later stages.

**Discovery** ([MITRE Tactic TA0007](https://attack.mitre.org/tactics/TA0007/))
The adversary would uncover information about the system and the network it is connected to. Within this stage, the knowledge base would be built from the active user accounts, the permissions granted, applications and software in use, web browser activity, files, directories and network shares, and system configurations.

**Privilege Escalation** ([MITRE Tactic TA0004](https://attack.mitre.org/tactics/TA0004/))
Following their knowledge-gathering, the adversary would try to gain more prominent permissions within the pivot system. They would leverage the information on the accounts present with vulnerabilities and misconfigurations found to elevate their access to one of the following superior levels:
- SYSTEM/ROOT
- Local Administrator
- A user account with Admin-like access
- A user account with specific access or functions

**Execution** ([MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/))
This is where they deploy their malicious code using the pivot system as their host. Remote trojans, C2 scripts, malicious links, and scheduled tasks are deployed and created to facilitate a recurring presence on the system and uphold their persistence.

**Credential Access** ([MITRE Tactic TA0006](https://attack.mitre.org/tactics/TA0006/))
Working hand in hand with the Privilege Escalation stage, the adversary would attempt to steal account names and passwords through various methods, including keylogging and credential dumping. This makes them harder to detect during their attack as they would be using legitimate credentials.

**Lateral Movement** ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))
With the credentials and elevated privileges, the adversary would seek to move through the network and jump onto other targeted systems to achieve their primary objective. The stealthier the technique used, the better.

##### Phase Out 
This phase wraps up the journey of an adversary's attack on an environment, where they have critical asset access and can fulfill their attack goals. These goals are usually geared toward compromising the confidentiality, integrity, and availability (CIA) triad.

**Collection** [MITRE Tactic (TA0009)](https://attack.mitre.org/tactics/TA0009/)
After all the hunting for access and assets, the adversary will be seeking to gather all the valuable data of interest. This, in turn, compromises the confidentiality of the data and would lead to the next attack stage – Exfiltration. The main target sources include drives, browsers, audio, video, and email.

**Exfiltration** ([MITRE Tactic TA0010](https://attack.mitre.org/tactics/TA0010/))
To elevate their compromise, the adversary would seek to steal data, which would be packaged using encryption measures and compression to avoid any detection. The C2 channel and tunnel deployed in the earlier phases will come in handy during this process.

**Impact** ([MITRE Tactic TA0040](https://attack.mitre.org/tactics/TA0040/))
If the adversary seeks to compromise the integrity and availability of the data assets, they would manipulate, interrupt, or destroy these assets. The goal would be to disrupt business and operational processes and may involve removing account access, disk wipes, and data encryption such as ransomware, defacement, and denial of service (DoS) attacks.

**Objectives**
With all the power and access to the systems and network, the adversary would seek to achieve their strategic goal for the attack.

For example, if the attack was financially motivated, they may seek to encrypt files and systems with ransomware and ask for payment to release the data. In other instances, the attacker may seek to damage the reputation of the business, and they would release private and confidential information to the public.

**Confidentiality, Integrity, and Availability (CIA) is the opposite of Disclosure, Alteration, and Destruction (DAD)**

# Room 5 
## Diamond Model 
The four core features that constitute the diamond are:
- Adversary 
- Infrastructure 
- Capability 
- Victim 

This model helps establish the fundamental atomic element of any intrusion activity.

#### Adversary 
Also known as attacker, enemy, or cyber threat actor:
- **Adversary Operator**: the one conducting the act 
- **Adversary Customer**: the one benefiting from the attack 

#### Victim 
This is a target of the adversary. A victim can be an organization, person, target email address, IP address, domain, etc. It's essential to understand the difference between the victim persona and the victim assets because they serve different analytic functions.

**Victim Personae**: are the people and organizations being targeted and whose assets are being attacked and exploited. These can be organization names, people's names, industries, job roles, interests, etc.

**Victim Assets**: are the attack surface and include the set of systems, networks, email addresses, hosts, IP addresses, social networking accounts, etc., to which the adversary will direct their capabilities.

#### Capability
Also known as the skill, tools, and techniques an attacker uses in an event:
- **Adversary Arsenal** is the set of capabilities that belong to the adversary 
- **Capability Capacity** is all of the vulnerabilities and exposures that the individual capability can use

#### Infrastructure
These are the software and hardware that the adversary uses to maintain and deliver a capability:
- **Infrastructure Type 1**: the one that is owned directly by the adversary 
- **Infrastructure Type 2**: the one controlled by an intermediary; sometimes they know and sometimes they don't 
  - **Service Providers**: important for the existence of other infrastructure like ISP, DNS 

#### Meta Features 
- **Timestamp**: when 
- **Phase**: like the kill chain model 
- **Result**: "success," "failure," or "unknown"
- **Direction**: Victim-to-Infrastructure, Infrastructure-to-Victim, Infrastructure-to-Infrastructure, Adversary-to-Infrastructure, Infrastructure-to-Adversary, Bidirectional, or Unknown
- **Methodology**: phishing, DDoS, breach, port scan, etc.
- **Resources**: Software, Hardware, Knowledge, Information, Funds, Facilities, Access 

#### Social-Political 
The **social-political** component describes the needs and intent of the adversary, for example, financial gain, gaining acceptance in the hacker community, hacktivism, or espionage.

#### Technology 
**Technology** – the technology meta-feature or component highlights the relationship between the core features: capability and infrastructure. The capability and infrastructure describe how the adversary operates and communicates. A scenario can be a watering-hole attack, which is a methodology where the adversary compromises legitimate websites that they believe their targeted victims will visit.

# Room 6
## MITRE 
**TTP**: Tactics, Techniques, and Procedures
- The **Tactic** is the adversary's goal or objective
- The **Technique** is how the adversary achieves the goal or objective
- The **Procedure** is how the technique is executed

#### CAR (Cyber Analytics Repository)
CAR is a knowledge base. While ATT&CK describes what attackers do, CAR shows defenders how to detect those activities.

#### MITRE ENGAGE 
Per the website, "MITRE Engage is a framework for planning and discussing adversary engagement operations that empowers you to engage your adversaries and achieve your cybersecurity goals."

This describes who to engage with the adversary. With **Cyber Denial** we prevent the adversary's ability to conduct their operations, and with **Cyber Deception** we intentionally plant artifacts to mislead the adversary.

##### The MITRE Engagement Matrix 
![MITRE Engagement Matrix](./../images/Pasted_image_20250507183739.png)

- **Prepare**: the set of operational actions that will lead to your desired outcome (input)
- **Expose**: adversaries when they trigger your deployed deception activities 
- **Affect**: adversaries by performing actions that will have a negative impact on their operations
- **Elicit**: information by observing the adversary and learn more about their modus operandi (TTPs)
- **Understand**: the outcomes of the operational actions (output)

#### D3FEND
**A knowledge graph of cybersecurity countermeasures.**

This is the contrary of ATT&CK; it's focused on defending rather than attacking.

D3FEND stands for:
- **D**etection
- **D**enial
- **D**isruption 
- **F**ramework  
- **E**mpowering  
- **N**etwork  
- **D**efense

#### ATT&CK Emulation Plan 

# Room 7
## Cyber Threat Intelligence 
Cyber Threat Intelligence (CTI) can be defined as evidence-based knowledge about adversaries, including their indicators, tactics, motivations, and actionable advice against them. These can be utilized to protect critical assets and inform cybersecurity teams and management business decisions.

- **Data**: discrete indicators associated with adversaries 
- **Information**: multiple data points that answer questions
- **Intelligence**: the correlation between data and information to extract patterns 

**Sources:**
- **Internal** 
  - Corporate security events such as vulnerability assessments and incident response reports
  - Cyber awareness training reports
  - System logs and events
- **Community** 
  - Open web forums
  - Dark web communities for cybercriminals
- **External** 
  - Threat intel feeds (Commercial & Open-source)
  - Online marketplaces
  - Public sources include government data, publications, social media, financial and industrial assessments

**Threat Intelligence Classification:**
- **Strategic Intel**: high-level intel that looks into the organization's threat landscape 
- **Technical Intel**: evidence and artifacts of attacks used by an adversary 
- **Tactical Intel**: assesses adversary TTPs 
- **Operational Intel**: looks into an adversary's specific motives and intent to perform an attack

#### Data Churning 
This is the process of transforming raw data to contextualized and action-oriented insights geared towards triaging security incidents. The transformation process follows 6 phases:

![Data Churning Process](./../images/Pasted_image_20250508172732.png)

- **Direction**: the objective and goals, identifying the following parameters:
  - Information assets and business processes that require defending
  - Potential impact to be experienced on losing the assets or through process interruptions
  - Sources of data and intel to be used towards protection
  - Tools and resources that are required to defend the assets
- **Collection**: after identifying the objectives, security analysts will gather the required data using commercial, private, and open-source resources
- **Processing**: due to the variety of data, it is necessary to structure it
- **Analysis**: driving insights from the data after processing for future decision-making that might involve:
  - Investigating a potential threat through uncovering indicators and attack patterns
  - Defining an action plan to avert an attack and defend the infrastructure
  - Strengthening security controls or justifying investment for additional resources
- **Dissemination**: spreading the information throughout the organization 
- **Feedback**: feedback should be regular interaction between teams to keep the lifecycle working

# Room 8
## Threat Intelligence Tools
Threat intelligence is the analysis of data and information using tools and techniques to generate meaningful patterns on how to mitigate against threats. To mitigate against risk, we start by answering these simple questions:
- Who's attacking you?
- What's their motivation?
- What are their capabilities?
- What artifacts and indicators of compromise should you look out for?

# Room 9
## YARA
YARA is a pattern matching tool primarily developed for malware identification and classification. It's usually used for:
- **Malware detection and classification** - Security researchers use YARA to create rules that identify specific malware families based on unique patterns or signatures
- **Threat hunting** - Security teams use YARA rules to scan systems and networks for indicators of compromise
- **Incident response** - When investigating security breaches, YARA helps identify malicious files and code
- **Reverse engineering** - Researchers use YARA to find similar code patterns across different malware samples
- **Intelligence sharing** - Organizations share YARA rules to help others detect the same threats

![YARA Diagram](./../images/Pasted_image_20250509185850.png)

YARA can be integrated with other libraries like:

**Cuckoo**
Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate YARA rules based upon the behaviors discovered from Cuckoo Sandbox. As this environment executes malware, you can create rules on specific behaviors such as runtime strings and the like.

**Python PE**
Python's PE module allows you to create YARA rules from the various sections and elements of the Windows Portable Executable (PE) structure.

# Room 10
## OpenCTI
