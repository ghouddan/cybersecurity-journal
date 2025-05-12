# Room 1
#### Tier 1 
The role of a tier 1 security analyst is as a triage specialist, with the roles of monitoring the system log, create ticket, configure tools 

### What is SOC
The core function of **Security Operation Center** is to monitor, investigate and respond to any threat and also charged with the protection of different assets 
- preparation and investigation 
- Monitoring and investigation 
- Response
# Room 2
## The pyramid of pain 
![[Pasted image 20250504162722.png]]
![[Pasted image 20250504170939.png]]
#### The MITRE ATT&AC

#### Hash
	A hash is a numeric value of fixed lenght that uniquely represent data, it is the result of a hash function and is used to check the integrety of data.
	- MD5 126 bites
	- SHA-1 160 bites
	- SHA-2 256 bites
#### Punycode
	Punycode is a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding.
#### Host artifact 
	Host artifacts are the traces or observables that attackers leave on the system, such as registry values, suspicious process execution, attack patterns or IOCs (Indicators of Compromise), files dropped by malicious applications, or anything exclusive to the current threat.
#### Network artifact 
	A network artifact can be a user-agent string, C2 information, or URI patterns followed by the HTTP POST requests.An attacker might use a User-Agent string that hasn’t been observed in your environment before or seems out of the ordinary. The User-Agent is defined by [RFC2616](https://datatracker.ietf.org/doc/html/rfc2616#page-145) as the request-header field that contains the information about the user agent originating the request
##### User-Agent
	in an HTTP header is a string that identify the client applicationn operating system, vendor and version 
	 User agents help web servers identify what type of device or browser is making the request, allowing them to serve optimized content or handle compatibility issues.
#### Tools 
- [MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) are good resources to provide you with access to the samples, malicious feeds, and YARA results - these all can be very helpful when it comes to threat hunting and incident response
- For detection rules, [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) is a great platform, where security professionals share their detection rules for different kinds of threats including the latest CVE's that are being exploited in the wild by adversaries.
- Fuzzy hashing also known as "Context Triggered Piecewise Hashing" for computing the similarity between file 
#### TTP tactics & technique & procedure 

# Room 3
## The cyber kill chain 

![[Pasted image 20250505082914.png]]

- this term is derivative from the military and it mean the structure of an attack it was developed by lockhead martine 
- finishing the kill chain mean that the attack was succesfull 

#### Reconnaissance
	is the first part of the attack which is gathreing informaton about the target by using different tools and social network for the porpose of knowing your taget and there infrastructer
#### Weaponization
	is the crqfting of the weapon for using in the attack 'the weapon of destruction' this weapon is combine of 'malware' & 'exploit'  
- malware is a program that's designed to damage 
- exploit is a program that take advantage of a flaw or vulnerability in the system 

#### Delivery
	is shoosing the method of transmition of the malware or the payload 
- Phishing email
- Infected USB
- Watering hole attack (drive by download)
#### Exploitation 
	exploiting the vulnirability in the system to escalate the privlege and to gain acess to deep data.
-  The victim triggers the exploit by opening the email attachment or clicking on a malicious link.
- Using a zero-day exploit.
- Exploit software, hardware, or even human vulnerabilities. 
- An attacker triggers the exploit for server-based vulnerabilities.
#### Installation 
	creating a back door that will allow us to access the system even after the patching 
#### C&C
	Command & controle or C2 si done by creating a tunel from the the vectime machine to the server of the attacker to remotly controle and manipulat  the victim 
- The protocols HTTP on port 80 and HTTPS on port 443 - this type of beaconing blends the malicious traffic with the legitimate traffic and can help the attacker evade firewalls.    
- DNS (Domain Name Server). The infected machine makes constant DNS requests to the DNS server that belongs to an attacker, this type of C2 communication is also known as DNS Tunneling.
#### Action on objectives 
	after going trought the six previous phase now the attacked can achieve his goals with hand on keyboard 

# Room 4 
## Unified kill chain
#### kill chain 
	is a term belong to the military that describe the startegie and methodologie an attacker take 
#### Threat modeling 
	is a serie of step that will allow us to improve the security of a system by identifying the risk and flaw in it :
1. Identifying what systems and applications need to be secured and what function they serve in the environment. For example, is the system critical to normal operations, and is a system holding sensitive information like payment info or addresses?
2. Assessing what vulnerabilities and weaknesses these systems and applications may have and how they could be potentially exploited
3. Creating a plan of action to secure these systems and applications from the vulnerabilities highlighted
4. Putting in policies to prevent these vulnerabilities from occurring again where possible (for example, implementing a software development life cycle (SDLC) for an application or training employees on phishing awareness).
#### The unified kill chain
	is a new model that complet the older model of kill chain 

![[Pasted image 20250506170345.png]]
##### Phase In
	setting the foothold in the system  
	
![[Pasted image 20250506171634.png]]
**Reconnaissance ([MITRE Tactic TA0043](https://attack.mitre.org/tactics/TA0043/))**

This phase of the UKC describes techniques that an adversary employs to gather information relating to their target. This can be achieved through means of passive and active reconnaissance. The information gathered during this phase is used all throughout the later stages of the UKC (such as the initial foothold).

Information gathered from this phase can include:

- Discovering what systems and services are running on the target, this is beneficial information in the weaponisation and exploitation phases of this section. 
- Finding contact lists or lists of employees that can be impersonated or used in either a social engineering or phishing attack.
- Looking for potential credentials that may be of use in later stages,  such as pivoting or initial access.
- Understanding the network topology and other networked systems can be used to pivot too. 

**Weaponization ([MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/))**

This phase of the UKC describes the adversary setting up the necessary infrastructure to perform the attack. For example, this could be setting up a command and control server, or a system capable of catching reverse shells and delivering payloads to the system.

**Social Engineering ([MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/))**

This phase of the UKC describes techniques that an adversary can employ to manipulate employees to perform actions that will aid in the adversaries attack. For example, a social engineering attack could include:

- Getting a user to open a malicious attachment.
- Impersonating a web page and having the user enter their credentials.
- Calling or visiting the target and impersonating a user (for example, requesting a password reset) or being able to gain access to areas of a site that the attacker would not previously be capable of (for example, impersonating a utility engineer).

**Exploitation ([MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/))**

This phase of the UKC describes how an attacker takes advantage of weaknesses or vulnerabilities present in a system. The UKC defines "Exploitation" as abuse of vulnerabilities to perform code execution. For example:

- Uploading and executing a reverse shell to a web application.
- Interfering with an automated script on the system to execute code.
- Abusing a web application vulnerability to execute code on the system it is running on.

**Persistence ([MITRE Tactic TA0003](https://attack.mitre.org/tactics/TA0003/))**  

This phase of the UKC is rather short and simple. Specifically, this phase of the UKC describes the techniques an adversary uses to maintain access to a system they have gained an initial foothold on. For example:

- Creating a service on the target system that will allow the attacker to regain access.
- Adding the target system to a Command & Control server where commands can be executed remotely at any time.
- Leaving other forms of backdoors that execute when a certain action occurs on the system (i.e. a reverse shell will execute when a system administrator logs in).

**Defence Evasion ([MITRE Tactic TA0005](https://attack.mitre.org/tactics/TA0005/))**  

The "Defence Evasion" section of the UKC is one of the more valuable phases of the UKC. This phase specifically is used to understand the techniques an adversary uses to evade defensive measures put in place in the system or network. For example, this could be:

- Web application firewalls.
- Network firewalls.
- Anti-virus systems on the target machine.
- Intrusion detection systems.

This phase is valuable when analysing an attack as it helps form a response and better yet - gives the defensive team information on how they can improve their defence systems in the future.

**Command & Control ([MITRE Tactic TA0011](https://attack.mitre.org/tactics/TA0011/))**

The "Command & Control" phase of the UKC combines the efforts an adversary made during the "Weaponization" stage of the UKC to establish communications between the adversary and target system.

An adversary can establish command and control of a target system to achieve its action on objectives. For example, the adversary can:

- Execute commands.
- Steal data, credentials and other information.
- Use the controlled server to pivot to other systems on the network.

**Pivoting ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))**

"Pivoting" is the technique an adversary uses to reach other systems within a network that are not otherwise accessible (for example, they are not exposed to the internet). There are often many systems in a network that are not directly reachable and often contain valuable data or have weaker security.

For example, an adversary can gain access to a web server that is publically accessible to attack other systems that are within the same network (but are not accessible via the internet
##### **Phase trough**
	after havong the foothold now the adversary will try to access higher level and expand to other systems

![[Pasted image 20250506171755.png]]
 **Pivoting** ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))
Once the attacker has access to the system, they would use it as their staging site and a tunnel between their command operations and the victim’s network. The system would also be used as the distribution point for all malware and backdoors at later stages.
 **Discovery** ([MITRE Tactic TA0007](https://attack.mitre.org/tactics/TA0007/))
The adversary would uncover information about the system and the network it is connected to. Within this stage, the knowledge base would be built from the active user accounts, the permissions granted, applications and software in use, web browser activity, files, directories and network shares, and system configurations.
**Privilege Escalation** ([MITRE Tactic TA0004](https://attack.mitre.org/tactics/TA0004/))
Following their knowledge-gathering, the adversary would try to gain more prominent permissions within the pivot system. They would leverage the information on the accounts present with vulnerabilities and misconfigurations found to elevate their access to one of the following superior levels:
- _SYSTEM/ ROOT._
- _Local Administrator._
- _A user account with Admin-like access._
- _A user account with specific access or functions._
 **Execution** ([MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/))
This is where they deploy their malicious code using the pivot system as their host. Remote trojans, C2 scripts, malicious links and scheduled tasks are deployed and created to facilitate a recurring presence on the system and uphold their persistence.
**Credential Access** ([MITRE Tactic TA0006](https://attack.mitre.org/tactics/TA0006/))
Working hand in hand with the Privilege Escalation stage, the adversary would attempt to steal account names and passwords through various methods, including keylogging and credential dumping. This makes them harder to detect during their attack as they would be using legitimate credentials.
**Lateral Movement** ([MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/))
With the credentials and elevated privileges, the adversary would seek to move through the network and jump onto other targeted systems to achieve their primary objective. The stealthier the technique used, the better.
#### Phase out 
	This phase wraps up the journey of an adversary’s attack on an environment, where they have critical asset access and can fulfil their attack goals. These goals are usually geared toward compromising the confidentiality, integrity and availability (CIA) triad.

 **Collection** [MITRE Tactic (TA0009)](https://attack.mitre.org/tactics/TA0009/)
After all the hunting for access and assets, the adversary will be seeking to gather all the valuable data of interest. This, in turn, compromises the confidentiality of the data and would lead to the next attack stage – Exfiltration. The main target sources include drives, browsers, audio, video and email.
**Exfiltration** ([MITRE Tactic TA0010](https://attack.mitre.org/tactics/TA0010/))
To elevate their compromise, the adversary would seek to steal data, which would be packaged using encryption measures and compression to avoid any detection. The C2 channel and tunnel deployed in the earlier phases will come in handy during this process.
 **Impact** ([MITRE Tactic TA0040](https://attack.mitre.org/tactics/TA0040/))
If the adversary seeks to compromise the integrity and availability of the data assets, they would manipulate, interrupt or destroy these assets. The goal would be to disrupt business and operational processes and may involve removing account access, disk wipes, and data encryption such as ransomware, defacement and denial of service (DoS) attacks.
 **Objectives**
With all the power and access to the systems and network, the adversary would seek to achieve their strategic goal for the attack.

For example, if the attack was financially motivated, they may seek to encrypt files and systems with ransomware and ask for payment to release the data. In other instances, the attacker may seek to damage the reputation of the business, and they would release private and confidential information to the public.

**Confidentiality, Integrity, and Availability (CIA) is the opposite of Disclosure, Alternation, and Destruction (DAD)**

# Room 5 
## Diamond Model 
	the four core feature that constetout the diamond are :
		- Adversary 
		- Infrastructure 
		- Capability 
		- victim 
		this model help establish the fundimetal atomic element of any intrusion activity 
#### Adversary 
	Also known as attacker, enemy, cyber threat actor 
	- Adversary Operator : the one conducting the act 
	- **Adversary Customer : the one benifiting from tha attack 
#### Victim 
	is a target of the adversary. A victim can be an organization, person, target email address, IP address, domain, etc. It's essential to understand the difference between the victim persona and the victim assets because they serve different analytic functions.
	Victim Personae: are the people and organizations being targeted and whose assets are being attacked and exploited. These can be organization names, people’s names, industries, job roles, interests, etc.
	Victim Assets : are the attack surface and include the set of systems, networks, email addresses, hosts, IP addresses, social networking accounts, etc., to which the adversary will direct their capabilities.
#### Capability
	Also known as the skill, tools and technique an attaker use in a event 
	- Adversary Arsenla is the set of capabilities that belong to the adversary 
	- Capability Capacity is all of the vulnerabilities and exposures that the individual capability can use.

#### Infrastructure
	Are the software and hardware , what the adversary use to mentain and deliver a  capability 
	- Infrastructure type 1 : the one that are own directly by the adversary 
	- Infrastructure type 2 : the one controlled by an intermediary some time they know and some time they don't 
		- Service Providers : important for the existance of the other Infrastructure like ISP, DNS 
#### Meta Feature 
- **Timestamp** : when 
- Phase: like the kill chain model 
- Result : "success," "failure," or "unknown."
- Direction :  Victim-to-Infrastructure, Infrastructure-to-Victim, Infrastructure-to-Infrastructure, Adversary-to-Infrastructure, Infrastructure-to-Adversary, Bidirectional or Unknown.
- Methodology :  phishing, DDoS, breach, port scan, etc.
- Resources : Software, Hardware, Knowledge, Information, Fund, Facilities, Access 
#### Social-Political 
	The **social-political** component describes the needs and intent of the adversary, for example, financial gain, gaining acceptance in the hacker community, hacktivism, or espionage.
#### Technology 
	Technology – the technology meta-feature or component highlights the relationship between the core features: capability and infrastructure. The capability and infrastructure describe how the adversary operates and communicates. A scenario can be a watering-hole attack which is a methodology where the adversary compromises legitimate websites that they believe their targeted victims will visit.

# Room 6
## MITRE 
	 TTP : Tactics, Techniques, and Procedures
	 - The  Tactic  is the adversary's goal or objective.
	- The  Technique  is how the adversary achieves the goal or objective.
	- The  Procedure  is how the technique is executed.
#### CAR (_Cyber Analytics Repository_)
	CAR is a knowledge base While ATT&CK describes what attackers do, CAR shows defenders how to detect those activities. 

#### MITRE ENGAGE 
	Per the website, " _MITRE Engage  is a framework for planning and discussing adversary engagement operations that empowers you to engage your adversaries and achieve your cybersecurity goals.
	who to engage with the adversary
	With  Cyber Denial  we prevent the adversary's ability to conduct their operations and with  Cyber Deception  we intentionally plant artifacts to mislead the adversary.
##### the mitre engagement matrix 
![[Pasted image 20250507183739.png]]
- Prepare  the set of operational actions that will lead to your desired outcome (input)
- Expose  adversaries when they trigger your deployed deception activities 
- Affect  adversaries by performing actions that will have a negative impact on their operations
- Elicit  information by observing the adversary and learn more about their modus operandi (TTPs)
- Understand  the outcomes of the operational actions (output)

#### D3FEND
	 _A knowledge graph of cybersecurity countermeasures._
	 id the contrary of the ATT&CK its focusd on defending rather than attacking 
	 D3FEND : stands
	  D etection,
	  D enial
	  D isruption 
	  F ramework  
	  E mpowering  
	  N etwork  
	  D efense.
#### ATT&CK emulation plan 



# Room 7
## Cyber threat intel 
	Cyber Threat Intelligence (CTI) can be defined as evidence-based knowledge about adversaries, including their indicators, tactics, motivations, and actionable advice against them. These can be utilised to protect critical assets and inform cyber security teams and management business decisions
- data : discrete indicator associated with adversary 
- information : multiple data point that answer question
- intelligence : the correlation between data and information to extract pattern 
Source:
- Internal 
	 - Corporate security events such as vulnerability assessments and incident response reports.
	- Cyber awareness training reports.
	- System logs and events.
- Community 
	 - Open web forums.
	- Dark web communities for cybercriminals.
- External 
	- Threat intel feeds (Commercial & Open-source)
	- Online marketplaces.
	- Public sources include government data, publications, social media, financial and industrial assessments.
Threat Intelligence Classification 
- Strategic intel : high level intel that look into the organization threat landscape 
- Technical intel : evidence and artifact  of attack used by an adversary 
- Tactical intel : Assess adversary TTP 
- Operational intel  : Looks into an adversary’s specific motives and intent to perform an attack.

#### data churning 
	is the process of transforming raw data to contextualised and action-oriented insights geared towards triaging security incidents
	the transfomation process fllow 6 phase :

![[Pasted image 20250508172732.png]]
- **direction** : the objective and goal and identifying the following parameter 
	-  Information assets and business processes that require defending.
	- Potential impact to be experienced on losing the assets or through process interruptions.
	- Sources of data and intel to be used towards protection.
	- Tools and resources that are required to defend the assets.
- **collection** : after identifying the the objective the security analysts will gather the required data by using commercial, private, open-source  
- **Processing** : due to the variety of data it is necessary to structure it
- **Analysis** : driving insight from the data after the processing for future decision making that might involve 
	- Investigating a potential threat through uncovering indicators and attack patterns.
	- Defining an action plan to avert an attack and defend the infrastructure.
	- Strengthening security controls or justifying investment for additional resources.
- dissemination: spreading the info trough the corps of the organization 
- Feedback :  Feedback should be regular interaction between teams to keep the lifecycle working
# Room 7
## Threat intelligence tools
		threat intelligence is the analysis of data and information using tool and techniques to generate meaningfull pattern on how to mitigate against threat, to mitigate agaist risk we start by answring these simple question :
			- Who's attacking you?
			- What's their motivation?
			- What are their capabilities?
			- What artefacts and indicators of compromise should you look out for?

# Room 8
## YARA
	yara is a pattern matching tool primary devloped for malware identification and classification it's usualy used as 
	- Malware detection and classification - Security researchers use Yara to create rules that identify specific malware families based on unique patterns or signatures
	- Threat hunting - Security teams use Yara rules to scan systems and networks for indicators of compromise
	- Incident response - When investigating security breaches, Yara helps identify malicious files and code
	- Reverse engineering - Researchers use Yara to find similar code patterns across different malware samples
	- Intelligence sharing - Organizations share Yara rules to help others detect the same threats

![[Pasted image 20250509185850.png]]
	Yara can be integrated with other libraries  like 
- Cuckoo
	Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox. As this environment executes malware, you can create rules on specific behaviours such as runtime strings and the like.
- Python PE
	Python's PE module allows you to create Yara rules from the various sections and elements of the Windows Portable Executable (PE) structure.

# Room 9
## OpenCTI
