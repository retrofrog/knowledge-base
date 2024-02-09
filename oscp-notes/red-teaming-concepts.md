# Red Teaming Concepts

#### Red Teaming

Red teaming is more than a penetration test. It involves security testing of the below

* **Technical Infrastructure:**  Red teams will try to uncover technical vulnerabilities and weaknesses, with a much higher emphasis on stealth and evasion to simulate a real-life attack.
* **Social Engineering:** Targeting people through phishing campaigns, phone calls or social media to trick them into revealing information that should be private.
* **Physical Intrusion:** Using techniques like lockpicking, RFID cloning, exploiting weaknesses in electronic access control devices to access restricted areas of facilities. Red teams simulate attack techniques to test the reaction capabilities of a defending team, generally known as **blue team**, against known adversary strategies. Red team engagements consist of emulating a real threat actor's **Tactics, Techniques and Procedures (TTPs)** so that we can measure how well our blue team responds to them and ultimately improve any security controls in place.

#### Red Team Roles and Responsibilities

**Red Team Lead**

Plans and organizes engagements at a high level by delegating assignments assistant leadand operators engagement.

**Red Team Assistant Lead**

Assists the team lead in overseeing engagement operations and operators. Can also assist in writing engagement plans and documentation if needed

**Red Team Operator**

Executes assignments delegated by team leads. Interpret and analyze engagement plans from team leads.

#### Understanding your client objectives

The key to a successful red team engagement is clearly defined client objectives or goals. Client objectives should be discussed between the client and the red team to create a mutual and common understanding between both parties of what is expected and provided. Without clear and concrete objectives, the red team campaign can be very unstructured and unplanned. Red team Engagements can be categorized into

* **Penetration Test** Check below for notes on penetration tests.
* **Focused adversary emulation** A focused adversary emulation will define a specific APT or group to emulate within an engagement. This will typically be determined based on groups that target the company's particular industries, i.e., finance institutions and [APT38](https://web.archive.org/web/20230325143301/https://content.fireeye.com/apt/rpt-apt38). Below are examples of client objectives #Example-1

```
1. Identify system misconfigurations and network weaknesses.
    1. Focus on exterior systems.
2. Determine the effectiveness of endpoint detection and response systems.
3. Evaluate overall security posture and response.
    1. SIEM and detection measures.
    2. Remediation.
    3. Segmentation of DMZ and internal servers.
4. Use of white cards is permitted depending on downtime and length.
5. Evaluate the impact of data exposure and exfiltration.
```

\#Example-2

```
1. System downtime is not permitted under any circumstances.
    1. Any form of DDoS or DoS is prohibited.
    2. Use of any harmful malware is prohibited; this includes ransomware and other variations.
2. Exfiltration of PII is prohibited. Use arbitrary exfiltration data.
3. Attacks against systems within 10.0.4.0/22 are permitted.
4. Attacks against systems within 10.0.12.0/22 are prohibited.
5. Bean Enterprises will closely monitor interactions with the DMZ and critical/production systems.
    1. Any interaction with "*.bethechange.xyz" is prohibited.
    2. All interaction with "*.globalenterprises.thm" is permitted.
```

#### Rules of Engagement

Rules of engagement (ROE) are used to define how the engagement should be conducted, the scope of the engagement, who should be contacted in case of emergency, and any other items of importance. The ROE is the primary safety net for both the red team and the customer, so if the red team were to deviate from those rules, systems could be damaged, or physically unsafe conditions could be created. Accidents can and do happen, however, so good ROE will define reporting processes for those incidents, and the red team will be completely honest about what happened. **Scope Creep** Scope creep is the addition of more items and targets to the scope of the assessment. **Statement of work (SOW)** A document that defines the purpose of the work, what work will be done, what deliverables will be created, the timeline for the work to be completed, the price for the work, and any additional terms and conditions that cover the work. Alternatives to statements of work include statements of objectives (SOOs) and performance work statements (PWSs).

#### Concept of Operations

This document serves as the reference for the client and red team for the full engagement. The Concept of Operations document should be written from a semi-technical summary perspective, assuming the target audience/reader has zero to minimal technical knowledge. Below are its components

```
- Client Name
- Service Provider
- Timeframe
- General Objectives/Phases
- Other Training Objectives (Exfiltration)
- High-Level Tools/Techniques planned to be used
- Threat group to emulate (if any)
```

Example is below

```
Stuxnet Enterprises has hired you as an external contractor to conduct a month-long network infrastructure assessment and security posture. The campaign will utilize an assumed breach model starting in Tier 3 infrastructure. Operators will progressively conduct reconnaissance and attempt to meet objectives to be determined. If defined goals are not met, the red cell will move and escalate privileges within the network laterally. Operators are also expected to execute and maintain persistence to sustain for a period of three weeks. A trusted agent is expected to intervene if the red cell is identified or burned by the blue cell throughout the entirety of the engagement. The last engagement day is reserved for clean-up and remediation and consultation with the blue and white cell.

The customer has requested the following training objectives: assess the blue team's ability to identify and defend against live intrusions and attacks, Identify the risk of an adversary within the internal network. The red cell will accomplish objectives by employing the use of Cobalt Strike as the primary red cell tool. The red cell is permitted to use other standard tooling only identifiable to the targeted threat.

Based on customer security posture and maturity, the TTP of the threat group: FIN6, will be employed throughout the engagement.
```

#### Resource Planning Document

Components of such document are below

```
- Header
    - Personnel writing
    - Dates
    - Customer
- Engagement Dates
    - Reconnaissance Dates
    - Initial Compromise Dates
    - Post-Exploitation and Persistence Dates
    - Misc. Dates
- Knowledge Required (optional)
    - Reconnaissance
    - Initial Compromise
    - Post-Exploitation
- Resource Requirements
    - Personnel
    - Hardware
    - Cloud
    - Misc.
```

#### Mission Plan Document

This document contains details about the exact actions to be completed by operators. Example sections that the document may include

```
- Objectives
- Operators
- Exploits/Attacks
- Targets (users/machines/objectives)
- Execution plan variations
```

#### Standard Frameworks

The below frameworks can be referred into when planning and executing an engagement.

* **Lockheed Martin Cyber Kill Chain**

**Definition** Cyber kill chain is an attack framework that demonstrates the steps the attacker takes to fully compromise their target and act on their objectives. It's used widely for penetration testing, threat intelligence and risk management. **Stages of the cyber kill chain**

* `Reconnaissance` Reconnaissance is discovering and collecting information on the system and the victim. The reconnaissance phase is the planning phase for the adversaries.
* `Weaponization` In this stage, the attacker embeds malicious code such as an exploit code or backdoor in the payload to deliver it later to the victim.
* `Delivery` In this stage, the attacker chooses the method for transmitting the payload or the malware such as through emails, social media, SMS,etc.
* `Exploitation` It's the stage where the exploit code delivered through the payload actively exploits the vulnerable application or OS on the target machine.
* `Installation` In this stage, the attacker install a RAT or backdoor to maintain access.
* `Command & Control` In this stage, the attacker opens up the C2 (Command and Control) channel through the malware to remotely control and manipulate the victim.
* `Actions on Objectives` The attacker starts to act on the objectives they planned first and usually they exfiltrate data, harvest user credentials or may even encrypt the machine with ransomware.
* **Diamond Model**

**Definition** The diamond model is used for intrusion analysis and is composed of four core features: adversary, infrastructure, capability, and victim, and establishes the fundamental atomic element of any intrusion activity. **Framework Components**

* `Adversary` An **adversary** is also known as an attacker, enemy, cyber threat actor, or hacker. The adversary is the person who stands behind the cyberattack. Cyberattacks can be an instruction or a breach.
* `Victim` **Victim** – is a target of the adversary. A victim can be an organization, person, target email address, IP address, domain, etc. It's essential to understand the difference between the victim persona and the victim assets because they serve different analytic functions.
* `Capability` **Capability** – is also known as the skill, tools, and techniques used by the adversary in the event. The capability highlights the adversary’s tactics, techniques, and procedures (TTPs).
* `Infrastructure` **Infrastructure** – is also known as software or hardware. Infrastructure is the physical or logical interconnections that the adversary uses to deliver a capability or maintain control of capabilities. For example, a command and control centre (C2) and the results from the victim (data exfiltration).
* **Unified Kill Chain**
* **Varonis Cyber Kill Chain**
* **Active Directory Attack Cycle**
* **MITRE ATT\&CK Framework**
* **Cyber Assessment Framework**

CAF is used to assess the risk of various cyber threats and an organization's defence against these. The framework applies to organizations considered to perform "vitally important services and activities" such as critical infrastructure, banking, and the likes

* **NIST Cybersecurity Framework**

NIST is used to improve an organization's cybersecurity standards and manage the risk of cyber threats. The framework provides guidelines on security controls & benchmarks for success for organizations from critical infrastructure (power plants, etc.) all through to commercial. [NIST 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) is a publication titled "**Security and Privacy Controls for Information Systems and Organizations**" that provides a catalogue of security controls to protect the CIA triad of information systems. The publication serves as a framework for organizations to assess and enhance the security and privacy of their information systems and comply with various laws, regulations, and policies. It incorporates best practices from multiple sources, including industry standards, guidelines, and international frameworks.

* **Open Web Application Security Project**

This framework is used solely to test the security of web applications and services.

* **The Open Source Security Testing Methodology Manual**

This framework includes aspects on the below:

1. **Telecommunications (phones, VoIP, etc.)**
2. Wired Networks
3. Wireless communications

#### Vulnerability Assessments

A vulnerability assessment focuses on scanning hosts, endpoints and other IT assets for vulnerabilities so that security deficiencies and weaknesses can be **identified** and effective security measures and controls can be deployed to **protect** the network in a prioritized manner. Most of the work can be done with automated tools and performed by operators without requiring much technical knowledge. Sometimes and according to the scope of the engagement, a manual assessment may be required for a more thorough approach and accurate scanning results.

#### Penetration Testing

Penetration tests add extra steps to vulnerability assessment in that the assessor or the team will attempt to exploit the discovered vulnerabilities in addition to conducting **post-exploitation** tasks on any compromised host to test the ability extracting any helpful information. Network pivoting can also be involved if the pentester discovered hosts on different subnets and they were included in the scope of engagement. **Black-Box Penetration Testing** This testing process is a high-level process where the tester is not given any information about the inner workings of the application or service. The tester acts as a regular user testing the functionality and interaction of the application or piece of software. This testing can involve interacting with the interface, i.e. buttons, and testing to see whether the intended result is returned. No knowledge of programming or understanding of the program is necessary for this type of testing. `Black-Box` testing significantly increases the amount of time spent during the information gathering and enumeration phase to understand the attack surface of the target. **Grey-Box Penetration Testing** It is a combination of both black-box and white-box testing processes. The tester will have some limited knowledge of the internal components of the application or piece of software. Still, it will be interacting with the application as if it were a black-box scenario and then using their knowledge of the application to try and resolve issues as they find them. With Grey-Box testing, the limited knowledge given saves time, and is often chosen for extremely well-hardened attack surfaces. **White-Box Penetration Testing** This testing process is a low-level process usually done by a software developer who knows programming and application logic. The tester will be testing the internal components of the application or piece of software and, for example, ensuring that specific functions work correctly and within a reasonable amount of time. The tester will have **full** knowledge of the application and its expected behaviour and is much more time consuming than black-box testing. The full knowledge in a White-Box testing scenario provides a testing approach that guarantees the entire attack surface can be validated. In a white box or known environment testing, the penetration tester will be given an exemption in the firewall or intrusion detection system to prevent blocking scenarios. Additionally, they will be allowed to bypass network access controls (NACs) that would normally prevent unauthorized devices from connecting to the network. **Internal Penetration Testing** Internal penetration testing teams consist of cybersecurity professionals from within the organization who conduct penetration tests on the organization’s systems and applications. These teams may be dedicated to penetration testing on a full-time basis or they may be convened periodically to conduct tests on a part-time basis. **Planning and Scoping**

* The scope determines what penetration testers will do and how their time will be spent. It is useful to determine whether you will do white, black or grey box testing while setting the scope of the penetration testing. Example of Detailed scoping starts by determining the acceptable targets. Are they first party hosted (internally) or third party hosted (externally), and are they on-site or off-site? Are they hosted by the organization itself, by a third party, or by an infrastructure-as-a- service (IaaS) or other service provider? Are they virtual, physical, or a hybrid, and does this impact the assessment? Are there specific environmental restrictions that need to be applied for the network, applications, or cloud systems and services? Once you have determined what assets are in scope and out of scope, you will need to build lists or filters to ensure that you don’t inadvertently target out-of- scope assets, systems, or other potential targets. That may include a list of IP addresses, hostnames, or other details. Targeting out-of- scope assets can result in significant issues, impact on business operations, or even contractual issues.
* There are often external legal and compliance requirements as well as the target organization’s internal policies. Laws, regulations, and industry standards are all part of the environment that a penetration tester must navigate. Equally important, regulations such as HIPAA strictly forbid protected health information (PHI) from being accessed, even in the process of penetration testing. Industry standards like PCI DSS, and government standards like FIPS 140-2, also have specific requirements that organizations must meet and that penetration testers may be asked either to include in their scope or to specifically address as part of their test. **Passive reconnaissance** Passive reconnaissance collects information about a targeted system, network, or organization using open source intelligence (OSINT). This includes viewing social media sources about the target, news reports, and even the organization’s website. For Example, theHarvester is a passive reconnaissance commandline tool used by testers in the early stages of a penetration test. It uses OSINT methods to gather data such as email addresses, employee names, host IP addresses, and URLs. Passive reconnaissance does not include using any tools to send information to targets and analyze the responses. **Active reconnaissance** Active reconnaissance methods use tools to engage targets by sending packets/requests and monitoring the target's response/behavior to gather intel and data. Example of these tools are `IP-scanners` which searche a network for active IP addresses, `Nmap` which is used to scan networks for live hosts, open ports and vulnerabilities, `Netcat` which is used it for banner grabbing by lively interacting with the target, `dnsenum` command enumerates (or lists) Domain Name System (DNS) records for domains. It lists the DNS servers holding the records and identifies the mail servers, `Nesus` which is a vulnerability scanner, `sn1per` which is an automated scanner used for vulnerability assessments and to gather information on targets during penetration testing and `curl` which is is used to transfer and retrieve data to and from servers, such as web servers. **Network footprinting** Network footprinting provides a big-picture view of a network, including the Internet Protocol (IP) addresses active on a target network. However, Fingerprinting is focusing on a specific individual target for intel. **Exploitation** After scanning the target, pen testers discover vulnerabilities. They then take it a step further and look for a vulnerability that they can exploit. For example, a vulnerability scan may discover that a system doesn’t have a patch installed for a known vulnerability. The vulnerability allows attackers (and testers) to remotely access the system and install malware on it. With this knowledge, the testers can use known methods to exploit. **Persistence** Persistence is an attacker’s ability to maintain a presence in a network for weeks, months, or even years without being detected. Penetration testers use backdoors to maintain access. **Lateral Movement** Lateral movement or pivoting is an advanced stage that comes after the attacker penetrates the network. Typically, the attacker uses the compromised target/machine to pivot and access other machines through tunneling and scanning the network. **Privilege Escalation** Simply it's an upward move from a low-privileged account such as `www-data` into a higher-privileged account such as `root` or a user in the middle that is not necessarily root but is higher privilege than \`www-data **Targeting An Internal Network Is Done By Either One Of Three Options**
* Hacking the public server if available.
* Phishing campaigns that target employees.
* Physical Attacks such as USB attacks **Phishing campaigns notes**
* A list of employees and their email addresses.
* A nice email idea.
* An email-sending platform.
* A neat malicious file that gives us access to the user’s machine. Preferably malicious excel or word \[See The playbook for instructions on creating one]
* Including a link rather than directly attaching a malicious file reduces the chances of being caught by the spam filter. **Start your pentest on any target domain with the following list in order**
* Finding DNS details about the domain name;ip,subdomains,emails
* Web vulnerabilities of the target's websties **Inspecting websites for vulnerabilities**
* Always play with input variables and monitor the response. see tools such as burp suite
* Look for file upload areas.
* Trying to access config files such as phpinfo, or web.config for iis server...etc.
* Look at the HTTP headers. They always reveal a lot about the web server **Upload vulnerabilities tricks**
* changing the content-type while intercepting the response
* changing file extension while intercepting the response
* changing file magic number before uploading it **DB testing**
* Use the --file-write option when using sqlmap and try writing your public ssh key to /home/mysql/.ssh to gain RCE. \[7-1] **First shell access and privilege escalation notes**
* Always start by disabling the bash history file to avoid your commands recorded.
* Always start by checking system type, version, network configs, firewall configs
* When on Linux, start by looking for SETUID bit files.
* When on Windows, look for passwords in unattend.xml, sysprep.xml or sysprep.inf file. **Lateral moves**
* When rooting a box, use socks proxy \<create a tunnel that forwards all traffic coming to it from your machine to the destination that you can't access from the internet \[internal hosts]>.
* The socks proxy should be installed on the machine you rooted so that we open a listening port on it to receive traffic from our attacking machine.
* When there is a firewall on the rooted box preventing traffic on the listening port, create two local rules to route every packet from your machine to the listening port
* Last step is to edit proxychains.conf and add socks5 \[rooted box ip or domain] \[port]
* You can use the autoroute in metasploit if you got meterpreter shell to do the routing.
* Alternatively you can use SSH tunnels
* Chisel can be used as well to connect to ports that are configured to listen locally.
* Use crackmapexec to brute force multiple windows machines if you got some credentials
* Use crackmapexec to execute commands on remote targets and fetch hashes with --sam option
* Use the GPO **Lateral moves with Metasploit**
* Use the add route feature to access other networks and add it to the current session.
* use auxiliary/server/socks4a to open a local port on your machine that forwards every traffic coming to it to the meterpreter session you got.
* Add \<socks4 127.0.0.1 \[port]> to your proxychains.conf
* start using your tools by appending `proxychains` to it. **Lateral moves with GPO**
* Activate the group policy modules in powershell
* Create fake GPO targeting the domain controller and specifying the server
* Restrict the scope of the policy to the computer name you want to target
* Generate powershell reverse shell encoded with base64
* Instruct thee GPO to setup a 'run' registery key which will execute the reverse shell **Lateral moves with WMI**
* Make sure you are on a windows domain-joined machine and the target has 135 port open.
* create a powershell base64-encoded payload
* execute invoke-wmimethod command to infect the target computer with the payload
* wait for the connection. **Internal Network testing**
* Start by harvesting passwords with mimikatz or Metasploit
* Always launch commands directly from the internal host you compromised to avoid the firewall catching you
* To execute remote powershell commands on other internal clients, you need remote powershell which runs on port 5985 and if its not possible, you can enable it
* If remote powershell is not possible, use WMI in the scripts **Data Exfiltration**
* Always zip the data you want to exfiltrate
* Encode the zip file as base64 with Do-Exfiltration.ps1 by Nishaning.
* Exfiltrate over http or DNS
* List network shares to find sensitive data
