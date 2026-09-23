# Welcome to TheEnterprise (TE)

TE is a Penetration Testing Automation, Tool Management, and Logging Software for a complete Engagement.
The precursor to TE came about because of the redundancy of running tools and the probability of typos.
TE does much more than simply run a tool and eliminate redunant data entry (thus reducing typos).
TE uses RabbitMQ for queuing and Celery for job management from the queue.
TE is written entirely in python3 and all dependencies are installed within a virtual environment (which keeps it from conflicting with other python installs that might use different versions of libraries)

# Installation

## Docker (recommended)

This is the primary, supported way to run TheEnterprise-NextGen. It builds one image containing
the Flask/Celery app plus the external pentest tool roster, and runs RabbitMQ/Redis as separate
containers alongside it.

**Prerequisites**: Docker Engine and the Docker Compose plugin (`docker compose version` should
work - this is the `docker-compose-plugin` package, not the older standalone `docker-compose`
binary).

1. Clone the repo and `cd` into it.
2. Copy the example environment file and fill in real values:
   ```
   cp .env.example .env
   ```
   Generate `TE_FLASK_KEY` with `python3 -c "import secrets; print(secrets.token_hex(20))"` and
   pick your own `TE_HASH_KEY` (a passphrase - **do not change it once you have real engagement
   data**, or it becomes unreadable). Both are required; `docker compose` refuses to start
   without them. Set `TE_ADMIN_USERNAME`/`TE_ADMIN_PASSWORD` too if you want a known login
   instead of a randomly-generated one buried in the container's startup logs.
3. Build and start everything:
   ```
   docker compose up --build
   ```
   The first build installs the full external tool roster (~30 tools, several from old/
   unmaintained upstream repos) and can take a long time. If an individual `RUN` step in the
   Dockerfile fails partway through (plausible - some of these projects are from 2015-2019 and
   may no longer build cleanly), that's the step to look at; the rest of the image is unaffected.
4. Wait until `docker compose ps` shows `rabbitmq` and `redis` as `healthy`, then open
   `https://localhost:1820` (or whatever port you set `TE_FLASK_PORT` to). Your browser will warn
   about the self-signed certificate the container generates on first start - that's expected for
   a local/internal deployment; accept it (or swap in a real cert via a mounted
   `flask_files/flask.crt`/`.key` for anything internet-facing).
5. Log in with the admin credentials from step 2 (or, if you left those blank, run
   `docker compose logs app` and look for the auto-generated username/password printed near the
   start of the logs - it's only shown once, on first boot). The same applies to
   `TE_ZAP_API_KEY`/`TE_MSFRPC_USER`/`TE_MSFRPC_PASSWORD` if you didn't set them either - see the
   comments in `.env.example` for exactly where each one shows up (or how to read the live value
   straight out of the running container at any time).
6. `docker compose down` stops everything (engagement data survives - it's bind-mounted from
   `/usr/local/clients` on the host, not a Docker-managed volume, so it's a real folder you can
   browse, back up, or point at a specific disk via `TE_CLIENT_DATA_PATH` in `.env`); `docker
   compose up -d` restarts it in the background.

This has been validated structurally (`docker compose config`) and the underlying code paths
(Celery/RabbitMQ/Redis wiring, the install bootstrap) have been tested directly, but the full
image has not yet been build-tested end-to-end on real Docker infrastructure - see the Dockerfile's
own header comment before relying on it for a real engagement.

## Bare-metal (legacy)

The original install path is still here for reference: `install.sh` (Kali-specific) provisions
the tool roster directly onto a host, followed by `python install.py`. Same env-var secrets apply
as above (`TE_FLASK_KEY`, `TE_HASH_KEY`, `TE_ZAP_API_KEY`, `TE_MSFRPC_USER`, `TE_MSFRPC_PASSWORD`,
`TE_RABBITMQ_USER`, `TE_RABBITMQ_PASS`), and you'll need to generate a TLS cert yourself before
running `enterprise-flask.py`:
```
openssl req -x509 -newkey rsa:4096 -nodes -out flask_files/flask.crt -keyout flask_files/flask.key -days 365 -subj "/CN=localhost"
```

# Quick Start Guide
Download from Files -> Documents -> 
- https://github.com/acknowledgeHim/TheEnterprise/blob/master/documents/TE%20Getting%20Started.docx

# Email Relay Outlook Rule
Download from Files -> Documents -> Creating an Outlook Rule for Email Vulnerability Tests.pdf
- https://github.com/acknowledgeHim/TheEnterprise/blob/master/documents/Creating%20an%20Outlook%20Rule%20for%20Email%20Vulnerability%20Tests.pdf
- Share this file with your client contact before sending the email relay tests
- Email relay results should be forwarded back to relay@issgs.net (and if you put in the External Identification # from Engage then the results will auto-push to Engage)

# Deleting Records:
`TE is setup such that if you delete a 'parent' record all of it's children records will also be deleted.
For instance, if I delete an EngagementDevice then all Ports, and Finding/Results for that EngagementDevice will ALSO be deleted.
If you delete, a Scope entry, then all EngagementDevices and each one of its Ports and Finding/Results will also be deleted.
This is referred to as cascading deletion.  So BE CAREFUL DELETING.
If you delete all locations, you have now just cleared out all scope entries, and everything under results.`

# Features:

- Respository: the heart and soul of TE.  All output is parsed and appropriately put into the corresponding repository.  And best of all, you have COMPLETE CONTROL over all data in the repository meaning you can insert, edit, or delete anything (or everything).
- Location: You can SPLIT up your SCOPEs by location. Read more under the Location section below as to what that means and how you can take advantage of it.
- Scope: Scope information is only entered 1 time and open IP/Port can be entered to enable blacklisting checks.
- Your Tester IP: Enter in all the IPs of your devices so that they are not included in the repository.
- Tools: Tools can be easly run just by selecting the tool (and sometimes answering a couple of questions).
- Built-In Tools: additional tools built right into TE (ex. email filter vulnerability scanning)
- Jobs: When a tool is run, it creates a job that can be monitored and even killed right from TE.
- Parrallel processing: Jobs can be run simulateously
- Chained processing: Specific tools can be run so that each target (scope entry, etc) is run 1 at a time
- Queuing: jobs are queued up so you can just have it load up on the tools to run and it will work its way through them
- Logging: all tool run is logged in the repository (where you can see its state (queued, running, finished, failed, parsed) and other pertinent information).  Also a tool.log file is created .
- Tool Grouping: a specific YAML config file can be created to call other YAML config files, allowing you to automate & quickly fire off a list of tools
- Accountability: Everything is timestamped meaning you can tell down to the millisecond when a tool was run and when it finished.
- Eliminate Unnecessary tool rerun: You can specify to not allow tools to re-run (keep from accidentally running a tool multiple times)
- Organization/Flow: Tools are organized roughly by the Phase that they are generally going to help with (Recon, Scan, etc)
- Modularization: This is not just a quick way to add tools but a really quick way to add tools.  To add a new tool, simply create a YAML file, view the section below for more information.
- GUI: TE has a nice GUI as well as command-line view.  Both function identically.  The command-line view can create GUI accounts since the GUI is accessible remotely via a browser.  In essence, now all the tools that have been added to TE have a GUI!
- Teamwork: Multiple people can work on the same project - taking advantage of all the features above.  This can be done many ways but here are some extra advantages that can be achieved: 1. different people work on different "locations" or 2. create a copy of the Engagement .out file and run it from multiple computers which can then be merged together at the end.
- Output: All tools generate an output file (that is stored in a timestamped folder so it is not overwritten if you rerun the same tool for the same target).  This also allows you to do any grep-ing or other such stuff you want to do on the output files.
- Results: All output is parsed into the repository.  You can insert, edit, delete any items from the repository you want.
- Sortable/Searchable Views: Repository data is searchable and sortable
- Separation of Engagement jobs - you can have multiple engagement jobs running from a server, all independent of each other, meaning 1 engagement's jobs won't clog up the actively running jobs of another.  However, remember that you should try to accurately determine how many of these (celery instances) jobs per engagement should optimally run to not exceed your system's resources.
- Export: Repository data can be exported into Excel format
- Encrypt: All output data and repository data can be 7z encrypted
- Real-time email notifications: to the tester, client, fellow employees, etc - if a tool has started or completed (YAML file dictates WHAT and when a client/engagement is created you can dictate IF)
- Data Organization:  All data (repository, output files, host files, etc) are stored in within a client folder/engagement folder (ex. 0__GOOGLE/20180801/ where 0__GOOGLE is the client#__ClientName and the sub folder for the engagement is the engagement# '20180801').  These keeps are engagements for the same client nicely bundled together.
- Cascading Delete

## Location
A location in TE can be physical or virtual or some combination.  The purpose can be to break off testing (you can specify your 'current location' and so only devices associated with that location can be selected by the tool to run), allow the report to be easily broken up by location, teamwork between multiple testers where each focuses on a different location, etc.
For example, you might want to have the default 'main' location for the corporate office (you can rename it as well) and also a different location for each branch office.  When you add your scope entries you can then assign them to the correct location.
Another example, maybe you want to create different 'vlan' locations.  You could have 'vlan1', 'vlan101', etc locations and put scope entries in the corresponding locations.
Another example, maybe by physical location & vlan.  You could have 'main-vlan1', 'main-vlan238', 'branch-vlan1', 'branch-vlan99', etc.
The possibilities and options here are endless.  You can create a thousand different locations in whatever combination you want so that each scope entry it its own 'location' but then still have your 'current tesing location' as 'all locations' so when you run a tool it fires against targets in all locations.

## Scope
For now a scope is either a domain, IP, or website.  It is auto-determined what type it is.  If the entry was a valid IP or range of IPs (single, range or CIDR notation accepted), then the type is desginated as IP.  If the entry has either http:// or https:// then it is considered a website, and the everything else is considered a domain.

## What is a Person
`TE definition of a person: an individual or entity.  So a person could be someone's name, someone's email address, or just an organization (entity) such as a vendor or ISP.`

## Features ToDO
- detail pages for an engagement asset/device (one-stop shop for all things associated) - same w/ Scope & Location
- figure out a yaml type configuration for parsing output (to make writing a parser as simple as adding a tool)

## A little bit about celery
Not just a vegetable good with peanut butter.  Celery is a pretty slick 'Distributed Task Queue' library written in python.
TE uses it by queuing up jobs to RabbitMQ which celery pulls from.  Celery uses what is called 'workers'.
TE uses workers to create separation of jobs between client/engagements.  That is why the very specific celery command TE tells you to run.
TE allows you to auto-start celery for a specific client/engagement but then you miss out on seeing real-time tool output, so I prefer to run it in another console or screen.

## To error or not to error
So the most common error you will receive (if you have celery running in a separate console or screen) and you kick off a lot of tools for a scope that has a lot of entries is:
`database is locked` - not too worry that is b/c sqlite can only have 1 connection at a time open and some tool output might produce large inserts / updates hence you get this 'error'.
However, this error is not a real error b/c I simply wait a random amount of time & try connecting again to the database until successful (increasing my backoff).
So you might see the error (as long as I keep printing it too!) but check and you should see your data hitting the Repo just fine.

# Internal Steps that happen when you run a tool:
This is just an FYI and you don't have to worry about figuring out any of this even if you want to add a new tool.  But doesn't hurt to know something of the inner workings.
1. Loads the YAML config file
2. Gets all targets (based on YAML) that are valid to run against `if no targets are found, a message is displayed.  This happens b/c of 1 of 2 scenarios.  1. there are no targets that match the targets to target in the YAML file or 2. all the targets that do match have already been run against this tool and you have specified to not re-run tools.`
3. Any designated questions / selections are asked and input used to run the tool later
4. Log entry is made per group of targets (ie. scope entry, host file, individual target) for that tool (so if 2 devices matched as a target for the tool then 2 Log entries made)
5. Output path is created (ex. output/scan/nmap/TIMESTAMP/)
6. Add the job to the queue: either each target (if more than one) is either added to run simulateously or in a chain (meaning only 1 at a time)
7. If there are empty slots to start running the tool then those empty slots are filled until the maximum designated number of concurrent jobs are running.  Any remainging wait in the queue until a spot opens.  The queue operates on a first in, first out basis.  `Queued jobs can be quickly seen from the Job -> Queued menu.  Running jobs can be quickly seen from the Job -> Active menu. Detailed job data can be viewed in the Log view and then filtered down to find the job you want.`
8. Blacklist checking: if there is an open IP/Port specified in the repository for a Scope entry, before the tool is run, a quick blacklist port scan is run to verify we can reach the known open IP/Port.  If the blacklist fails, the tool does not run, since our comms are compromised.
9. Job completion `Failed jobs: the Log will be updated with failed = True and typically a comment as to what went wrong (if the tool gives us that).  Successful jobs: are then sent to the parsing function from the YAML file`
10. Blacklist checking: upon successful completion and if an open IP/Port is specified, a quick blacklist scan is run to verify we can still get to our open IP/Port.  If not then the Log entry is updated as blacklisted = True
11. Parsing: output files are parsed using the parsing function specified in the YAML file
12. Certain tools (ex. Eyewitness, Linkedint, etc) create nice HTML files and so the parser for those also auto opens the created files in a local browser for quick, easy viewing.
13. Log is updated if parsing appeared to be successful or not

# Configurable Options
Configurable global variables are in enterprise_user_conf.py.  Make sure you are careful while changing these values.  Most values are values for a specific tool and allow you to specify the value 1x instead of everytime you run the tool.
Other values like the top most values, including celery, and flask values change important aspects of TheEnterprise.  Below is a list of the configuration options you can modify (w/o going into each tools' possible global variable).
- **AUTO_START_CELERY**: True/False -> if True you do not need to manually start up celery for the specific client/engagement.  Setting it to False, means you will manually start celery in a console, which has the benefit of allowing you to see realtime output and system messages from jobs.  Setting it to True means, it will auto start CELERY when you start TE.
- CELERY_CONCURRENCY: 8 -> a number representing how many jobs can run simultaneously for this client/engagement (this # is important to not set to high to exceed your system resources.  Review Celery documentation about recommendations on how many workers should run with specific hardware.  Note, that these start up per client/engagement so if you have a server that will be doing multiple client/engagements at the same time, the actual # of celery workers running will be this # times the # of different client/engagements running at the same time.
- **AUTO_START_GUI**: True/False -> True will auto start the Web GUI when you run enterpise.py (command-line view).
- **OUTPUT_PATH**: This can be changed to change the base path where all the client/engagement data will be stored.
- **LINUX_GROUP**: This is the linux group name that everyone that will be using TE on this device is apart of (all output folders/files are put in this group)
- FLASK_KEY: A random 30 character key to help protect the Flask instance (GUI)
- FLASK_PORT: 1820 -> a number that represents a port number to start the web GUI on.  This device must not already be listening on this port # or else the Web GUI (Flask) will not run.
- DEVICE_IP: 127.0.0.1 -> can be a localhost IP so the GUI is only accessibly locally, a specify IP address of this device so only through the interface that has that IP can the Web GUI be accessed, or 0.0.0.0 which means all interfaces have access to the GUI.  `Be CAREFUL since the Web GUI only has username/password authentication and you do NOT EVER want this accessible directly from the Internet.  You are responsible for your own stupidity!`
- PYTHONV2_PATH: Full path to python2.7.  TE is written in Python3 and is inside a virtual environment and several tools are written in python2 so you can set the global variable here; otherwise, you will be required to enter it in every time you run a tool that needs the python2 path.
- All other remaining variables are for various tools so you don't have to specify this value each time you run that tool.  Sometimes that makes sense other times it does not.  Just depends on the type of Enagagement you will be performing.

# Getting Started
1. Install TE using the installation script (a separate GIT project) (git clone https://git.issgs.net/khuber/TheEnterprise-Install_Script.git)
2. Review the README for the installation script for installation instructions.
3. To run TE, you must be in the path where TE is installed, by default that is: > cd /pentest/py3virtual/the_enterprise.
4. Activate the virtualenvironment: > source ../bin/activate
5. Start either the command-line view (python enterprise.py), the GUI (python enterprise-flask.py) or BOTH. (Depending upon variables in enterprise_user_conf.py the GUI might autostart when the commandline is started (review the Configuration Options section below for more information).  All steps below with the exception noted in Step 6, can be done through the command-line (enterprise.py) or Web GUI (enterprise-flask.py)
6. The console has 2 features not present in the GUI.  1st - it can create and manage the Web GUI user accounts and 2nd - it setups up your profile which has your email address to send email notifications to and command-line options like filtering client/engagement selections.
7. Create a new client and a new engagement for that client (faster in the GUI but a little more prone to typos if you are adding just a new engagement for an existing client)
8. Or Select a current client/engagement to continue doing work in.
9. If you have not elected to have CELERY auto start (see the Configuration Options section above) then you must open a console, cd to the TE installation path, source ../bin/activate, and run celery as will be specified (on the homepage of the Web GUI and on the screen for the command-line).  `The command-line will not let you do anything until it sees celery running for the created/selected client/engagement.  The Web GUI will let you 'run tools' but those tools will only be queued up until you have this celery instance running.'`
10. Additional client/engagement information will be asked: like who should auto recieve email notifications, if tools should be rerun, if IPs should only be external/public IPs, if you want open ports created as a finding (probably only want this if you are doing external testing), etc.  These values here can be changed at any time during the engagement through the command-line or Web GUI views.
11. Now your client/engagement backend is all setup but you STILL need to input Location (if you want to have multiple locations), Scope, and optionally contacts (you must have client contact if you are going to be using the email filter vulnerability scanning).  In the command-line view, you will not see the rest of the menu options if you do not have at least 1 Scope entry which is not true for the Web GUI.
12. Add additional locations as desired (the location 'main' is automatically added for you).  Locations would most efficiently be added before Scope entries (but you can change a Scope entry's location at any time)
13. *Add at least 1 Scope entry* (but you might as well add all of them). `The comand-line view has the added feature of inserting scope entries from a text file where each line represents a new scope entry.  Each location would have to have a separate upload file to assign them automatically to different locations.`
14. Now run some tools.  You'll notice that I tried to order the tools according to the Penetration Phases.  So generally you can start with the tools under the 1st phase and work downward.  However, you do NOT have to.  Just be mindful that a lot of tools target devices that have a certain port or service running and if you have not done scanning or manually inserted them into the repository, then you will not have any devices to target even though some might exist on the network you are targeting.
15. To run a tool go to the corresponding menu - for Recon tools that would be under recon, etc, and select to run it.  Some tools will have questions you must answer to run it (credentials, # threads to run, etc), if so answer the ones required (not all are required) and then the tool will start within celery.
16. If you have celery running in a separate console / screen you will be able to see any tool output show up there.  Likewise you can, go to **Jobs -> Active** to view currently running jobs, **Jobs -> Queue** to see jobs that are waiting to run (either waiting for an open celery worker process or are setup to wait on a preceeding process), and **Logs** is where you can view the status of all tools run (see if still running, if finished, if parsed, if you were blacklisted, and see comments - reasons why it failed if it did fail).
17. Under **Results**, you will see the parsed results (Devices, Ports, Findings, Recon, People, and Credentials)
18. When done, you can generate an Excel spreadsheet report, "**Report -> Excel Report**".  If you are using Engage, you can upload the .out file to Engage and watch all your data transfer to Engage for Engage reports.

# Creating a WebApp (Flask) User
WebApp (Flask) users can **ONLY** be created from the command-line (enterprise.py).  
- Start cmd-line TE (python enterprise.py inside the virtual environment).  
- You can 'edit' your profile and select 'Y' to view WebApp users at login, then you will be presented with the WebApp Options (view, add, update, delete) and you can add a WebApp user.
- Or you can create/select an engagement and then go to the Setup Menu -> WebApp Menu, and here you can view, add, update, delete.
- Once you've created a WebApp user, make sure enterprise_flask is running (ps -ef|grep flask) or just surf to it with your browser.  If not running start it: python enterprise-flask.py

# Additional Tips / Information
- When creating an Engagement you will be asked several questions, these questions can be changed at anytime by going to "**Setup -> Engagement**" and then edit.
- Some questions are about emailing people (internal assessments should keep the default N).
- The question about External IP only, is a safety check if you are doing an External only engagement, that internal, private IPs can not be added to the Scope.
- The finding for open ports question (for External engagements), will auto add findings if certain open services are found (3389, 445, 23, 21, etc).
- The question about Re-running a tool for specific entry is used to check if it should rerun the same tool against the same target.  For example, you've already run nmap 192.168.0.0/24 and you hit nmap again if this is set to N (the default) it will not run nmap 192.168.0.0/24 (but if you have other entries that have not run it will run)
- The **Log** table is the heart and soul of managing the processes (queued, running, and already run).
- **Log** - You can truncate (delete all) entries in the Log table and all queued items will not run and even though you already ran a tool for an entry it will now let you rerun because it has not record of the prior run.  You will lose the historical work of what has been run.  The tool.log file will still have when all tools have started and finished, but will not be as granular or easily searchable as the **Log** table.
- **Make sure you start the user you start celery & theEnterprise in are both members of the LINUX_GROUP you noted in enterprise_user_conf.py**
- `Celery must be started for each client/engagement currently being used.  Both TE web gui and console view will tell you the command to copy and paste to start the celery workers for the client/engagement you have selected.`
- If you want to kill celery - doing a 'pkill celery' will kill all celery workers (if you have multiple engagements running at the same time this will kill your others celery - or someone else's celery workers - like on a scanner box).  On shared systems, better use ps -ef| grep celery to find the celery processes for your engagement and kill them individually (by default there will be 8) and each celery process will have your client name and engagement number in the process name.

# Example Getting Started Steps:
1. git clone https://git.issgs.net/khuber/TheEnterprise-Install_Script.git
2. cd TheEnterprise-Install_Script
3. vi install.sh - if you want you can change the 'PENTESTDIR' and/or the 'CLIENTDIR'
4. chmod +x *
5. ./install.sh - you will have to occassionally hit Y or OK for various installs and updates (this will install and update all tools used by TheEnterprise (TE) including TE itself.
6. cd to the PENTESTDIR location (default /pentest/) and then cd to py3virtual/the_enterprise
7. source ../bin/activate (now you are within python3 virtual environment)
8. python enterprise.py (console view) or python enterprise-flask.py (web gui view)
9. create / select your client/engagement
10. if you do not want celery to auto-start so you can see any output, then do steps 11-14 otherwise skip to 15
11. open another console or screen
12. cd PENTESTDIR/py3virtual/the_enterprise
13. source ../bin/activate
14. copy and paste the celery command from either enterprise.py console or the homepage in enterprise-flask.py web gui
15. To use the GUI for the 1st time, you WILL have to create a web user from enterprise.py console view first.
16. Go to, Setup -> Web User -> Add (your username should be the same as your issg username if going to incorporate this with Engage)

# Tool Global Values
vi tool.yaml
- tools can have global values set for a specific tool inside its yaml config file
- for instance: tools/vuln/gobuster.yaml has gobuste_wordlist variable that is a global variable so that if a user does not specify an answer to that question that value is used

# Current Tools Implemented
- Amass
- Blacksheepwall
- DNS Lookup (built-in)
- DNS Bruteforce (built-in)
- DNSDict6
- DNSFootprint.pl
- DNSRecon
- DNS Zone Transfer (built-in)
- FindFrontalDomain
- LinkedInt
- Shodan
- crtsh
- gobuster
- theHarvester (10 different search engines)
- ARP Ping (built-in)
- Nmap
- Nmap (ping)
- Massscan
- Enum4Linux
- Eyewitness
- Metasploit enumeration modules (35 of them)
- Netview (active directory computer enumeration)
- Burp
- Dirbuster
- Email filter vulnerability scan (built-in)
- Nmap promiscuous mode finding
- Nessus
- Nikto
- xsstrike
- wpscan
- Zap
- Hydra bruteforcer (38 modules)
- Medusa bruteforcer (22 modules)
- Metasploit bruteforce modules (9 modules)
- Metasploit ASA extrabacon
- Metasploit OWA login
- Ncrack bruteforcer (11 modules)
- Responder
- RunFinger (identify smb signing disabled targets)
- SMBRelayx
- NTLMRelay
- Secretsdump AD hashes
- Secretsdump AD detail w/ hashes
- Secretsdump AD history hashes
- Samrdump Local Users detail

# Tools under development or not fully implemented
Review the todo to see other possile tools and ideas that will be in the works to implement
- Email Phishing (built in)
- DHCP server
- DHCP FORCERENEW (built in)

# Optional Tool Development / Addition Documentation Below

## Adding a New Tool:
1. Creating a YAML file
2. adding the tool to common/navigation_menu.py
3. creating your parser file (name it what you named it in the YAML file and it need to return a dictionary of the table:values to insert)

### YAML Configuration Documentation
Below is an example YAML config file:
```
tool author: "https://cirt.net/Nikto2"  -> who wrote the actual tool
config_creator: "huber"                 -> who created this yaml config
tool_name: "nikto"                      -> name of the tool
simultaneous: False                     -> either True or False (if each target identified should be run at the same time or wait to run 1 at a time)
group_by: "target"                      -> either "target" or "tool" -> determines how to apply simultaneous if set to False (ex. for nmap you don't want to run 2 different nmap scans against same target but do want to run a nmap scan against each unique target so you set 'group_by'='target'.  For theHarvester, you don't want to run multiple targets against the same search enginge (or you'll probably get blocked) so you set 'group_by'='tool'
targets:                                -> inside here you specify the targets to go after
      special: "all_websites"           -> you can specify an special (view Special Target Section below)
target_by_host_file: False              -> if True the target for each command would be the host_file (useful when you want to run a tool against a group of targets at once for optimization purposes)
command: "<nikto_path> -nointeractive <nikto_stealthy> -Format XML -Pause <nikto_pause_time> -maxtime <nikto_max_execution_time>m -host ENTRY -port PORT SSL -output OUTPUT_FOLDERnikto__sSCOPE_ID__FORMATTED_ENTRY.xml"    -> this is the actual command that will be run. With several PLACEHOLDERS located throughout the command.  View Placeholder section below for more information.
function_to_call "FUNCTION:tools.recon.dns_query.dns_query" -> For built-in tools this is used over the command option above and you specify the path to the function that should be run.
function_pass_json: True                -> used in companion with function_to_call (NOT for command), if True the answers to any questions are passed to the function identified in function_to_call
output_path: "output/vuln/nikto/"       -> the base output path for this tool. every actual run will create a sub folder whose name is the timestamp it was created
tool_parser: "parsers.vuln.nikto_parser.nikto_parser"   -> the path to the parsing function for this tool
check_already_run: True                 -> whether this tool cares if it has already been run for a target or not (most will but some like responder you don't care)
create_folder: True                     -> whether you want to create the output_folder (only manual parsing should have this set, all other tools must generate an output file and thereby must create the output folder to save the output file to)
questions:                              -> list of questions to ask the user. If the question is global and the global value exists and is not null, then this question will not show up for the user as the global value will be used.
      - question: "Nikto path"          -> display text shown to the user so they know what information is being asked for
        name: "nikto_path"              -> the name of the field (note that if you need the user's answer for the command this name must match what is used in the command but in the command this name is encapsulated by <>
        nullable: False                 -> if the user can not enter any answer
        regex:                          -> any regex checks that must be met for an acceptable answer
        global: True                    -> if the question has a global variable that might be set and if so then that global variable is used and this question is not even asked.
      - question: "Pause between scans (in secs)"   -> next question display text
        name: "nikto_pause_time"        -> next question field name
        nullable: False                 -> next question if can be null/blank
        regex: "[0-9]+"                 -> next question's regex check (in this example, the user must enter a number)
        global: True                    -> if the question has a global variable to use instead if set
      - question: "Nikto evasion"       -> 3rd question display text
        name: "nikto_stealthy"          -> 3rd question field name
        nullable: False                 -> 3rd question if can be null
        regex: "^(?:Y|N)$"              -> 3rd question regex
        global: True                    -> 3rd question if global variable
        answers:                        -> 3rd question answers. this is used to subsitute user supplied answers, or append
          Y: "-evasion 1"               -> 3rd question possible answer: if Y then the real answer to substitute in the command is '-evasion 1'
          N: ""                         -> 3rd question possible answer: if N then substitute will be blank
          blank: ""                     -> if blank was entered then use blank (could have had '-evasion 1' as blank answer)
          default: ""                   -> default answer to question if doesn't match any other answers
```
Look through the yaml_template.txt inside the 'documents' folder inside the TE installation path for more options.  Also, look at current yaml tool config files, which can be found under the tools/ folder in the TE installation path.

#### Target Options
These target options can be used together (for example: if you want to grab all targets that have port 21 or have 'ftp' in the port description, you'd include both port_numbers and port_descriptions).
##### scope:
Must be one of the following:
- SCOPE_IPS
- SCOPE_SINGLE_IP -> used for tasks that are not tied directly to specific scope like Responder
- FORCE_SCOPE_IPS -> not allow live hosts if that option was selected
- SCOPE_DOMAINS
- SINGLE_SCOPE_DOMAIN -> just uses 1st scope domain pulled back
- ALL_DOMAINS -> includes DOMAIN and A records from Recon results + Scope Domains
- SCOPE_WEBSITES
- SCOPE_IPS+SCOPE_WEBSITES
- SCOPE_IPS+SCOPE_DOMAINS
- ASN -> Recon result that is ASN type
- CLIENTNAME
- ALL

##### port_numbers:
Just put a string of port numbers separated by commas (if multiple).  For example:
- port_numbers: "21"
or
- port_numbers: "80,8080,443"

##### port_desriptions:
Just put a string of port numbers separated by commas (if multiple).  For example:
- port_descriptions: "web,iis,tomcat,apache"

##### protocol:
Only is relevant to port_descriptions and port_numbers and unlike the rest provides an AND filter instead of an OR, meaning it would have to be TCP port # 21 not TCP or port #21 (because then you'd match all open ports that were TCP!)

##### special:
These represent pre-defined repository queries and the current possible valid options are:
- all_email_servers
- all_websites
- all_vnc_servers
- all_rdp_servers
For example: special: all_vnc_servers
Or you can specify that the target or group of targets is a response provided by an answer to a YAML question.  To use this option you put: special: <QUESTION_FIELD_NAME>
For example: special: <interface_name> if you had a question in the YAML file whose name was 'interface_name'.

#### Placeholder
A placeholder can represent a string of characters that will be replaced from global client/engagement data (like the client's name).  These types of placeholders are in all caps and the current list of these types of placeholders is below:
- CLIENT_NAME: the actual client name for this engagement is replaces this string of characters
- CLIENT_NAME_FORMATTED: because the client name had spaces, the spaces are substituted with 5 'Z' (ex. 'Post Office' would be 'PostZZZZZOffice') - only useful for a couple unique tools so far
- SCOPE_ID: the actual scope id replaces this, if this is part of an output file name then a __sSCOPE_ID should be present to more precisely grab the accurate file for parsing later
- FORMATTED_ENTRY: the target (scope entry, host file, or specific device) formatted to replace some special characters including: 'http://' 'https://' '/' ',' ':' and " "
- ENTRY: the target (scope entry, host file, or specific device)
- PORT: the port number being targeted
- OUTPUT_FOLDER: the output folder location pulled for that specific generated Log entry and includes the full path down to the timestamp-named folder
- FORMATTED_WEBSITE: similar to FORMATTED_ENTRY
- PROTOCOL: the protocol being targeted
- SSL: if '-ssl' should replace it based on if https vs http
- CODE_BASE_PATH: installation path of TE
- RDP_HOST_FILE: replaced by the hosts/port#__sSCOPE_ID.txt file name
- VNC_HOST_FILE: similar to RDP_HOST_FILE
- WEB_HOST_FILE: similar to RDP_HOST_FILE
- SMB_SIGNING_DISABLED_FILE: similar to RDP_HOST_FILE
- HOST_FILE: replaced by the actual host file name
The other type of placeholder is a question/answer placeholder. Meaning in the command you can put ''<nikto_path>' and you must have a question whose name is 'nikto_path' because it will replace whatever the ending value of that question's answer is for '<nikto_path>'

#### Questions
Questions are optional and only should be used when needed to run the tool.  A basic question only needs to have the following fields:
```questions:
    -question: 'Display text'
      name: 'display_text'
      nullable: True|False
      regex:
      global: True|False
```

#### Optional Question Fields
```
under 'question:' you can put answers:
    answers:
        default: 30
        blank: 30
```

#### Global Tool Values
````
Above the questions, you put the question name value with its global default value
````
All other options are to be used only as needed.  If you don't want to check against a regex leave it blank like above, don't put '' as that will give you unexpected results.
