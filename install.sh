#!/bin/bash
#set -x #echo everything

# Modify the 5 following variables as desired
PENTESTDIR=/pentest            # This is where TheEnterprise will be installed (PENTESTDIR/py3virtual/the_enterprise)
CLIENTDIR=/usr/local/clients/  # This is where your client information will be stored
LINUXGROUP=staff               # This is the group that will have permission to run TE (not necessarily modify it) if this is on a shared resource

DEFAULT_USER=captain
DEFAULT_PASSWD=donewithstartrek

# ------------------- DO NOT CHANGE ANYTHING BELOW HERE ------------------------

CURRENT_WORKING_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

dpkg --configure -a

# In case you have not updated kali in awhile this will grab the old key to allow updating
wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add

# Update Repositories
apt --fix-broken install -y
sudo apt-get update -y
sudo apt-get -y upgrade
apt --fix-broken install -y

if [ ! -d "$CLIENTDIR" ]; then
    sudo mkdir $CLIENTDIR
fi
sudo chmod 775 $CLIENTDIR
sudo chgrp $LINUXGROUP $CLIENTDIR


dpkg --configure -a

#----------------------------------------------------------------------
# These are PYTHONv2 tools so must do before inside virtual environment
#----------------------------------------------------------------------
# Audit/Get Local Users
#apt-get install wmi-client
#pip install wmi-client-wrapper

# Install python Pandas
#python2 -m pip install pandas

# Snapback related stuff
apt-get install npm
npm install -g n stable
apt-get install sqlite


# LDAP
apt-get install build-essential python3-dev python2.7-dev libldap2-dev libsasl2-dev slapd ldap-utils lcov valgrind
#python -m pip install python-ldap
git clone https://github.com/ropnop/windapsearch.git $PENTEST_DIR/windapsearch/


# Check if DataSploit is installed otherwise install
if [ ! -d "$PENTESTDIR/datasploit/" ]; then
    git clone https://github.com/DataSploit/datasploit.git $PENTESTDIR/datasploit/
    cp $PENTESTDIR/datasploit/config_sample.py $PENTESTDIR/datasploit/config.py
    pip install -r $PENTESTDIR/datasploit/requirements.txt
    pip install cfscrape
fi
chgrp -R $LINUXGROUP $PENTESTDIR/datasploit
chmod -R 775 $PENTESTDIR/datasploit/

# Install ZAP
if [ ! -d "$PENTESTDIR/zap/" ]; then
    mkdir $PENTESTDIR/zap
    cd $PENTESTDIR/zap
    wget https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Linux.tar.gz
    tar -xzvf ZAP_2.7.0_Linux.tar.gz
    cd ZAP_2.7.0
    cp -r * ../
    cd ../
    chmod +x *.sh
    #start java -jar zap-2.7.0.jar
    #start w/o gui: ./zap.sh -daemon
fi

# Check if EyeWitness is installed otherwise install
apt-get install -y libxml2-dev libxslt1-dev #necessary for eyewitness dependant
if [ ! -d "$PENTESTDIR/eyewitness/" ]; then
    git clone https://github.com/ChrisTruncer/EyeWitness.git $PENTESTDIR/eyewitness/
    sudo $PENTESTDIR/eyewitness/setup/setup.sh
fi

# Get newest Responder version
if [ ! -d "$PENTESTDIR/responder/" ]; then
    git clone https://github.com/lgandx/Responder.git $PENTESTDIR/responder/
fi

# MassScan
sudo apt-get install git gcc make libpcap-dev -y
if [ ! -d "$PENTESTDIR/massscan/" ]; then
    git clone https://github.com/robertdavidgraham/masscan $PENTESTDIR/massscan/
    cd $PENTESTDIR/masscan
    make -j
fi

# SMBetray
if [ ! -d "$PENTESTDIR/smbetray/" ]; then
    git clone https://github.com/QuickBreach/SMBetray.git $PENTESTDIR/smbetray/
    cd $PENTESTDIR/smbetray
    sudo ./install.sh
fi

# Impacket
if [ ! -d "$PENTESTDIR/impacket/" ]; then
    git clone https://github.com/CoreSecurity/impacket.git $PENTESTDIR/impacket/
    cd $PENTESTDIR/impacket/
    python setup.py install
fi

# Pywerview
if [ ! -d "$PENTESTDIR/pywerview/" ]; then
    git clone https://github.com/the-useless-one/pywerview $PENTESTDIR/pywerview/
fi

# FindFrontableDomains
if [ ! -d "$PENTESTDIR/FindFrontableDomains/" ]; then
    git clone https://github.com/rvrsh3ll/FindFrontableDomains.git $PENTESTDIR/FindFrontableDomains/
    cd $PENTESTDIR/FindFrontableDomains/
    ./setup.sh
fi

# THC-IPv6
if [ ! -d "$PENTESTDIR/thc-ipv6/" ]; then
    git clone https://github.com/vanhauser-thc/thc-ipv6.git $PENTESTDIR/thc-ipv6/
    cd $PENTESTDIR/thc-ipv6/
    sudo apt-get install libpcap-dev libssl-dev libnetfilter-queue-dev -y
    make all
    make install
fi

# Python DHCP server
if [ ! -d "$PENTESTDIR/pydhcp/" ]; then
    git clone https://github.com/tmeiczin/pydhcp.git $PENTESTDIR/
fi

# Struts PWN 2017-9805
if [ ! -d "$PENTESTDIR/struts/struts_pwn_2017_9805/" ]; then
    git clone https://github.com/mazen160/struts-pwn_CVE-2017-9805.git $PENTESTDIR/struts/struts_pwn_2017_9805/
fi

# Struts PWN 2018-11776
if [ ! -d "$PENTESTDIR/struts/struts_pwn_2018_11776/" ]; then
    git clone https://github.com/mazen160/struts-pwn_CVE-2018-11776.git $PENTESTDIR/struts/struts_pwn_2018_11776/
fi

## Install Wine
#apt-get install wine -y

dpkg --configure -a

# Install NodeJS
curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
apt install -y nodejs
apt-get install npm -y

# Install scope-creep
if [ ! -d "$PENTESTDIR/scope_creep/" ]; then
    git clone https://github.com/fkasler/scope_creep.git $PENTESTDIR/scope_creep
    cd scope_creep
    npm install
fi

## POWERSHELL on KALI
sudo apt update && apt -y install curl gnupg apt-transport-https
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/powershell.list
sudo apt update
sudo apt -y install powershell
## Download & Install prerequisites
#echo "Installing Powershell"
#apt --fix-broken install
#sudo apt-get install libunwind8 -y
#apt --fix-broken install
#apt-get install multiarch-support -y
#sudo dpkg -i libicu55_55.1-7_amd64.deb
#dpkg --configure -a
#apt --fix-broken install
##wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u7_amd64.deb
#sudo dpkg -i libssl1.0.0_1.0.1t-1+deb8u7_amd64.deb
#dpkg --configure -a
#apt --fix-broken install
## Download & Install PowerShell
##wget https://github.com/PowerShell/PowerShell/releases/download/v6.0.0/powershell_6.0.0-1.ubuntu.16.04_amd64.deb
#sudo dpkg -i powershell_6.0.0-1.ubuntu.16.04_amd64.deb
#dpkg --configure -a
## Start PowerShell
##pwsh
apt --fix-broken install

# PowerMeta
if [ ! -d "$PENTESTDIR/PowerMeta/" ]; then
    git clone https://github.com/dafthack/PowerMeta.git $PENTESTDIR/PowerMeta
fi

# MailSniper
if [ ! -d "$PENTESTDIR/MailSniper/" ]; then
    git clone https://github.com/dafthack/MailSniper.git $PENTESTDIR/MailSniper/
fi

# metagoofil
if [ ! -d "$PENTESTDIR/metagoofil/" ]; then
    git clone https://github.com/laramies/metagoofil.git $PENTESTDIR/metagoofil/
fi

# GOLANG
echo "Installing GOLANG"
apt-get install golang
# GOLANG WORKSPACE
if [ ! -d "$PENTESTDIR/golang/" ]; then
    mkdir $PENTESTDIR/golang/
    export GOPATH=$PENTESTDIR/golang
    echo GOPATH=$PENTESTDIR/golang >> /etc/profile
    export PATH=$PATH:$PENTESTDIR/golang/bin
    export GOBIN=$GOPATH/bin
    echo GOBIN=$GOBIN >> /etc/profile
    echo PATH=$PATH:$PENTESTDIR/golang/bin >> /etc/profile
    source /etc/profile
fi

# Ruler
if [ ! -d "$PENTESTDIR/golang/src/github.com/ruler/" ]; then
    git clone https://github.com/sensepost/ruler.git $PENTESTDIR/golang/src/github.com/ruler/
    go get -u github.com/sensepost/ruler/...
    cd $GOPATH/src/github.com/sensepost/ruler
    go install ./...
fi

# GoBuster
if [ ! -f "$PENTESTDIR/golang/bin/gobuster" ]; then
    #git clone https://github.com/OJ/gobuster.git $PENTESTDIR/golang/src/github.com/gobuster/
    go get -u github.com/OJ/gobuster/...
    cd $GOPATH/src/github.com/OJ/gobuster
    go install ./...
fi

# Bettercap
if [ ! -d "$PENTESTDIR/bettercap/" ]; then
    go get -u github.com/bettercap/bettercap/...
    cd $GOPATH/src/github.com/bettercap/bettercap
    go install ./...
fi

# blacksheepwall
if [ ! -f "$PENTESTDIR/golang/bin/blacksheepwall" ]; then
    #git clone https://github.com/tomsteele/blacksheepwall $PENTESTDIR/golang/src/github.com/blacksheepwall/
    go get -u github.com/tomsteele/blacksheepwall/...
    cd $GOPATH/src/github.com/tomsteel/blacksheepwall
    go install ./...
fi

apt-get install amass
# Amass - https://github.com/OWASP/Amass
if [ ! -f "$PENTESTDIR/golang/bin/amass" ]; then
    go get -u github.com/OWASP/Amass/...
    cd $GOPATH/src/github.com/OWASP/Amass
    go install ./...
fi
# first install and start snap and add snap binaries to path
#sudo apt install snapd
#sudo systemctl start snapd
export PATH=$PATH:$PENTESTDIR/golang/bin
# now use snap to install amass
#sudo snap install amass

# C# compiling/running
apt-get install mono-devel -y
apt-get install mono-complete -y

if [ ! -d "$PENTESTDIR/ptf/" ]; then
    # Clone PTF - which will install / update pentest tools in default $PENTESTDIR directory
    git clone https://github.com/trustedsec/ptf.git $PENTESTDIR/ptf/
    # sudo $PENTESTDIR/ptf/ptf --no-network-connection
fi

# Check if DirSearch is installed otherwise install
if [ ! -d "$PENTESTDIR/dirsearch/" ]; then
    git clone https://github.com/maurosoria/dirsearch.git $PENTESTDIR/dirsearch/
fi

# Install S3Scanner script
if [ ! -d "$PENTESTDIR/s3scanner/" ]; then
    git clone https://github.com/vysec/S3Scanner.git $PENTESTDIR/s3scanner/
    pip install -r requirements.txt
fi

# Install Jexboss
if [ ! -d "$PENTESTDIR/jexboss/" ]; then
    git clone https://github.com/joaomatosf/jexboss.git $PENTESTDIR/jexboss/
    pip install -r requirements.txt
fi

# Install Seth (RDP mitm)
if [ ! -d "$PENTESTDIR/seth/" ]; then
    git clone https://github.com/SySS-Research/Seth.git $PENTESTDIR/seth/
    pip install -r requirements.txt
fi

# Install Sublist3r
if [ ! -d "$PENTESTDIR/sublist3r/" ]; then
    git clone https://github.com/aboul3la/Sublist3r.git $PENTESTDIR/sublist3r/
fi

# Install SpiderFoot
if [ ! -d "$PENTESTDIR/spiderfoot/" ]; then
  git clone https://github.com/smicallef/spiderfoot.git $PENTESTDIR/spiderfoot/
fi

# CrackMapExec
apt-get install crackmapexec -y
#sudo apt-get install -y libssl-dev libffi-dev python-dev build-essential
#if [ ! -d "$PENTESTDIR/crackmapexec/" ]; then
#    sudo pip install pipenv
#    git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec $PENTESTDIR/crackmapexec/
#    cd $PENTESTDIR/crackmapexec && pipenv install
#    pipenv shell
#    python setup.py install
#    exit
#fi

# This is where the_enterprise will be installed and run from
VIRTUALDIR=$PENTESTDIR/py3virtual
if [ ! -d "$VIRTUALDIR" ]; then
    mkdir $VIRTUALDIR
fi

apt --fix-broken install

echo "Installing Python3 and setting up virtual environment ..."
sudo apt-get install python3 python3-dev build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev -y
sudo apt-get install python3-venv -y
sudo apt-get install python3-pip -y
python3 -m venv $VIRTUALDIR

echo "Moving into Virtual Directory $VIRTUALDIR"
cd $VIRTUALDIR
source $VIRTUALDIR/bin/activate

# Used for finding names in text
#pip install nltk
#pip install nameparser

# Additional 3rd Party tools - ones that use Python3
echo "Still installing 3rd Party tools (these are of the py3 type)."
# FuxExploiter
if [ ! -d "$PENTESTDIR/fuxploider/" ]; then
    git clone https://github.com/almandin/fuxploider.git $PENTESTDIR/fuxploider/
    cd fuxploider
    python -m pip install -r requirements.txt
    #pip3 install -r requirements.txt
fi

# Install XSStrike
if [ ! -d "$PENTESTDIR/xsstrike/" ]; then
    git clone https://github.com/s0md3v/XSStrike.git $PENTESTDIR/xsstrike/
    cd $PENTESTDIR/xsstrike/
    python -m pip install -r requirements.txt
    python -m pip install fuzzywuzzy
fi

cd $VIRTUALDIR

echo "Virtual Directory activated!  Now time to get TheEnterprise!"

if [ ! -d "$VIRTUAL/the_enterprise" ]; then
    mkdir $VIRTUALDIR/the_enterprise
    cp -r $CURRENT_WORKING_DIR/* $VIRTUALDIR/the_enterprise/
    # clone the_enterprise inside py3virtual/the_enterprise
    #git clone https://git.issgs.net/khuber/the_enterprise.git $VIRTUALDIR/the_enterprise
fi

# Pypi modules
pip3 install -r requirements.txt
#pip3 install pyyaml
#pip3 install terminaltables
#pip3 install colorclass
#pip3 install sqlalchemy
#pip3 install dateutils
#pip3 install netaddr
#pip3 install ipaddress
#pip3 install pythonwhois
#pip3 install pygeoip
#pip3 install ipwhois
#pip3 install dnspython
#pip3 install lxml
#pip3 install bleach
#pip3 install py3dns
#pip3 install requests    #used by theHarvester
#pip3 install shodan
#pip3 install pyrabbit    #not used yet
#pip3 install XlsxWriter
#pip3 install selenium
#pip3 install beautifulsoup4
#pip3 install msgpack-python #used by MetasploitRPC
#pip3 install netifaces
#pip3 install psutil
#pip3 install readline
#pip3 install pexpect
#pip3 install python-owasp-zap-v2.4
#pip3 install scrapy
#pip3 install pika        #interacts w/ rabbitmq
#pip3 install bs4         #used by LinkedInt
#pip3 install thready     #used by LinkedInt
#pip3 install cookiejar   #used by LinkedInt
#pip3 install exchangelib #used by OWA bruteforce
#pip3 install ldap3       #used for AD (ldap) querying (replace hyena)
#pip3 install matplotlib  #used by scapy
#pip3 install PyX         #used by scapy
#pip3 install pysmb       #used by my pywerview_run to download the GPOs
##pip3 install pysnmp      #used to get & walk snmp devices
#pip3 install pyhunter     #hunter.io library
#pip3 install crtsh      # used to search crtsh
#pip3 install python-socketio-client #used for sockets.io (scope_creep, ...)
#pip3 install droopescan # used for scan CMS sites (drupal, joomla, wordpress, etc)

# Flask
#pip3 install Flask
#openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout $VIRTUALDIR/the_enterprise/flask/flask.key -out $VIRTUALDIR/the_enterprise/flask/flask.crt
#US
#Palmyra
#the_enterprise-flask
#pentesting framework
#the.domain.tld

apt --fix-broken install -y

# Celery
sudo apt-get install -y build-essential libssl-dev ncurses-dev m4
apt-get --fix-broken install
#pip3 install celery
if [ ! -d "/var/run/celery/" ]; then
    sudo mkdir /var/run/celery
fi

apt autoremove -y
apt-get remove erlang17-base -y
apt-get install erlang-base -y
sudo apt-get install rabbitmq-server -y
apt-get --fix-broken install -y
systemctl start rabbitmq-server
systemctl enable rabbitmq-server
#pip3 install redis
#pip3 install -U celery[redis]
sudo apt-get install redis-server -y
/etc/init.d/redis-server start
systemctl enable redis-server

# Install Scapy python3
if [ ! -d "$PENTESTDIR/scapy-master" ]; then
    cd $PENTESTDIR
    wget https://github.com/secdev/scapy/archive/master.zip
    unzip master.zip
    cd $PENTESTDIR/scapy-master/
    python setup.py install
fi

# Install Drupwn python3
if [ ! -d "$PENTESTDIR/drupwn" ]; then
    cd $PENTESTDIR
    git clone https://github.com/immunIT/drupwn.git $PENTESTDIR/drupwn
    cd $PENTESTDIR/drupwn/
    pip3 install -r requirements.txt
fi

# PhantomJS
sudo apt-get install build-essential chrpath libssl-dev libxft-dev -y
sudo apt-get install libfreetype6 libfreetype6-dev libfontconfig1 libfontconfig1-dev -y
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2
tar xvjf phantomjs-2.1.1-linux-x86_64.tar.bz2 -C /usr/local/share/
sudo ln -sf /usr/local/share/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin

# Copy get_adusers.py to impacket/examples b/c modified version to include additional information (account-expires)
cp $PENTESTDIR/py3virtual/the_enterprise/tools/credential/get_adusers.py $PENTESTDIR/impacket/examples/

apt --fix-broken install -y

sudo apt-get install p7zip-full -y
sudo apt-get install nikto -y

apt --fix-broken install -y

# Copy CLIENTDIR to OUTPUT_PATH
sed -i "/OUTPUT_PATH = /c\OUTPUT_PATH = '$CLIENTDIR'" $VIRTUALDIR/the_enterprise/enterprise_user_conf.py

# Copy Pentest Dir to PENTEST_DIR
sed -i "/PENTEST_DIR = /c\PENTEST_DIR = '$PENTESTDIR/'" $VIRTUALDIR/the_enterprise/enterprise_user_conf.py

# Copy Linux Group to LINUX_GROUP
sed -i "/LINUX_GROUP = /c\LINUX_GROUP = '$LINUXGROUP'" $VIRTUALDIR/the_enterprise/enterprise_user_conf.py

# Make enterprise.sh executable
chmod +x $VIRTUALDIR/the_enterprise/enterprise.sh

# Copy VIRTUALDIR to enterprise.sh
sed -i "/VIRTUALDIR=/c\VIRTUALDIR=$VIRTUALDIR" $VIRTUALDIR/the_enterprise/enterprise.sh

# Now create a shortcut so you can just type enterprise from anywhere and you are good to go
sudo ln -s $VIRTUALDIR/the_enterprise/enterprise.sh /usr/local/bin/enterprise

# Update permissions
chmod -R 775 $VIRTUALDIR/the_enterprise/tools/recon/theharvester/
chgrp -R $LINUXGROUP $VIRTUALDIR/the_enterprise/tools/recon/theharvester/


# Fix celery async
#!/bin/sh
# FIX Celery redis on Python3.7
# https://github.com/celery/celery/issues/4500
TARGET=$VIRTUALDIR/lib/python3.6/site-packages/celery/backends
cd $TARGET
if [ -e async.py ]
then
    mv async.py asynchronous.py
    sed -i 's/async/asynchronous/g' redis.py
    sed -i 's/async/asynchronous/g' rpc.py
fi
TARGET=$VIRTUALDIR/lib/python3.7/site-packages/celery/backends
cd $TARGET
if [ -e async.py ]
then
    mv async.py asynchronous.py
    sed -i 's/async/asynchronous/g' redis.py
    sed -i 's/async/asynchronous/g' rpc.py
fi
TARGET=$VIRTUALDIR/lib/python3.8/site-packages/celery/backends
cd $TARGET
if [ -e async.py ]
then
    mv async.py asynchronous.py
    sed -i 's/async/asynchronous/g' redis.py
    sed -i 's/async/asynchronous/g' rpc.py
fi

cd $VIRTUALDIR/the_enterprise

# Install python libraries necessary
pip3 install -r requirements.txt

# add amass dir & set permissions
mkdir amass
chgrp $LINUXGROUP amass
chmod 774 amass

# make sure anyone can edit email_event.db
sudo chmod 774 setup
sudo chgrp $LINUXGROUP setup
sudo chmod 774 setup/email_event.db
sudo chgrp $LINUXGROUP setup/email_event.db

python install.py

# since NMAP needs sudo, you must add the following to your sudoers visudo:
#<username> ALL = NOPASSWD: <path/to/nmap>
