#!/bin/bash
# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v1.1
# Released under GPL Version 2 license.
# Use at your own risk
# Modified by Kevin Huber July 2017 for use with TheEnterprise

# Use this to load different configuration files (which can then start Burp on different listeners)
# --config-file="burp_user_options.json"

# Change working directory to location where launch_burp.sh is located
cd "${0%/*}"

if [[ -n $1 && -n $2 && -n $3 && -n $4 && -n $5 ]] #not provide enough parameters to launch carbonator
then
	SCHEME=$1
	FQDN=$2
	PORT=$3
	JAR_LOCATION=$5
	CARBONATOR_LOCATION=$6
	REPORT_FILE=$7
	if [[ -n $4 ]]
	then
		FOLDER=$4
	fi
    #-Djava.awt.headless=true
	echo Launching Burp Scan against $1://$2:$3 $4
	java -Djava.awt.headless=true -jar -Xmx1024m $JAR_LOCATION $SCHEME $FQDN $PORT $FOLDER

	echo Moving Burp report $6/burp_$1_$2_$3.xml to $7
	mv -v $6/burp_$1_$2_$3.xml $7
else
	echo Usage: $0 scheme fqdn port export_path path_to_burp_jar carbonator_path report_path
	echo '    'Example: $0 http localhost 80 /folder /pentest/burp/burp_pro.jar /the_enterprise/tools/vuln/carbonator/ /usr/local/clients/0/1/output/vuln/burp/burp__http_example.com.xml
	echo '    Scan multiple sites: cat scheme_fqdn_port.txt | xargs -L1 '$0
fi

exit
