import os
import sys
import random
import string
from common import encryption
from common import email_db_model
from common import print_text
from setup import install_helper
import getpass
from enterprise_user_conf import *

try:
    # change 'setup/' directory permissions, otherwise event.db permission errors
    os.system('chmod 774 ' +os.path.dirname(os.path.realpath(__file__)) + 'setup')

    import nltk
    curr_dir = os.getcwd() #os.path.dirname(os.path.realpath(__file__))
    virtual_dir = curr_dir[:curr_dir.rstrip("/").rfind("/")]
    nltk.download('punkt', download_dir=virtual_dir + "/nltk_data")
    nltk.download('averaged_perceptron_tagger', download_dir=virtual_dir + "/nltk_data")
    nltk.download('maxent_ne_chunker', download_dir=virtual_dir + "/nltk_data")
    nltk.download('words', download_dir=virtual_dir + "/nltk_data")

    print_text.print_bold("Finally all the children are taken care of, now time to configure The Enterprise!")

    star_trek_characters = ['picard', 'data', 'spock', 'kirk', 'mccoy', 'worf', 'q', 'scott', 'riker', 'laforge', 'chekov']
    user_entered_username = star_trek_characters[random.randint(0, 9)]
    user_pass = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=100))

    """
    user_entered_username = ''
    while True:
        user_entered_username = input("Please enter the username  to use for The Enterprise: ")
        confirm_user_username = input("Please re-enter the username: ")
        if user_entered_username == confirm_user_username and user_entered_username.strip() != "":
            break
        else:
            print_text.print_error("\tLooks like your username did not match!  Please try again.")

    user_pass = ''
    while True:
        user_pass = getpass.getpass("Please enter the password  to use for The Enterprise: ")
        confirm_user_pass = getpass.getpass("Please re-enter the password: ")
        if user_pass == confirm_user_pass and user_pass.strip() != "":
            break
        else:
            print_text.print_error("\tLooks like your password did not match!  Please try again.")
    """

    user_entered_hash = 'WF1fj3kUBBjeZKsu9acBKFOmC1spequUqYG4cMgj'
    """user_specified_hash = input("Do you want to specify your own hash key, this can NOT be changed later without "
                                "affecting data integrity, Y|N (default is N): ")
    if user_entered_hash == "Y":
        while True:
            user_entered_hash = input("Please enter the hash  to use for The Enterprise: ")
            confirm_user_hash = input("Please re-enter the hash: ")
            if user_entered_hash == confirm_user_hash:
                break
            else:
                print_text.print_error("\tLooks like your hash did not match!  Please try again.")
    """
    user_entered_hash = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=40))

    base = os.path.dirname(os.path.realpath(__file__)) + "/"
    if "/common" in base:
        base = base.replace("/common/", "/")

    email_db_model.initialize_email_db(base + 'setup/email_event.db')

    # Add flaskuser
    flask_add_values = {'username': user_entered_username, 'passwd': encryption.hash_string(user_pass)}
    flask_add_values = encryption.get_hash_string(["username"], flask_add_values)
    install_helper.add_flaskuser(flask_add_values)

    new_global_user_str = ""
    user_conf = os.path.dirname(os.path.realpath(__file__)) + "/enterprise_user_conf.py"
    if "the_enterprise" not in os.path.dirname(os.path.realpath(__file__)):
        user_conf = os.path.dirname(os.path.realpath(__file__)) + "/the_enterprise/enterprise_conf.py"
    with open(user_conf, 'r') as global_user_conf:
        user_lines = global_user_conf.readlines()
        for user_line in user_lines:
            if "HASH_KEY" in user_line:
                new_global_user_str = new_global_user_str + "HASH_KEY = '" + user_entered_hash + "'\n"
            else:
                new_global_user_str = new_global_user_str + user_line

    zap_api_key = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=49))
    new_global_user_str = new_global_user_str + "\nZAP_API_KEY='" + zap_api_key + "'\n"

    # Now rewrite enterprise_user_conf.py
    with open(user_conf, 'w') as global_user_conf:
        global_user_conf.write(new_global_user_str)

    """
    # default Email Event records
    EMAIL_EVENTS = [{'event': 'dirsearch',
                     'tester_msg': 'Directory guessing using a similar approach to dirsearch (and the dirbuster word list), has started for CLIENTNAME against TARGET in SCOPEENTRY.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'Directory guessing started for CLIENTNAME against TARGET in SCOPEENTRY',
                     'start_or_end': 'start'},
                    {'event': 'dns bruteforce',
                     'tester_msg': 'DNS bruteforcing for DOMAINNAME has finished against TARGET.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'DNS bruteforcing for CLIENTNAME',
                     'start_or_end': 'end'},
                    {'event': 'dns lookup',
                     'tester_msg': 'DNS lookup for DOMAINNAME has finished',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'DNS lookup for CLIENTNAME',
                     'start_or_end': 'end'},
                    {'event': 'dns zonetransfer',
                     'tester_msg': 'DNS zonetransfer attempt for DOMAINNAME has finished',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'DNS zonetransfer for CLIENTNAME',
                     'start_or_end': 'end'},
                    {'event': 'email filter',
                     'tester_msg': 'Email Filter/Relay Test messages sent for all mailservers / mx records identified for CLIENTNAME against TARGET in SCOPEENTRY.',
                     'client_msg': 'The email filter/relay testing is commencing, you will receive a series of emails for each identified email server.  Please forward back each message to EMAIL_MSG_WHERE_TO_FORWARD_BACK_TO which is also specified in each email test\'s message body.  These test emails will not appear to come from EMAIL_ADDRESS.  Each subject will say \'Test # ...,\' please forward to EMAIL_MSG_WHERE_TO_FORWARD_BACK_TO',
                     'corp_msg': 'The email filter/relay tests help determine deficiancies in the configuration of the email server(s) setup for CLIENTNAME\'s network.  Each identified email server is sent a series of emails to identify its configuration.  This helps us identify configuration problems, and vulnerabilities.',
                     'subject': 'Email Filter Relay Testing for CLIENTNAME against TARGET in SCOPEENTRY',
                     'start_or_end': 'start'},
                    {'event': 'email phishing',
                     'tester_msg': 'Email phishing using SCENARIONAME for CLIENTNAME.',
                     'client_msg': 'Currently selected emails have all been sent the phishing email.',
                     'corp_msg': 'Email phishing for CLIENTNAME is completed.',
                     'subject': 'Email phishing SCENARIONAME',
                     'start_or_end': 'end'},
                    {'event': 'enum4linux',
                     'tester_msg': 'Enum4Linux for DOMAINNAME completed',
                     'client_msg': 'Anonymous Active Directory enumeration was attempted.',
                     'corp_msg': '',
                     'subject': 'Anonymous AD enumeration against SCOPEENTRY',
                     'start_or_end': 'end'},
                    {'event': 'hashcat cracking',
                     'tester_msg': 'HashCat cracking finished.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'HashCat cracking',
                     'start_or_end': 'end'},
                    {'event': 'theharvester',
                     'tester_msg': 'Search engine harvesting has been started for CLIENTNAME against SCOPEENTRY.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'Search engine harvesting for CLIENTNAME against SCOPEENTRY.',
                     'start_or_end': 'start'},
                    {'event': 'nessus',
                     'tester_msg': 'Nessus vulnerability scanner has started for CLIENTNAME against SCOPEENTRY.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'Vulnerability Scanner started for CLIENTNAME against SCOPEENTRY',
                     'start_or_end': 'start'},
                    {'event': 'nikto',
                     'tester_msg': 'Nikto website vulnerability scanner has been started for CLIENTNAME.',
                     'client_msg': '',
                     'corp_msg': 'Nikto website vulnerability scanner has been started for CLIENTNAME against TARGET in SCOPEENTRY.',
                     'subject': 'Website Vulnerability Scan for CLIENTNAME against TARGET',
                     'start_or_end': 'start'},
                    {'event': 'nmap',
                     'tester_msg': 'Nmap scanning started for CLIENTNAME which includes the top 25 and the top 1024 most common ports for both UDP and TCP and then also a full TCP port scan against SCOPEENTRY.',
                     'client_msg': 'Open port scanning has been started by EMAIL_ADDRESS.  If you receive any notifications or alerts, please let EMAIL_ADDRESS know against SCOPEENTRY.',
                     'corp_msg': 'Port scannings purpose is to identify the services that are available which can then be tested for vulerabilities and weaknesses against SCOPEENTRY.',
                     'subject': 'Port Scanning started for CLIENTNAME against SCOPEENTRY',
                     'start_or_end': 'start'},
                    {'event': 'responder',
                     'tester_msg': 'Responder LLMNR, NBT-NS, MDNS poisoner for CLIENTNAME against SCOPEENTRY.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'MitM started for CLIENTNAME against SCOPEENTRY',
                     'start_or_end': 'start'},
                    {'event': 'shodan',
                     'tester_msg': 'Shodan search for device / public reconnaissance against SCOPEENTRY.',
                     'client_msg': '',
                     'corp_msg': '',
                     'subject': 'Shodan search for CLIENTNAME against SCOPEENTRY',
                     'start_or_end': 'start'}]

    number_rows_added = install_helper.add_default_email_events(user_entered_hash, EMAIL_EVENTS)
    """

    print_text.print_msg("You have successfully setup The Enterprise!  Happy pentesting!  \n\tIf you want to change your encryption key, you must do a fresh install!")

    print_text.print_msg("If you want to be able to change Email Event wording, who receives them, and the actual events,"
                 " you will need to add/change that specific tool's .yaml file configuration.  You can refer to the documents/yaml_template for an example.")

    print_text.print_bold("Congrats!  You've finished setting up and install The Enterprise!  You should look at the_enterprise/enterprise_user_conf.py for variables you should update (such as your API keys and some tool executables, you might neeed to install these if not already installed on your system - look into TrustedSec/PTF on git for help on managing some of the necessary tools), etc)")
    print_text.print_msg("To run The Enterprise, you must be in the python virtual environment setup first.  Follow these easy "
                     "steps to start The Enterprise (and celery which The Enterprise uses):"
                     "\n\t1.cd INSTALL DIRECTORY\n\t3.source ../bin/activate\n\t2.python enterprise.py"
                     "\n\t** You might also need to change the folder permissions to /usr/local/clients so that you and "
                     "anyone on this device using The Enterprise will have read/write access to it (ie. sudo chgrp YOUR_GROUP_NAME /usr/local/clients)"
                     "\n\n\t*** Celery must be run inside the virtual environment as well and in a new console or screen "
                     "and must be started first for The Enterprise to run.  Celery can remain running and would only need to be "
                     "stopped when The Enterprise code has been updated so that it has access to the newest code.\n\n"
                     "**** YOU should also change any variables in enterprise_user_conf.py.  These variables can be changed "
                         "at any time as specific tools require this variables be set.")
    print_text.print_bold("You MUST add " + PENTEST_DIR + "golang/bin to your $PATH environment variable in order to "
                          "use golang tools (like gobuster, bettercap, etc). "
                          "You can append: ':/" + PENTEST_DIR + "golang/bin' to /etc/profile to apply to all users or "
                        "do: export PATH=$PATH:" + PENTEST_DIR + "golang/bin for just you")
    print_text.print_msg("Your default WebApp (Flask) credentials are: " + user_entered_username +  "/" + user_pass + " which "
                                                                        "SHOULD be changed by running enterprise.py.")
except Exception as e:
    print_text.print_error("\tInstallation failed. Error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

