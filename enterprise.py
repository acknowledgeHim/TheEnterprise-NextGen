import sys
import os
import subprocess
import time
import shlex
from random import randint
from common import print_text
from common import common
from common import system_process
from common import copy_keys, network
from flask_files import flask_user
from enterprise_user_conf import GOLANG_PATH
from setup import current_location
from common.menu_class import MenuClass
from setup.client_engagement import ClientEngagement
from setup.profile import MyProfile
from enterprise_user_conf import MSFRCP_STARTUP, AUTO_START_CELERY, AUTO_START_GUI, CELERY_CONCURRENCY, ZAP_API_KEY, PENTEST_DIR

try:
    from enterprise_conf import OUTPUT_PATH
except Exception as e:
    print_text.print_error("\t The TheEnterprise Configuration File, enterprise_conf.py, is missing from the directory"
                           " or is corrupted.  Please re-acquire TheEnterprise from Github. ")
    sys.exit()


def main():
    """
    Main function, setups TheEnterprise.
    Starts by getting encryption key from user.
    Grabs or creates user enterprise profile.
    Retrieves user selected client/engagement (could be newly created one)
    Starts the main menu of pat!
    """

    # Setup Readline
    try:
        os.system("export PATH=$PATH:/" + GOLANG_PATH + "/bin")

        import readline
        import rlcompleter
        completer = rlcompleter.Completer()
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
        readline.parse_and_bind('set show-all-if-ambiguous on')
        readline.parse_and_bind('"\C-r": reverse-search-history')
        readline.parse_and_bind('"\C-s": forward-search-history')
        readline.get_completer_delims()
        readline.set_completer_delims('\t\n')
    except:
        pass

    print_text.print_msg("\n\nPenetration testing, the final frontier.  These are the engagements of The Enterprise.  Its never-ending mission: "
          "to explore strange new vulnerabilities, to seek out new exploits and new hacking methodologies, to boldly "
          "go where no one has gone before.\n")

    random_pic = randint(1,4)
    with open('documents/enterprise' + str(random_pic) + '.txt') as pic:
        print(pic.read() + "\n          Pentest Automation\n")

    """
    print("                  xxxXRRRMMMMMMMMMMMMMMMxxx,.\n"\
"              xXXRRRRRXXXVVXVVXXXXXXXRRRRRMMMRx,\n"\
"            xXRRXRVVVVVVVVVVVVVVVXXXXXRXXRRRMMMMMRx.\n"\
"          xXRXXXVVVVVVVVVVVVVVVVXXXXVXXXXXXRRRRRMMMMMxx.\n"\
"        xXRRXXVVVVVttVtVVVVVVVVVtVXVVVVXXXXXRRRRRRRMMMMMXx\n"\
"      xXXRXXVVVVVtVttttttVtttttttttVXXXVXXXRXXRRRRRRRMMMMMMXx\n"\
"     XRXRXVXXVVVVttVtttVttVttttttVVVVXXXXXXXXXRRRRRRRMMMMMMMMVx\n"\
"    XRXXRXVXXVVVVtVtttttVtttttittVVVXXVXVXXXRXRRRRRMRRMMMMMMMMMX,\n"\
"   XRRRMRXRXXXVVVXVVtttittttttttttVVVVXXVXXXXXXRRRRRMRMMMMMMMMMMM,\n"\
"   XXXRRRRRXXXXXXVVtttttttttttttttttVtVXVXXXXXXXRRRRRMMMMMMMMMMMMM,\n"\
"   XXXXRXRXRXXVXXVtVtVVttttttttttttVtttVXXXXXXXRRRRRMMMMMMMMMMMMMMMR\n"\
"   VVXXXVRVVXVVXVVVtttititiitttttttttttVVXXXXXXRRRRRMRMMMMMMMMMMMMMMV\n"\
"   VttVVVXRXVVXtVVVtttii|iiiiiiittttttttitXXXRRRRRRRRRRMMMMMMMMMMMMMM\n"\
"   tiRVVXRVXVVVVVit|ii||iii|||||iiiiiitiitXXXXXXXXRRRRRRMMMMMMMMMMMMM\n"\
"    +iVtXVttiiii|ii|+i+|||||i||||||||itiiitVXXVXXXRRRRRRRRMMMMMMRMMMX\n"\
"    `+itV|++|tttt|i|+||=+i|i|iiii|iiiiiiiitiVtti+++++|itttRRRRRMVXVit\n"\
"     +iXV+iVt+,tVit|+=i|||||iiiiitiiiiiiii|+||itttti+=++|+iVXVRV:,|t\n"\
"     +iXtiXRXXi+Vt|i||+|++itititttttttti|iiiiitVt:.:+++|+++iXRMMXXMR\n"\
"     :iRtiXtiV||iVVt||||++ttittttttttttttttXXVXXRXRXXXtittt|iXRMMXRM\n"\
"      :|t|iVtXV+=+Xtti+|++itiiititittttVttXXXXXXXRRRXVtVVtttttRRMMMM|\n"\
"        +iiiitttt||i+++||+++|iiiiiiiiitVVVXXRXXXRRRRMXVVVVttVVVXRMMMV\n"\
"         :itti|iVttt|+|++|++|||iiiiiiiittVVXRRRMMMMMMRVtitittiVXRRMMMV\n"\
"           `i|iitVtXt+=||++++|++++|||+++iiiVVXVRXRRRV+=|tttttttiRRRMMM|\n"\
"             i+++|+==++++++++++++++|||||||||itVVVViitt|+,,+,,=,+|itVX'\n"\
"              |+++++.,||+|++++=+++++++|+|||||iitt||i||ii||||||itXt|\n"\
"              t||+++,.=i+|+||+++++++++++++|i|ittiiii|iiitttttXVXRX|\n"\
"              :||+++++.+++++++++|++|++++++|||iii||+:,:.-+:+|iViVXV\n"\
"              iii||+++=.,+=,=,==++++++++++|||itttt|itiittXRXXXitV'\n"\
"             ;tttii||++,.,,,.,,,,,=++++++++++|iittti|iiiiVXXXXXXV\n"\
"            tVtttiii||++++=,,.  . ,,,=+++++++|itiiiiiii||||itttVt\n"\
"           tVVttiiiii||||++++==,. ..,.,+++=++iiiiiitttttVVXXRRXXV\n"\
"        ..ttVVttitttii||i|||||+|+=,.    .,,,,==+iittVVVXRRMXRRRV\n"\
"...'''ittitttttitVttttiiiiii|ii|++++=+=..... ,.,,||+itiVVXXVXV\n"\
"      ,|iitiiitttttttiiiii||ii||||||||+++++,.i|itVt+,,=,==.........\n"\
"        ,|itiiiVtVtiii||iiiiii|||||||++||||tt|VXXRX|  ....  ..     ' ' '.\n"\
"          ,,i|ii||i||+|i|i|iiiiiiii||||ittRVVXRXRMX+, .  ...   .         ,\n"\
"    .       .,+|++|||||ii|i|iiiitttVVttXVVXVXRRRRXt+. .....  . .       ,. .\n"\
"  . .          ,,++|||||||i|iiitVVVXXXXVXXVXXRRRV+=,.....  ....  ..       ..\n"\
"                  .,,++|||i|iittXXXXRMViRXXXXRVt+=, ..    ...... .        ..\n"\
"                   ,XX+.=+++iitVVXXXRXVtXXVRRV++=,..... .,, .              .\n"\
"            ....       +XX+|i,,||tXRRRXVXti|+++,,. .,,. . . .. .      . ....\n"\
"  . .          .      ..  ..........++,,..,...,.... ..             .. ...\n"\
"                 The Enterprise: The Pentest Automation Toolkit \n"\
"                                  'Make It So'\n\n")
    """
    encrypt_key = ""#encryption.enter_encrypt_key()

    with MyProfile(True) as my_profile:
        profile_dictionary = my_profile.profile_questions()
    only_owner = profile_dictionary["only_owner"]
    newer_than = profile_dictionary["newer_than"]
    profile_email = profile_dictionary["profile_email"]
    auto_view_flask_user = profile_dictionary["auto_view_flask_user"]

    # Create Flask User
    if auto_view_flask_user or auto_view_flask_user == "True":
        flask_user.view_flask_user(None, "WebApp Users", [], "", False)

    tester = common.get_tester()

    # make sure golang is in PATH
    os.system('export PATH=$PATH:/pentest/golang/bin')

    full_client_engagement_path = ''
    db = None
    completed_setup = False
    with ClientEngagement(OUTPUT_PATH, tester, only_owner, newer_than, encrypt_key) as ce:
        full_client_engagement_path, db = ce.which_client_engagement()

    # Check if celery is running for selected client, if not start it
    client_name = common.format_target(full_client_engagement_path.rstrip("/"))
    if system_process.process_with_args_is_running("celery", client_name):
        print_text.print_msg("Celery queue running for this client already.  So not trying to start it manually.  If "
                             "you want/need to start it manually do so by type in another console: celery worker "
                             "--loglevel=INFO -Q " + client_name + " -n " + client_name + "--app=common.jobs.celery_app"\
                             ".  Read the TheEnterprise user guide for detailed instructions.")
    elif AUTO_START_CELERY and not system_process.process_with_args_is_running("celery", client_name):
        subprocess.Popen(shlex.split("celery worker -Q " + client_name + " -n " + client_name + " --app=common.jobs.celery_app  --concurrency " + str(CELERY_CONCURRENCY)))
        print_text.print_msg("Celery was automatically started in the background for this engagement so you will not see"
                             " tool output on the console.  To start celery manually, please set AUTO_START_CELERY in "
                             "enterprise_user_conf.py to False.")
    else:
        curr_directory = os.path.dirname(os.path.realpath(__file__))
        print_text.print_bold("Before continuing, please run celery from another terminal console or screen by doing "
                              "the following: \n\t1. Open new console terminal or screen. "
                              "\n\t2. cd " + curr_directory +
                              "\n\t3. source ../bin/activate"
                              "\n\t4. celery worker -Q " + client_name + " -n " + client_name + " --app=common.jobs.celery_app --loglevel=INFO --concurrency " + str(CELERY_CONCURRENCY) +\
                              "\n\t**TheEnterprise will not run for this client until you have started celery using the above 4 steps.") #+ " -n " + client_name +
        while not system_process.process_with_args_is_running("celery", client_name):
            time.sleep(5)

    if full_client_engagement_path == "" or db is None:
        print_text.print_error("\tUnable to verify the client/engagement. If you were trying to create"
               " a new client/engagement please verify folder permissions of " + OUTPUT_PATH + " and try again!.")
        sys.exit()

    # Reset Information.current_location - used to determine what to test
    current_location.reset_current_testing_location(db)

    flask_running, flask_processes = system_process.is_running("enterprise-flask.py")
    if not flask_running:
        try:
            if AUTO_START_GUI:
                print_text.print_msg("Starting enterprise-flask ... the web GUI for TheEnterprise!")
                subprocess.Popen(shlex.split("python enterprise-flask.py"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print_text.print_msg("If you want to start the TheEnterprise's web GUI, simply run python "
                                     "enterprise-flask.py instead of or in addition to enterprise.py OR set variable "
                                     "AUTO_START_GUI in enterprise_user_conf.py to True to automatically start it!")
        except Exception as e:
            pass
            #print_text.print_error("enterprise except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    else:
        print_text.print_msg("TheEnterprise Flask (the web GUI for TheEnterprise) was already running with the configuration specified in enterprise_user_conf.py.")


    msf_running, msf_processes = system_process.is_running("msfrpcd")
    if not msf_running:
        try:
            print_text.print_msg("Starting msfrpc ... Metasploit's RPC daemon, allowing you to use Metasploit within "
                                 "TheEnterprise!\nKilling this instance of TheEnterprise will kill the MSFRPCD.  "
                                 "Manually starting this will keep msfprcd running even when this instance of "
                                 "TheEnterprise is exited. \nTo manually start msfrpcd follow these steps:"
                                 "\n\t1. Open new console terminal or screen \n\t2. " + MSFRCP_STARTUP)
            subprocess.Popen(shlex.split(MSFRCP_STARTUP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print_text.print_error("enterprise except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    zap_running, zap_processes = system_process.is_running("zap")
    if not zap_running:
        try:
            ZAP_STARTUP = PENTEST_DIR + "/zap/zap.sh -daemon -config api.key=" + ZAP_API_KEY
            print_text.print_msg("Starting ZAP ... OWASP ZAP daemon, allowing you to use ZAP within "
                                 "TheEnterprise!\nKilling this instance of TheEnterprise will kill the ZAP.  "
                                 "Manually starting this will keep zap running even when this instance of "
                                 "TheEnterprise is exited. \nTo manually start zap follow these steps:"
                                 "\n\t1. Open new console terminal or screen \n\t2. " + ZAP_STARTUP)
            subprocess.Popen(shlex.split(ZAP_STARTUP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print_text.print_error("enterprise except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            ## Start zap in daemon (headless) mode and configure the api key on startup
            #os.system(PENTEST_DIR + "/zap/zap.sh --config api.key=" + zap_api_key + " -daemon")

    # Make sure Scope Creep is running
    scope_creep_running = network.nc_verify('localhost', '3007')
    if not scope_creep_running:
        try:
            SCOPE_CREEP_STARTUP = "node " + PENTEST_DIR + "/scope_creep/index.js"
            print_text.print_msg(
                "Starting Forrest's Scope Creep on port 3007.  Scope Creep normally runs on port "
                "3000 but TE's version runs on port 3007 which is modified in the index.js file.")
            subprocess.Popen(shlex.split(SCOPE_CREEP_STARTUP), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print_text.print_error("enterprise except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    # Copy enterprise_conf.py KEYS
    copy_keys.copy_keys()


    with MenuClass(db, "Main", [0], full_client_engagement_path, True) as create_menu:
        create_menu.select_option()

if __name__ == "__main__":
    main()
