import os
import secrets

# Auto Start Celery (means it will be in the background and you will not see outputed data)
# TE_AUTO_START_CELERY overrides this - Docker defaults it to true since there's no separate
# interactive terminal to run "celery worker" in by hand inside a container.
AUTO_START_CELERY = os.environ.get("TE_AUTO_START_CELERY", "false").lower() == "true" # False / True
CELERY_CONCURRENCY = 8

# Auto Start TheEnterprise Flask (Web GUI) - only useful when starting enterprise from the command line
AUTO_START_GUI = False # False / True

#Base absolute path where client/engagements will be saved.
OUTPUT_PATH = '/usr/local/clients/'

# Optional deterministic first-run admin account (used by install.py's bootstrap). If unset,
# install.py falls back to its existing random-Star-Trek-username/random-password generation.
# Mainly useful for Docker, where you want a known login rather than digging a random one out
# of container logs.
ADMIN_USERNAME = os.environ.get("TE_ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("TE_ADMIN_PASSWORD")

# Linux group that created folders will be assigned to
LINUX_GROUP = 'staff'

# Flask Config
# TE_FLASK_KEY should be set in the environment for any non-throwaway install; if unset,
# a fresh random key is generated on each start (fine for local dev, but sessions won't
# survive a restart).
FLASK_KEY = os.environ.get("TE_FLASK_KEY") or secrets.token_hex(20)
FLASK_PORT = 1820
FLASK_FILE_UPLOAD_LIMIT = 64 # in MB, limits file size for uploaded files
DEVICE_IP = '0.0.0.0' # IP Address of this device (where TheEnterprise is running) so you can connect using your browser

# PENTEST DIR
PENTEST_DIR = "/pentest/"

# Path to python 2.7 version (some external tools use 2.7)
# Note: every call site (tools/attack/scapy_setup.py, tools/scan/create_hosts_file.py,
# tools/credential/responder_hashcat_setup.py, tools/recon/datasploit_setup.py,
# tools/credential/secretsdump_setup.py) imports this as PYTHONv2_PATH (lowercase v) - keeping
# the name in that case here rather than PYTHONV2_PATH, which no code actually imported.
PYTHONv2_PATH = "/usr/bin/python2.7"

# GOLANG path
GOLANG_PATH = PENTEST_DIR + "golang/"

INTERFACE_NAME = ""     # Used by reponder & scapy & others (unless this is on a server w/ static IP, don't set here)
YOUR_IP_ADDRESS = ""    # Used by responder & scapy & email filter testing & others (unless this is on a server w/ static IP, don't set here)
YOUR_DOMAIN = ""

# Email notification variables
EMAIL_ADDRESS = "" # This is the email address that your emails will originate from
EMAIL_SERVER = "" # This is the email server to send out email updates, etc through (NOT filter, relay, spoofing, or phishing tests)
SMTP_EHLO_SERVER = ""

# API Keys
SHODAN_API_KEY = ""
BING_API_KEY = ""
GOOGLE_CSE_API_KEY = ""

# API KEYS USED BY DATASPLOIT
GITHUB_ACCESS_TOKEN = ""
BUILTWITH_API = ""
CENSYSIO_ID = ""
CENSYSIO_SECRET = ""
FACEBOOK_ACCESS_TOKEN = ""
FLICKR_API = ""
GOOGLE_API = ""
GOOGLE_CSE_CX = ""
HASHES_API = ""
IPINFODB_API = ""
JIGSAW_API = ""
JIGSAW_PASSWORD = ""
JIGSAW_USERNAME = ""
LINKEDIN_API = ""
LINKEDIN_SECRET = ""
PWNDEDLIST_API = ""
PWNDEDLIST_IV = ""
PWNDELIST_SECRET = ""
SPYONWEB_ACCESS_TOKEN = ""
TWITTER_CONSUMER_KEY = ""
TWITTER_CONSUMER_SECRET = ""
TWITTER_ACCESS_TOKEN = ""
TWITTER_ACCESS_TOKEN_SECRET = ""
ZOOMEYEUSER = ""
ZOOMEYPASS = ""
CLEARBIT_API = ""
EMAILHUNTER = ""
JSONWHOIS = ""
INSTAGRAM_TOKEN = ""
INSTAGRAM_CLIENT_ID = ""
INSTAGRAM_CLIENT_SECRET = ""
FULLCONTACT_API = ""
MAILBOXLAYER_API = ""
VIRUSTOTAL_PUBLIC_API = ""
GITHUB_TRAVIS_KEY = ""

# Datasploit python script path
DATASPLOIT_PATH = "/pentest/datasploit/"

# Metasploit MSFRPC configuration
# Both are set here and used to start the local msfrpcd daemon (see MSFRCP_STARTUP below),
# so a fresh random password each run is fine unless you need it stable across restarts.
MSFRPC_USER = os.environ.get("TE_MSFRPC_USER", "msf")
MSFRPC_PASSWORD = os.environ.get("TE_MSFRPC_PASSWORD") or secrets.token_urlsafe(16)
MSFRPC_URL = "https://127.0.0.1:" # start this up locally by running ./msfrpcd -a 127.0.0.1 -U le_verite -P est_levangile from metasploit directory
MSFRPC_PORT = 55553
MSFRCP_STARTUP = "msfrpcd -a " + MSFRPC_URL[MSFRPC_URL.find("://") + 3:].replace(":", "") + " -U " + \
                 MSFRPC_USER + " -P " + MSFRPC_PASSWORD + " -p " + str(MSFRPC_PORT)

# Enter FULL path to userlist and passlist (newline separated) otherwise will use default below
MSFRPC_USERLIST = os.path.dirname(os.path.realpath(__file__)) + "/tools/attack/userlist.txt"
MSFRPC_WORDLIST = os.path.dirname(os.path.realpath(__file__)) + "/tools/attack/pass.lst"

DEFAULT_USERLIST = MSFRPC_USERLIST
DEFAULT_WORDLIST = MSFRPC_WORDLIST

# -------------------- CREDENTIALS GLOBAL VARIABLES --------------
# Hashcat configuration
HASHCAT_PATH = "hashcat"
HASHCAT_WORDLIST = "/pentest/wordlist/Dont_Mangle_Me.lst"
HASHCAT_MANGLE = ""

# John configuration
JOHN_PATH = "john"
JOHN_WORDLIST = "/pentest/wordlist/rockyou.txt"
JOHN_RULE_MANGLE = ""

# Used to authenticate to the locally-started ZAP daemon for this process; safe to
# regenerate per-run unless TE_ZAP_API_KEY is set for a stable value.
ZAP_API_KEY = os.environ.get("TE_ZAP_API_KEY") or secrets.token_urlsafe(32)
