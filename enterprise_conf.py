import os

from enterprise_user_conf import *

# ----------------------------------------------------------------------------------------------------------------------
# DO NOT MODIFY ITEMS BELOW HERE -------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

#Email Event Database (pre-populated with default email events)
EMAIL_EVENT_DB = 'setup/email_event.db'

# Regex for IPv4 or IPv6
IP_REGEX = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'

# Regex for email addresses
EMAIL_REGEX = r'[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}'

# RabbitMQ information, this is the default information
RABBITMQ_HOST = os.environ.get("TE_RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.environ.get("TE_RABBITMQ_PORT", 5672))
RABBITMQ_USER = os.environ.get("TE_RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("TE_RABBITMQ_PASS", "guest")

# Hash Key - changing this will mess up your database.  You set this up originally when installing The Enterprise.
# Set TE_HASH_KEY in the environment for any non-throwaway install - the fallback below is a
# known, documented default, not a private secret.
HASH_KEY = os.environ.get("TE_HASH_KEY", "PassPhr@s#")