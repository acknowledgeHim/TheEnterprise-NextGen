import hmac
import sys
import hashlib
import base64
import getpass
from common import print_text
from common import database_object
from enterprise_conf import HASH_KEY

def verify_key(HASH, HASH_KEY, user_entered_key):
    """
    Verifies user inputed Encryption Key is the correct one
    Returns bool True if user_entered_key was correct and False if not

    Arguments:
        user_entered_key -- encryption key specified by the user
    """
    user_hashed_key = base64.b64encode(hmac.new(HASH_KEY, msg=user_entered_key, digestmod=hashlib.sha256).digest()).decode()
    if user_hashed_key == HASH:
        return True
    return False

def enter_encrypt_key(msg=None):
    """
    Allows user to type in encryption key.
    Calls verify_key to make sure correct encryption key entered if not re-asks for it.
    Returns encryption key.
    """

    if msg != None:
        print_text.print_bold(msg)
    correct_key_entered = False
    while not correct_key_entered:
        username = input("Please enter the password")
        passwd = getpass.getpass()

        correct_key_entered = database_object.verify_key_connect_to_emailevent_db(username, passwd)

    if correct_key_entered:
        return passwd
    else:
        return ""

def get_hash_string(hash_fields, field_values):
    """
    Takes List of fields to hash and grabs user input-ed values for each field to concatonate together.
    Returns concatonated hash_string as new entry in field_values dictionary.

    Attributes:
        hash_fields -- list of db table names that will be hashed together
        field_values -- Dict: key is name db table name, value is the value to add
    """
    try:
        hash_fields_concat = ''
        if hash_fields is not None and len(hash_fields) > 0:
            for hash_field in hash_fields:
                if hash_field in field_values:
                    hash_fields_concat = hash_fields_concat + "~~" + str(field_values[hash_field]).lstrip().rstrip()
                elif "_" in hash_field and hash_field[:hash_field.find("_")] in field_values:
                    hash_fields_concat = hash_fields_concat + "~~" + str(field_values[hash_field[:hash_field.find("_")]]).lstrip().rstrip()
                else:
                    print_text.print_error("\tMissing values (" + hash_field + ") necessary to create the hash value for the database.")
                    return field_values
            field_values['hashval'] = hash_string(hash_fields_concat)

        return field_values
    except Exception as e:
        print("encryption except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}


def hash_string(hash_string):
    return base64.b64encode(
                hmac.new(HASH_KEY.encode('utf-8'), msg=hash_string.encode('utf-8'), digestmod=hashlib.sha256).digest()).decode()