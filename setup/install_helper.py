import hmac
import sys
import hashlib
import base64
from common import print_text
from common.database_object import OurCoolDBObject
from enterprise_conf import EMAIL_EVENT_DB, HASH_KEY


def add_default_email_events(user_entered_key, EMAIL_EVENTS):
    EMAIL_EVENTS_HASHED = []
    for event in EMAIL_EVENTS:
        event['hashval'] = base64.b64encode(hmac.new(HASH_KEY.encode('utf-8'), msg=event['event'].encode('utf-8') + event['start_or_end'].encode('utf-8'), digestmod=hashlib.sha256).digest()).decode()
        EMAIL_EVENTS_HASHED.append(event)

    with OurCoolDBObject(EMAIL_EVENT_DB, 'common.email_db_model') as db:
        number_rows_added = db.add_multiple("EmailEvent", EMAIL_EVENTS_HASHED)
    return number_rows_added

def add_email_event(user_entered_key, add_values_dictionary, print_message=True):
    """
            Same as add function although it returns the hashvalue of the newly created row.

            :param db_table_name: name of the DB table
            :param add_values_dictionary: key:value dictionary where the key is the name of the column in the DB to update.
            :return: hash value for the newly added row
            """
    try:
        with OurCoolDBObject(EMAIL_EVENT_DB, 'common.email_db_model') as interaction:
            db_table_name = "EmailEvent"
            success, hashval = interaction.get_or_create(db_table_name, add_values_dictionary)

            return hashval
    except Exception as e:
        print_text.print_error(
            "install_helper except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def add_flaskuser(add_values_dictionary):
    try:
        with OurCoolDBObject(EMAIL_EVENT_DB, 'common.email_db_model') as interaction:
            success, hashval = interaction.create_or_update("FlaskUser", add_values_dictionary)

            print_text.print_msg("Successfully created user.  This user is only used for the Web App view (enterprise-flask.py).")
            return hashval
    except Exception as e:
        print_text.print_error(
            "install_helper except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))