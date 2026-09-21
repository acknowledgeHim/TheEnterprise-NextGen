import sys
from common import print_text

def parse_file(command, scope_id, location_id, db_object, log_id):
    """ File parsing"""
    try:
        print_text.print_msg("Now time to kick off the parsing!")

    except Exception as e:
        print_text.print_error("file_parser except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
