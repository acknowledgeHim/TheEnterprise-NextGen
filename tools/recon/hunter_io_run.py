import yaml
import json
import sys
from pyhunter import PyHunter
from common import print_text

def hunter_io(command, scope_id, location_id, db_object, log_id, hunter_args):
    """ Hunter IO query. """
    try:
        hunter_values = json.loads(hunter_args)
        hunter_io_key = hunter_values['hunter_io_key']

        scope_ips = db_object.scope_ips()
        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        domain = command[command.find(";")+1:]
        log_info = db_object.log_record_by_id(log_id)

        output_file_path = log_info['output_filepath']
        output_file = output_file_path + "hunter_io__" + str(log_id) + "__" + domain + ".json"
        source = "hunter_io"

        hunter = PyHunter(hunter_io_key)
        data = hunter.domain_search(domain)
        print("25 tools/recon/hunter_io data: " + str(data))
        with open(output_file, "w") as ofp:
            ofp.write(json.dumps(data))

        return True
    except Exception as e:
        print_text.print_error("hunter_io except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return False


def hunter_io_company(command, scope_id, location_id, db_object, log_id, hunter_args):
    """ Hunter IO query. """
    try:
        hunter_values = json.loads(hunter_args)
        hunter_io_key = hunter_values['hunter_io_key']
        company_name = hunter_values['company_name']
        if company_name.strip() == "":
            einfo = db_object.view("Engagement", None, ['id'], [1], [True])
            company_name = einfo[0]['client_name']

        scope_ips = db_object.scope_ips()
        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        domain = command[command.find(";")+1:]
        log_info = db_object.log_record_by_id(log_id)

        output_file_path = log_info['output_filepath']
        output_file = output_file_path + "hunter_io_company__" + str(log_id) + "__" + domain + ".json"
        source = "hunter_io_company"

        hunter = PyHunter(hunter_io_key)
        data = hunter.domain_search(company=company_name)

        with open(output_file, "w") as ofp:
            ofp.write(json.dumps(data))

        return True
    except Exception as e:
        print_text.print_error("hunter_io except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return False