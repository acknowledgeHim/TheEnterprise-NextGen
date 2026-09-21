import json
import sys
import os
from crtsh import crtshAPI
from common import print_text

def crt_sh(command, scope_id, location_id, db_object, log_id):#, passed_args):
    """ crt sh """
    try:
        #passed_values = json.loads(passed_args)
        command = command.replace('"', '')
        domain = command[command.find(";")+1:]
        log_info = db_object.log_record_by_id(log_id)

        output_file_path = log_info['output_filepath']
        output_file = output_file_path + "crt_sh__" + str(log_id) + "__" + domain + ".json"
        source = "crt_sh"
        data = crtshAPI().search(domain)
        json_results = {}
        json_results['data'] = data[0]
        with open(output_file, "w") as ofp:
            ofp.write(json.dumps(json_results))

        return True
    except Exception as e:
        print_text.print_error("crt_sh except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return False
