import sys
import shodan
import json
from common import print_text, common, network

def shodan_search(command, scope_id, location_id, db_object, log_id, passed_args):
    """ Shodan search. """
    try:
        passed_values = json.loads(passed_args)
        command = command.replace('"', '')
        domain = command[command.find(";")+1:]

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']

        scope_ips = db_object.scope_ips()

        api = shodan.Shodan(passed_values['shodan_api_key'])

        results = []
        try:
            results = api.search(domain)
            for result in results['matches']:
                if 'ip_str' in result and result['ip_str'] != "" and 'port' in result:
                    with open(output_file_path + "shodan__" + str(log_id) + "__" + domain + ".txt", "w") as ofp:
                        description = ""
                        if "http" in result:
                            if 'server' in result['http']:
                                description = " - " + str(result['http']['server'])
                        info = "Sub domain is not within the Scope IP ranges."
                        for scope_ip in scope_ips:
                            if network.check_in_network(scope_ip['entry'], result['ip_str']):
                                info = "Sub domain's resolved IP is within Scope: " + scope_ip + "."
                                break
                        description = "Port: " + str(result['port']) + description + ". " + info
                        if result['hostnames'] is not None and len(result['hostnames']) > 0:
                            hostnames = ' '.join(result['hostnames'])
                        else:
                            hostnames = result['ip_str']
                        os = ""
                        if result['os'] is not None:
                            os = result['os']

                        ofp.write(str(scope_id) + "\tshodan\t" + hostnames + "\t" + os + "\t"
                                  + result['ip_str'] + "\t" + description + "\t\tshodan\n")
        except Exception as e:
            print_text.print_error("shodan run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    except Exception as e:
        print_text.print_error("shodan run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
