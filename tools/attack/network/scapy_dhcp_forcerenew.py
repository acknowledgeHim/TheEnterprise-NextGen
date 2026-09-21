import random
import sys
import json
from scapy import *
from common import print_text


def dhcp_forcerenew(command, scope_id, location_id, db_object, log_id, passed_args):
    """ DHCP FORCERENEW """
    try:
        command = command.replace('"', '')
        your_ip_address = command[command.find(";") + 1:]
        passed_values = json.loads(passed_args)

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']

        output_file = output_file_path + "dhcp_forcerenew__" + str(log_id) + ".txt"

        try:
            fam, hw = get_if_raw_hwaddr(passed_values['interface_name'])
            ans, unans = srp(IP(src=passed_values['dhcp_server'], dst=passed_values['ip_to_target'])/
                             UDP(sport=67, dport=68)/
                             BOOTP(chaddr=hw, ciaddr=passed_values['your_ip_address'], xid=random.randint(0, 0xFFFFFFFF))/
                             DHCP(options=[("message-type", "forcerenew"), ("server_id", passed_values['dhcp_server']), 'end']),
                         iface=passed_values['interface_name'], timeout=2)
            #packet = Ether(src=)
            #send(IP(src=passed_values['dhcp_server'], dst=passed_values['ip_to_target']) /
            #     UDP(sport=67, dport=68) /
            #     BOOTP(chaddr=hw, ciaddr=passed_values['your_ip_address'], xid=random.randint(0, 0xFFFFFFFF)) /
            #     DHCP(options=[("message-type", "forcerenew"), ("server_id", passed_values['dhcp_server']), 'end'])

            msg = "Successfully send FORCERENEW packet to " + passed_values['ip_to_target']
        except Exception as e:
            msg = "Failed.  Error: " + str(e)

        with open(output_file, "w") as ofp:
            ofp.write(str(scope_id) + "\t" + passed_values['dhcp_server'] + "\t" + passed_values['ip_to_target'] + "\t" + msg + "\n")

        return True
    except Exception as e:
        print_text.print_error("dns_query except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return False
