import string, sys
import json
from scapy.all import *
from common import print_text, network

def arp_ping(command, scope_id, location_id, db_object, log_id, passed_args):
    """ ARP Ping """
    try:
        command = command.replace('"', '')
        your_ip_address = command[command.find(";") + 1:]
        passed_values = json.loads(passed_args)

        # Find scope that your IP is part of
        scope_entry = ""
        scope_ips = db_object.scope_ips()
        for scope in scope_ips:
            if network.find_networks_ip_is_in(scope['entry'], your_ip_address) is True:
                scope_id = scope['id']
                scope_entry = scope['entry']

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']

        output_file = output_file_path + "arp_ping__" + str(log_id) + ".txt"

        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=scope_entry), iface=passed_values['interface_name'], timeout=2)
            with open(output_file, "w") as ofp:
                for s,r in ans:
                    ofp.write(str(scope_id) + "\t" + r.psrc + "\t" + r.src + "\n")
                    print_text.print_msg(r.src + " is the MAC address for host " + r.psrc)
            return "Success. ARP broadcast sent out."
        except Exception as e:
            print("ARP ping failed, error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return "Failed. " + str(e)
    except Exception as e:
        print("ARP ping failed, error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return "Failed. " + str(e)