import sys
import dns.zone
import dns.query
import dns.exception
from common import print_text, common, dns_functions, network


def zonetransfer(command, scope_id, location_id, db_object, log_id):
    """ DNS records. """
    try:
        scope_ips = db_object.scope_ips()
        command = command.replace('"', '')
        domain = command[command.find(";")+1:]

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']

        with open(output_file_path + "dns_zonetransfer__" + str(log_id) + "__" + domain + ".txt", "w") as ofp:
            # DNS lookups
            associated_info, information, description, organization, nameservers = dns_functions.domain_information(domain, True)

            if associated_info != "":
                # also check for DNS records that have nsX.
                dns_records = db_object.view("Recon", ['record', 'associated_info'], ['recon_type', 'record'], ['dns', 'ns'], equal=False)
                if dns_records is not None:
                    for dr in dns_records:
                        print("26 zonetransfer run dr: " + str(dr))
                        if common.regex_exist_in_entry(dr['record'], r'ns[\d].', False) != "" and network.valid_ip(dr['associated_info']):
                            print("28 zonetransfer run dr['record']: " + str(dr['record']))
                            nameservers.append(dr['associated_info'])
                    print("30 zonetransfer run nameservers: " + str(nameservers))
                    afrx_check(ofp, scope_id, domain, nameservers, scope_ips)
        return True
    except Exception as e:
        print_text.print_error("zonetransfer_run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return False

def afrx_check(ofp, scope_id, domain, nameservers, scope_ips):
    for server in nameservers:
        server_ip = None
        records = ""
        if not network.valid_ip(server):
            server = str(server).rstrip(".")
            try:
                server_ip, additional = dns_functions.grab_dns_record(server, True)
            except Exception as e:
                if "Connection timed out" not in str(e):
                    print("zonetransfer_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        else:
            server_ip = server

        #in_scope = False
        #for scope_ip_entry in scope_ips:
        #    if network.check_in_network(scope_ip_entry['entry'], server_ip):
        #        in_scope = True
        #        break
        #if in_scope:
        if server_ip is not None:
            try:
                print("52 zonetransfer run server_ip: " + str(server_ip))
                zone = dns.zone.from_xfr(dns.query.xfr(server_ip, domain))
                records = sorted(zone)
                zone_transfer = "Zone Transfer: Success"
            except dns.exception.DNSException as socket_error:
                zone_transfer = "Zone Transfer: Failed"
        #else:
        #    zone_transfer = "Zone Transfer: Not attempted as name server is not within scope."

            ofp.write(str(scope_id) + "\tAFRX\t" + server + "\t" + zone_transfer + "\t" + server_ip + "\t" + str
                (records) + "\t" + additional + "\tdns zonetransfer\n")

