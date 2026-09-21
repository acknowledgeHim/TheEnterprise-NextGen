import sys
import time
import shodan
import json
import ipaddress
from common import print_text, common, network

def shodan_host_search(command, scope_id, location_id, db_object, log_id, passed_args):
    """ Shodan host search. """
    try:
        passed_values = json.loads(passed_args)

        command = command.replace('"', '')
        entry = command[command.find(";")+1:]
        entries = [entry]

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']

        scope_ips = db_object.scope_ips()

        api = shodan.Shodan(passed_values['shodan_api_key'])

        if "/" in entry and network.valid_ip(entry[:entry.find("/")]):
            entries = []
            # find all ips in network cidr
            for ip in network.return_all_ips_from_network_cidr(entry):
                entries.append(str(ip))

        for entry in entries:
            try:
                is_ip = False
                if network.valid_ip(entry):
                    is_ip = True

                    host = api.host(entry)

                    ip = ""
                    if "ip_str" in host:
                        ip = host['ip_str']
                    with open(output_file_path + "shodan_host__" + str(log_id) + "__" + entry + ".txt", "w") as ofp:
                        if ip == "":
                            ip = ipaddress.IPv4Address(host['ip'])

                        # General info
                        title = ""
                        org = ""
                        os = ""
                        hostname = ""
                        if host is not None and 'ip' in host and host['ip'] != "":
                            if "org" in host:
                                org = host.get('org', '')
                            if "os" in host:
                                os = host.get('os', '')
                            if "title" in host:
                                title = host.get('title', '')
                            if "ssl" in host and "subject" in host['ssl'] and "CN" in host['ssl']['subject']:
                                hostname = host['ssl']['subject']['CN']
                            if os is None:
                                os = ""
                            if org is None:
                                org = ""
                            if title is None:
                                title = ""
                            if hostname is None:
                                hostname = ""
                            ofp.write(str(scope_id) + "\tshodan host\t" + entry + "\t" + ip + "\t" +hostname + "\t" + os + "\t" + title + "\t\tASSET\n")
                            if org != "":
                                ofp.write(str(scope_id) + "\tshodan host\t" + entry + "\t" + org + "\t\tSCOPE\n")

                        # Open Port
                        if "port" in host and host['port'] is not None:# and ("product" in host or "server" in host) and host['port'] is not None:
                            description = None
                            if "server" in host:
                                description = host['server']
                            elif "product" in host:
                                description = host['product']
                            if description is None:
                                description = ""
                            print("77 shodan host open_port: " + str(host['port']))
                            ofp.write(str(scope_id) + "\tshodan host\t" + entry + "\t" + ip + "\t" + host['port'] + "\t"
                                      + description + "\t\tPORT\n")

                        # Domains
                        if "domains" in host:
                            domains = host['domains']
                            for domain in domains:
                                if domain is not None:
                                    print("86 shodan run domain: " + str(domain))
                                    ofp.write(str(scope_id) + "\tshodan host\t" + entry + "\t" + domain + "\t\tDNS-Domain\n")

                        # Hostnames
                        if "domains" in host:
                            hostnames = host['hostnames']
                            for hostname in hostnames:
                                if hostname is not None:
                                    print("94 shodan run hostname: " + str(hostname))
                                    ofp.write(str(scope_id) + "\tshodan host\t" + entry + "\t" + hostname + "\t\tDNS-Hostname\n")

                        for item in host['data']:
                            if "vulns" in item:
                                vulns = item['vulns']
                                for cvee, vuln in vulns.items():
                                    try:
                                        verified = vuln['verified']
                                        references = ", ".join(vuln['references'])
                                        cvss = vuln['cvss']
                                        summary = vuln['summary']
                                        if verified is not None and references is not None and cvss is not None \
                                                and summary is not None:
                                            ofp.write(str(scope_id) + "\tshodan host\t" + entry + "\t" + ip + "\t" +
                                                      cvee + "\t" + verified + "\t" + references + "\t" + cvss + "\t" +
                                                      summary + "\t\tVULN\n")
                                    except Exception as e:
                                        pass
                    # capture entire host data from shodan
                    print("114 shodan_run_host host: " + str(host))
                    with open(output_file_path + "shodan_host__" + str(log_id) + "__" + entry + ".log", "w") as ofp_log:
                        ofp_log.write(str(host))

                # have to rate limit our calls
                time.sleep(155)
            except Exception as e:
                print_text.print_error("shodan host run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

            # wait 58 seconds between requests
            time.sleep(58)

    except Exception as e:
        print_text.print_error("shodan host run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
