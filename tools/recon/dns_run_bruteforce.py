import sys
from common import print_text, common, dns_functions, network

def dns_run_bruteforce(command, scope_id, location_id, db_object, log_id):
    """ DNS records. """
    try:
        command = command.replace('"', '')
        domain = command[command.find(";")+1:]

        log_info = db_object.log_record_by_id(log_id)
        output_file_path = log_info['output_filepath']
        output_file = str(output_file_path) + "dns_bruteforce__" + str(log_id) + "__" + str(domain) + ".txt"
        print("13 dns_run_bruteforce output_file: " + str(output_file))
        source = ""#output_file + " - "

        scope_ips = db_object.scope_ips()

        count_bruteforce = 0
        count_same_result = 0
        prior_result_ip = ""
        tmp_results = []
        results = []
        # DNS Bruteforce
        with open("tools/recon/wordlist.wl") as dns_prefixes:
            for dns_prefix in dns_prefixes:
                dns_prefix = dns_prefix.replace("\n", "").strip()
                if count_bruteforce > 50 and count_same_result == count_bruteforce:
                    msg = "DNS resolves any sub-domain."
                    print_text.print_msg("\t" + msg)
                    # Update Log record comment
                    update_values = dict(id=log_id, comment=msg)
                    db_object.update("Log", update_values, "id")
                    break
                elif count_bruteforce % 100000:
                    # Update Log record comment
                    update_values = dict(id=log_id, comment="Bruteforce still running. Currently working on dns prefix: " + dns_prefix)
                    db_object.update("Log", update_values, "id")

                result_ip, information, dns_description, organization, nameservers = dns_functions.domain_information(dns_prefix + '.' + domain, False)

                if count_bruteforce == 0:
                    prior_result_ip = result_ip

                if result_ip != "":
                    if prior_result_ip == result_ip:
                        count_same_result += 1
                    prior_result_ip = result_ip
                    description = "Sub domain is not within the Scope IP ranges.  " + dns_description
                    for scope_ip in scope_ips:
                        if network.check_in_network(scope_ip['entry'], result_ip):
                            description = "Sub domain's resolved IP, " + result_ip + ", is within Scope: " + scope_ip['entry'] +".  " + str(dns_description)
                            break
                    tmp_results.append((dns_prefix + "." + domain, result_ip, description, information, organization))
                count_bruteforce += 1

        if count_same_result != count_bruteforce:
            results = tmp_results
        if "sleep " not in output_file and scope_id is not None:
            with open(output_file, "w") as ofp:
                for result in results:
                    ofp.write(str(scope_id)+"\tDOMAIN\t"+result[0]+"\t" + result[3] + "\t"+result[1]+"\t"+result[2]+"\t\t"+source+"dns bruteforce\n")

    except Exception as e:
        print_text.print_error("dns_run_bruteforce except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
