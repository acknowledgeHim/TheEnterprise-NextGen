import sys
import socket
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from ipwhois import IPWhois
from common import dns_functions, print_text, common, network


def dns_query(command, scope_id, location_id, db_object, log_id):
    """ DNS records. """
    try:
        scope_ips = db_object.scope_ips()
        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        domain = command[command.find(";")+1:]
        print("17 dns_query command: " + str(command))
        print("18 dns_query domain: " + str(domain))
        log_info = db_object.log_record_by_id(log_id)
        print('20 dns_query log_info: ' + str(log_info))
        output_file_path = log_info['output_filepath']
        print("21 dns_query output_file_path: " + str(output_file_path))
        output_file = output_file_path + "dns_lookup__" + str(log_id) + "__" + domain + ".txt"
        source = ""#output_file + " - "

        with open(output_file, "w") as ofp:
            # DNS lookups
            associated_info, information, description, organization, nameservers = dns_functions.domain_information(domain, True)
            dns_info = str(scope_id)+"\tDOMAIN\t"+domain.lower()+"\t"+information+"\t"+associated_info+"\t"+description+"\t"+\
                       organization+"\t"+source+"whois database"
            ofp.write(dns_info.replace("\n","") + "\n")

            for ns in nameservers:
                domain_ip, information = dns_functions.grab_dns_record(ns, True)
                ns_info = str(scope_id) + "\tNS\t" + ns.lower() + "\t" + information + "\t" + domain_ip + "\t" + "\t" + "\t"+source+"dns lookup"
                ofp.write(ns_info.replace("\n", "") + "\n")

            # Vendor
            if "ISP: " in information:
                isp = information[information.find("ISP: ") + 5:]
                isp = isp[:isp.find(" for IP")]
                ofp.write(str(scope_id) + "\tvendor\t" + isp + "\t\t\t\t\t"+source+"whois database\n")

            mx_query(ofp, scope_id, domain, source)

            txt_records_query(ofp, scope_id, domain)

        return True
    except Exception as e:
        print_text.print_error("dns_query except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return False

def mx_query(ofp, scope_id, domain, source=""):
    """
    MX (Mail Exchange) records.
    :return:
    """
    records = []
    try:
        records = dns.resolver.query(domain, 'MX')
    except Exception as e:
        try:
            query = dns.message.make_query(domain, dns.rdatatype.MX)
            records = dns.query.udp(query, domain, timeout=10).answer
        except Exception as e:
            print_text.print_error("\tDNS query error: " + str(e))
            #print("dns_query 58 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    source = source + "dns lookup (mx)"
    for record in records:
        ip = ""
        print("65 dns_query record: " + str(record))
        record = str(record)
        mxfull = str(record).rstrip('.')
        mx = mxfull # mxfull should be something like: 10 mailserver.google.com so need to only keep mailserver.google.com portion
        if " " in mx:
            mx = mxfull[mxfull.find(
                ' ') + 1:]
            if "." not in mx:
                mx = mxfull[:mxfull.find(' ')]
        try:
            ip = socket.gethostbyname(mx)  # finds out if IP associated
            whois_info = IPWhois(ip.rstrip('\n')).lookup_whois()
            nets = whois_info['nets']
            sep = ""
            whois_ip_owner = ""
            for net in nets:
                if whois_ip_owner != "":
                    sep = "; "
                whois_ip_owner = whois_ip_owner + sep + net['description']
        except Exception as e:
            whois_ip_owner = ''
            ip = ''
        mx = mx.lower()
        if whois_ip_owner != "":
            whois_ip_owner = "WHOIS IP owner: " + whois_ip_owner

        ofp.write(str(scope_id) + "\tMX\t" + mx.lower() + "\t" + whois_ip_owner + "\t" + ip + "\t" + "\t" + "\t" + source +"\n")

def txt_records_query(ofp, scope_id, domain):
    """ Grab all txt records from DNS. """
    try:
        records = dns.resolver.query(domain, 'TXT')
        for record in records:
            txt_info = str(scope_id) + "\tTXT\t" + str(record).lower() + "\t\t\t\t\tdns lookup (txt)"
            ofp.write(txt_info.replace("\n", "") +  "\n")
    except Exception as e:
        print_text.print_error("\tDNS txt record: " + str(e))


