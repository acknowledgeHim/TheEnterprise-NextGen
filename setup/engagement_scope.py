import sys
import ipaddress
import socket
import dns.resolver
from common import dns_functions, common
from netaddr import IPNetwork
from common import network
from common import print_text

class ScopeEntry():
    """
    Validates, standardizes and obtains public information about scope entry.

    :param passed_fields_value: dictionary where key is column name
    :return list dictionary of fields_values where key:value pair is column:value
    """
    def __init__(self, external_or_internal, passed_fields_value, engagement_id=None):
        self.passed_fields_value = passed_fields_value
        self.engagement_id = engagement_id

        self.public_only = False
        self.private_only = False
        if external_or_internal == "external":
            self.public_only = True
        elif external_or_internal == "internal":
            self.private_only = True
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def __is_private(self, ip):
        """Returns True if IP entered is Private IP, False if Public IP"""
        return network.is_private(ip)

    def __find_type(self):
        """
        Find Entry type - IP, DOMAIN, WEBSITE
        Return entry type.
        """
        try:
            tmp_entry = self.passed_fields_value['entry']
            if "-" in tmp_entry:
                tmp_entry = tmp_entry[:tmp_entry.find("-")]
            elif "/" in tmp_entry:
                tmp_entry = tmp_entry[:tmp_entry.find("/")]
            ipaddress.ip_network(tmp_entry.replace(" ", ""))
            return "IP"
        except Exception as e:
            pass
        if "http://" in self.passed_fields_value['entry'] or "https://" in self.passed_fields_value['entry']:
            return "WEBSITE"
        else: #elif "." in self.passed_fields_value['entry']:
            return "DOMAIN"
        return "UNKNOWN"

    def initialize(self):
        """
        Initializes checks to verify entry entered.
        First determines the type of entry entered.

        Returns field_values Dict or empty Dict if error and if insert-ing many at once (only IPs use this).
        """
        type = self.__find_type()
        if "type" in self.passed_fields_value:
            if type != "":
                self.passed_fields_value['type'] = type
            else:
                self.passed_fields_value = {}
        return type

    def __find_geo_data(self, single_ip):
        """
        Calls function to get Geo Data and then returns the results of that formatted in a string.
        Attributes:
            single_ip -- the IP address to find Geo Location information about.
        """
        try:
            return dns_functions.get_formated_geo_data(single_ip)
        except Exception as e:
            print("EngagementScope find geo except: " + str(e))
        return ''

    def __find_whois(self, single_ip):
        """
        Calls function to grab whois information for passed IP.
        Combines the ISP and description returned by grab_whois_ip function.
        Returns whois information.

        :param single_ip: single IP address from entry used to find whois information about
        """
        return dns_functions.grab_whois_ip(single_ip)

    def __find_whois_domain(self, domain):
        """
        Calls function to grab whois information for passed domain.
        Returns whois information.

        :param domain: entry domain used to find whois information about
        """
        information, registrar, domain_valid_date_range, nameservers = dns_functions.grab_whois_domain(domain)
        return information

    def __find_open_ip_port(self, list_of_ips_in_cidr, port_list=None):
        """
        Find an open IP/Port combo for ip_list entered.
        If you want to skip NetworkID & Broadcast checking then, add: i != 0 or i < len(IPNetwork(ipt))-1: for if i <len(IPNetwork(ipt) line.
        Returns open_ip and open_port if found, else blank

        Arguments:
            ip_list -- List(str): the IPs in CIDR notation.
        """
        try:
            ports = ['80', '443', '1723', '47'] # For External Engagements
            if not self.public_only: # For Internal Engagements
                ports = ["445", "80", "443", "139"]

            if port_list != None:
                ports = port_list
            for ip_range in list_of_ips_in_cidr:
                if "/" in ip_range:
                    i = 0
                    for ip in IPNetwork(ip_range):  # loop through all ips in network range
                        if i < len(IPNetwork(ip_range)):  # don't do for NetworkID or broadcast
                            for port in ports:
                                if network.nc_verify(str(ip), port, "tcp"):
                                    return str(ip), port
                        if i > 40:  # don't try more than 50 combos (means 12 IPs tested for each of the 4 ports)
                            break
                        i = i + 1
        except Exception as e:
            print("setup engagement_scope 142 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return '', ''

    def __standardize_ip(self, original_entry):
        """
        Takes IP original_entry/range and converts to CIDR range(s).
        Returns List(str) of IPs in CIDR notation.

        Arguments:
            original_entry -- original IP original_entry
            ip_type -- if IPv4 or IPv6
        """
        msg = "\tInvalid CIDR notation found in Scope IP original_entry."
        cidr_standardized_ips = []
        if "-" in original_entry:
            ip_ent = network.convert_ip_range_to_cidr(original_entry[:original_entry.find("-")].strip(),
                                                      original_entry[original_entry.find("-") + 1:].strip())
            cidr_standardized_ips = ip_ent.split("\n")
            cidr_standardized_ips.pop()
        elif "/" in original_entry:
            try:
                ipaddress.ip_network(original_entry, strict=False)
                cidr_standardized_ips.append(original_entry)
            except:
                print_text.print_error(msg)
                cidr_standardized_ips = msg
        else:
            try:
                ipaddress.ip_network(original_entry + '/32')
                cidr_standardized_ips.append(original_entry + '/32')
            except:
                print_text.print_error(msg)
                cidr_standardized_ips = msg
        return cidr_standardized_ips

    def add_ip(self, current_scope_ips_in_db, location_id):
        """
        Verifies if IP should be/is private/pubic.
        Standardizes IP to CIDR notation.
        Verifies if each standardized IP is already in DB or not, if so does not add, if not adds, if superset (larger) range than a current entry, then deletes current entry.
        Tries to find Open IP/Port.
        Grabs Whois information.
        Grabs Geolocation information.

        Returns Dict{column:value} and bool insert_many which is True if IP was broken
        into multiple ranges and False if single entry.
        """
        insert_many = False
        original_entry = self.passed_fields_value['entry']

        single_ip = ''
        msg = "Failed to add Scope IP entry."
        try:
            tmp_single_ip = original_entry
            if "-" in original_entry:
                tmp_single_ip = original_entry[:original_entry.find("-")]
            elif "/" in original_entry:
                tmp_single_ip = original_entry[:original_entry.find("/")]
            elif "," in original_entry:
                tmp_single_ip = original_entry[:original_entry.find(",")]
            single_ip = tmp_single_ip
            ipaddress.ip_network(single_ip)

            if self.public_only and self.__is_private(single_ip):
                msg = "Only Public/External IPs should be entered. You entered a Private IP address/range.  Try again!"
                print_text.print_error("\t" + msg)
                return None, None, None
            ip_type = 'v4'
            if network.is_valid_ipv6_address(single_ip):
                ip_type = 'v6'
        except Exception as e:
            print_text.print_error("\tEngagement Scope Except: " +  str(e))
            return None, None, None

        if isinstance(single_ip, str):
            single_ip.encode("utf-8")

        list_of_ips_in_cidr = self.__standardize_ip(original_entry)

        # If str then IP notation was messed up and so reject
        if isinstance(list_of_ips_in_cidr, str):
            return list_of_ips_in_cidr

        list_of_ips_to_add = []
        list_of_ips_to_remove = []
        try:
            if len(current_scope_ips_in_db) > 0:
                for ip in list_of_ips_in_cidr:
                    check_in_network = True
                    for db_ip in current_scope_ips_in_db:
                        check_in_network = network.check_in_network(db_ip, ip)
                        if check_in_network is not False and check_in_network is not True:
                            if check_in_network not in list_of_ips_to_remove:
                                list_of_ips_to_remove.append(check_in_network)
                        if check_in_network == True:
                            break
                    if check_in_network != True:
                        list_of_ips_to_add.append(ip)
            else:
                list_of_ips_to_add = list_of_ips_in_cidr
        except Exception as e:
            msg = "EngagementScope check if exists except: " + str(e)
            print_text.print_error("\t" + msg)
            return msg

        try:
            open_ip = ""
            open_port = ""
            information = ""
            additional = ""
            if not self.__is_private(single_ip):
                open_ip, open_port = self.__find_open_ip_port(list_of_ips_to_add)

                information = self.__find_whois(single_ip)

                additional = self.__find_geo_data(single_ip)
            permission = True
            if 'permission' in self.passed_fields_value:
                permission = self.passed_fields_value['permission']
            if len(list_of_ips_to_add) > 1:
                insert_many = True
                fields_value = []
                for ip in list_of_ips_to_add:
                    if ip != "":
                        fields_value.append({'original_entry':original_entry, 'entry': ip,
                                         'permission': permission, 'open_ip': open_ip,
                                         'open_port': open_port, 'information': information, 'type': "IP",
                                         'additional': additional, 'location_id': location_id})
            elif len(list_of_ips_to_add) == 1:
                if list_of_ips_to_add[0] != "":
                    fields_value = {'original_entry':original_entry, 'entry': list_of_ips_to_add[0],
                                'permission': permission, 'open_ip': open_ip,
                                'open_port': open_port, 'information': information, 'type': "IP",
                                'additional': additional, 'location_id': location_id}
            else:
                fields_value = "Entry, " + original_entry + ", is already part of the Engagement Scope."

            return fields_value, insert_many, list_of_ips_to_remove
        except Exception as e:
            print_text.print_error("engagement scope except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            return "EngagementScope check if exists except: " + str(e)

    def add_website(self, current_websites_in_db, location_id):
        """
        Building Dict of values to add website to Scope.
        Verify that the website is not already in the DB.
        Find out open_ip/port.
        Grab whois associated IP info, Geo location, and domain whois info.
        """
        unresolved_website_error_text = "\tThe website entered does not have a valid IP address it resolves to so not adding!"
        original_entry = self.passed_fields_value['entry']

        for website_db in current_websites_in_db:
            if website_db == original_entry:
                print_text.print_error("\tThe website, " + original_entry +", is already included in the Scope.")
                return {}

        domain = common.format_website(original_entry)
        if 'permission' in self.passed_fields_value:
            permission = self.passed_fields_value['permission']
        else:
            permission = True

        try:
            website_ip_address = socket.gethostbyname(domain)
        except Exception as e:
            print_text.print_error(unresolved_website_error_text + ", except: " + str(e))
            return unresolved_website_error_text

        port = str(network.return_port(original_entry))

        open_ip = ""
        open_port = ""
        information = ""
        additional = ""
        if isinstance(website_ip_address, str):
            website_ip_address.encode("utf-8")
        if not self.__is_private(website_ip_address):
            information = self.__find_whois(website_ip_address)
            additional = self.__find_whois_domain(domain)
            sep = ""
            if additional != "":
                sep = "; "
            additional = additional + sep + self.__find_geo_data(website_ip_address)
            open_ip, open_port = self.__find_open_ip_port([website_ip_address+"/32"], port_list=[port])
            if open_ip is None or open_ip == "":
                open_ip = website_ip_address
            if open_port is None or open_port == "":
                # get open port from website URL
                strip_http = original_entry.replace("://", "")
                if ":" in strip_http:
                    open_port = strip_http[strip_http.find(":") + 1:]
                    if "/" in open_port:
                        open_port = open_port[:"/"]
                    elif "http://" in original_entry:
                        open_port = 80
                    elif "https://" in original_entry:
                        open_port = 443
        else:
            print_text.print_error(unresolved_website_error_text)

            return unresolved_website_error_text

        fields_value = {'original_entry':original_entry, 'entry': original_entry,
                        'permission': permission, 'open_ip': open_ip,
                        'open_port': open_port, 'information': information, 'type': "WEBSITE",
                        'additional': additional, 'location_id': location_id}

        return fields_value

    def add_domain(self, current_domains_in_db, location_id, domain=None):
        """
        Building Dict of values to add domain to Scope.
        Domain whois, associated IP show is and geo location.
        Returns Dict of values ready to add.
        """
        information = ""
        additional = ""
        permission = True
        if domain is None:
            domain = self.passed_fields_value['entry']
            permission = self.passed_fields_value['permission']

        for domain_db in current_domains_in_db:
            if domain_db == domain:
                print_text.print_error("\tThe domain, " + domain +", is already included in the Scope.")
                return {}

        domain_ip = ""
        if "." in domain and ".local" not in domain: #try to avoid timely lookup stuff for internal domains
            try:
                information = self.__find_whois_domain(domain)
            except Exception as e:
                print_text.print_error("engagementscope 355 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

            domain_ip, additional = dns_functions.grab_dns_record(domain, self.public_only)
        else:
            pass
            # Try to find Domain Controlles, DNS Servers, etc

        fields_value = {'original_entry': domain, 'entry': domain,
                        'permission': permission, 'open_ip': domain_ip,
                        'open_port': "", 'information': information, 'type': "DOMAIN",
                        'additional': additional, 'location_id': location_id}
        return fields_value


def domain_in_scope(db_object, domain):
    """
    Check if passed domain is part of a website in a scope entry.
    Ex. Domain: vpn.example.com Scope Entry: https://vpn.example.com would return True
    """
    websites = db_object.view("Scope", ['entry'], ['type'], ['WEBSITE'])    #grab_column_from_single_record("Scope", ["type"], ["WEBSITE"], "entry")

    if websites is not None:
        for website in websites:
            print("392 engagement_scope website: " + str(website))
            if domain in website['entry']:
                return True

    return False

def ip_in_scope(db_object, ip):
    """
    Check if passed ip is with an IP scope entry
    :param db_object:
    :param ip:
    :return:
    """

    ips = db_object.view("Scope", ['entry'], ['type'], ['IP']) #grab_column_from_single_record("Scope", ["type"], ["IP"], "entry")

    if ips is not None:
        for curr_ip in ips:
            if network.check_in_network(curr_ip['entry'], ip):
                return True

    return False