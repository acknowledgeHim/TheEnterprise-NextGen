import re, os
import sys
import html
import requests
import datetime
import socket
from itertools import islice
from lxml import etree
from common import keep_tags, network, common_merge, scope_functions
from parsers. parser import Parser
from parsers.finding_for_open_port import OpenPortFinding

def nessus_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("nessus", db_object, key, hashvals) as p:
            p.parse("parsers.vuln.nessus_parser", "NessusParser")

    except Exception as e:
        print("nessus_parser 24 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class NessusParser():
    """ Parse Nessus files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        try:
            if "/" in target:
                target = target.replace("/", "_")
            self.db_object = db_object
            self.output_path = output_path
            self.location_id = location_id
            self.scope_id = scope_id
            self.tool = "nessus"
            self.target = target
            self.log_id = log_id
            self.ext = ext
            self.tester_device_list = tester_device_list
            self.file_path = file_path_name
            self.file_name = just_file_name
            self.modified_by = modified_by
            self.modified_date = modified_date
            self.engagement_info = db_object.view("Engagement", ['id', ''])

            self.scope_type = db_object.grab_column_from_single_record("Scope", ["id"], [scope_id], "type")
            self.scope_domains = db_object.dictionary_list("Scope", "entry", ["type"], ["DOMAIN"])

            # Scope IPs
            self.log_info = db_object.view("Log", ['target', 'command', 'source'], ['id'], [log_id], True)
            self.curr_scope_id = None
            self.current_location_id = None
            if not os.path.isfile(self.log_info[0]['target']) and not os.path.isdir(self.log_info[0]['target']):
                self.curr_scope_id = self.scope_id
                current_location_id = self.db_object.view("Scope", ["location_id"], ["id"], [self.curr_scope_id])
                self.current_location_id = current_location_id[0]["location_id"]
            #self.current_location_id = self.db_object.grab_current_location()
            #if not isinstance(self.current_location_id, int):
            #    self.current_location_id = None
            self.scope_ips = scope_functions.scope_ips(db_object, self.current_location_id)
            self.scope_ip_dictionary = scope_functions.scope_dictionary(db_object, 'IP', self.current_location_id)
            self.scope_website_dictionary = scope_functions.scope_dictionary(db_object, "WEBSITE", self.current_location_id)
            self.scope_domain_dictionary = scope_functions.scope_dictionary(db_object, "DOMAIN", self.current_location_id)

        except Exception as e:
            print("nessus_parser 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        try:
            self.tags = ""
            self.scope_list = []
            self.engagement_device_list = []
            self.open_port_list = []
            self.result_list = []
            self.already_found_internet_accessible_login = []
            if self.ext == "nessus":
                return self.parse_nessus_file()

        except Exception as e:
            print("nessus_parser 64 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return None, None, None, None, None, None

    def remove_extra_spaces(self, text):
        """
        Used to remove extra spaces and tabs.
        :param text:
        :return:
        """
        if "\t" in text:
            text = text.replace("\t", " ")
        while "  " in text:
            text = text.replace("  ", " ")
        return text

    def get_xml_tag_text(self, elements, tag):
        """ Used to extract tag from current xml element. """
        tag_text = ""
        try:
            tags = list(elements.iter(tag))
            for tg in tags:
                tag_text = tg.text
                if tag_text is not None and tag_text != "":
                    tag_text = keep_tags.clean_text(tag_text)
                    break
        except Exception as e:
            print("nessus parser 90 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return tag_text

    def exploits_lookup(self, report_item):
        """ Grab if exploit(s) available. """
        try:
            exploitable = False
            exploits = ""
            exploit_availables = list(report_item.iter('exploit_available'))
            for ea in exploit_availables:
                if ea.text == "true":
                    exploitable = True
            if exploitable is True:
                metasploits = list(report_item.iter('metasploit_name'))
                for m in metasploits:
                    if m.text != "":
                        sep = ""
                        if exploits != "":
                            sep = ", "
                        m.text = keep_tags.clean_text(m.text)
                        exploits = exploits + sep + m.text
                osvdbs = ""
                osvdbs_list = list(report_item.iter('osvdb'))
                for osvdb in osvdbs_list:
                    if osvdb.text != "":
                        sep = ""
                        if osvdbs != "":
                            sep = ", "
                        osvdb.text = keep_tags.clean_text(osvdb.text)
                        osvdbs = osvdbs + sep + osvdb.text
                if osvdbs != "" and exploits != "":
                    exploits = exploits + "; OSVDB(s): " + osvdbs
                else:
                    exploits = "OSVDB(s): " + osvdbs
                if exploits != "" and exploitable is True:
                    exploits = "Exploits are available."
        except Exception as e:
            print("nessus_parser 128 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return exploits

    def patch_publication_date_lookup(self, report_item):
        """ Grab patch_publication_date. """
        patch_publication_date = None
        patch_publications = list(report_item.iter('patch_publication_date'))
        for pp in patch_publications:
            patch_publication_date = pp.text
            patch_publication_date = keep_tags.clean_text(patch_publication_date)
            try:
                patch_publication_date = datetime.datetime.strptime(patch_publication_date, '%Y/%m/%d')
            except:
                patch_publication_date = None
            break
        return patch_publication_date

    def parse_nessus_file(self):
        """
                    Parse nessus .nessus files.  Returns Dictionary of Engagement Devices to Insert/Update

                    PluginID: 10335 - Port Scanner
                    PluginID: 11219 - Port Scanner
                    PluginID: 11936 - OS identification
                    PluginID: 12053 - Host Fully Qualified Domain Name (FQDN) Resolution - get hostname for IP
                    PluginID: 10902 - Members of Administrator's Group (Domain Users or everyone would be finding); 71246 - enumerate local group membership
                    PluginID: 69236 - Active Directory (AD) list of computers & join dates
                    PluginID: 69237 - AD Trusts
                    PluginID: 69238 - AD Groups and members of each group
                    PluginID: 69239 - AD members and groups they are associated with
                    PluginID: 69556 - Retrieves setting of Default Domain Policy GPO (for password, account lockout, and Kerberos policy)
                    PluginID: 24260 - HTTP Info
                            110385 - Authentication success insufficient access (send alert that this nessus scan might not have been a full auth scan)
                """
        try:
            with open(self.file_path, 'rb') as xml_file:
                # loop through Hosts in .nessus file
                for _, element in etree.iterparse(xml_file, tag='ReportHost'):
                    disabled_accounts = []
                    host_name = None
                    host_names = []
                    ip = element.get("name")
                    ip = keep_tags.clean_text(ip)
                    os = ""
                    mac = ""
                    info = ""
                    domain = ""
                    p = element.get("name")
                    ip = keep_tags.clean_text(ip)
                    if not network.valid_ip(ip):  # might be website then
                        host_name = ip
                        try:
                            domain = ip
                            if "://" in domain:
                                domain = domain[domain.find("://") + 3:]
                            if "/" in domain:
                                domain = domain[:domain.find("/")]
                            if not network.private_ip():
                                ip = socket.gethostbyname(domain)
                        except Exception as e:
                            print("nessus_parser 193 except: " + str(e) + " Error on line {}".format(
                                sys.exc_info()[-1].tb_lineno))

                    if not network.valid_ip(ip):
                        valid_ip = False
                        tags = list(element.iter('tag'))
                        for tag in tags:
                            if tag.get('name') is not None and tag.get('name') == 'host-ip':
                                ip = tag.text
                                if network.valid_ip(ip):
                                    valid_ip = True
                            if valid_ip:
                                break

                    # Find hostname
                    start_time = None
                    end_time = None
                    identification_tags = list(element.iter('tag'))
                    for it in identification_tags:
                        tag_name = it.get('name')
                        if tag_name == "os":
                            os = keep_tags.clean_text(it.text)
                        elif tag_name == "operating-system":
                            os = it.text
                            os = keep_tags.clean_text(os)
                        elif tag_name == "host-ip":
                            ip = keep_tags.clean_text(it.text)
                        elif tag_name == "host-fqdn":
                            host_name = keep_tags.clean_text(it.text)
                        elif (tag_name == "netbios_name" or tag_name == "netbios-name") and (
                                    host_name is None or host_name == ip or host_name == ""):
                            host_name = it.text
                            host_name = keep_tags.clean_text(host_name)
                        elif tag_name == "HOST_END":
                            end_time = it.text
                            end_time = keep_tags.clean_text(end_time)
                        elif tag_name == "HOST_START":
                            start_time = it.text
                            start_time = keep_tags.clean_text(start_time)
                        elif tag_name == "mac-address":
                            mac = it.text
                            mac = keep_tags.clean_text(mac)

                    if host_name is None:
                        host_name = ip

                    try:
                        start_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M%S')
                        end_time = datetime.datetime.strptime(end_time, '%Y-%m-%d %H:%M%S')
                    except:
                        start_time = datetime.datetime.strptime(start_time, '%a %b %d %H:%M:%S %Y')
                        end_time = datetime.datetime.strptime(end_time, '%a %b %d %H:%M:%S %Y')

                    if network.valid_ip(ip) and ip not in self.tester_device_list:
                        report_items = list(element.iter('ReportItem'))
                        deviceport_list = []
                        for report_item in report_items:
                            valid_host_name = True
                            port = report_item.get('port')
                            port = keep_tags.clean_text(port)
                            protocol = report_item.get('protocol')
                            protocol = keep_tags.clean_text(protocol)
                            plugin_id = report_item.get('pluginID')
                            plugin_id = keep_tags.clean_text(plugin_id)
                            title = report_item.get('pluginName')
                            title = self.remove_extra_spaces(html.unescape(title))
                            title = keep_tags.clean_text(title)
                            plugin_family = report_item.get('pluginFamily')
                            plugin_family = keep_tags.clean_text(plugin_family)

                            outputs = list(report_item.iter('plugin_output'))
                            output = ""
                            for o in outputs:
                                sep = ""
                                if output != "":
                                    sep = "; "
                                output = output + sep + o.text
                            output = self.remove_extra_spaces(html.unescape(output))
                            output = keep_tags.clean_text(output)

                            description = self.remove_extra_spaces(self.get_xml_tag_text(report_item, "description"))
                            remediation = self.remove_extra_spaces(self.get_xml_tag_text(report_item, "solution"))
                            cvss = self.remove_extra_spaces(self.get_xml_tag_text(report_item, "cvss_base_score"))
                            severity = keep_tags.clean_text(report_item.get('severity'))
                            exploit_available = self.exploits_lookup(report_item)
                            patch_publication_date = self.patch_publication_date_lookup(report_item)
                            see_also = self.remove_extra_spaces(self.get_xml_tag_text(report_item, "see_also"))

                            if see_also != "":
                                remediation = remediation + "\n" + see_also

                            # Device Port.
                            if plugin_id == "10335" or plugin_id == "11219":
                                print("306 nessus parser plugin_id: " + str(plugin_id))
                                self.get_deviceport(ip, port, protocol, report_item, start_time, end_time)
                            elif os is not None and plugin_id == "11936":
                                # See if not found os already, then look inside 11936 plugin to try & grab OS for engagement_device
                                os, info = self.grab_os(report_item)
                            elif plugin_id == "24260":
                                if "Server: " in output:
                                    http_description = output[output.find("Server: ") + 8:]
                                    http_description = http_description[:http_description.find("\n")]
                                    if "X-Powered-By: " in output:
                                        http_description = http_description + " " + output[output.find(
                                            "X-Powered-By: ") + 14:]
                                        http_description = http_description[:http_description.find("\n")]
                                    print("318 nessus parser plugin_id: " + str(plugin_id))
                                    add_port = True
                                    if not network.private_ip(ip):
                                        if not network.nc_verify(ip, port):
                                            add_port = False
                                    if add_port:
                                        self.open_port_list.append((ip, port, protocol, http_description, True,
                                                                self.modified_by, self.modified_date, False, start_time,
                                                                end_time, self.tool))
                            elif plugin_id == "12053" and (host_name is None or host_name == ip or host_name == ""):  # FQDN match
                                host_name = output[output.find("resolves as ") + 12:]
                                if "\n" in host_name:
                                    host_name = host_name.replace("\n", "")
                                    host_name = host_name.rstrip(".").rstrip()
                                # Make sure host name has a domain name in it not just a junk ISP fqdn but only for Public IPs
                                if not network.private_ip(ip):
                                    valid_host_name = common_merge.valid_host_name(ip, host_name)
                            elif plugin_id == "46180":  # DNS Name Found.
                                thostnames = output.split("\n")
                                for hname in thostnames:
                                    if "-" in hname:
                                        hname = hname.replace("-", "").replace(" ", "").replace("\n", "")
                                        host_names.append(hname)
                            elif plugin_id == "10150":  # Netbios
                                tmp_name = ""
                                for output_line in output.split("\n"):
                                    if "= Computer name" in output_line:
                                        tmp_name = tmp_name[:tmp_name.find("= Computer name")]
                                        tmp_name = tmp_name.strip()
                                        break
                                    if tmp_name != "":
                                        host_names.append(tmp_name)
                                        host_name = tmp_name
                                if port == "445":
                                    ignore_finding = True
                            elif plugin_id == "42410":  # Netbios or Windows NTLMSSP authentication request
                                tmp_name = ""
                                for output_line in output.split("\n"):
                                    if "= Computer name" in output_line:
                                        tmp_name = tmp_name[:tmp_name.find("= Computer name")]
                                        tmp_name = tmp_name.strip()
                                    if tmp_name != "":
                                        host_names.append(tmp_name)
                                        host_name = tmp_name
                            elif plugin_id == "43815":  # netbios giving multiple IPs of device
                                if info is None:
                                    info = output
                                else:
                                    info = info + output
                            elif plugin_id == "108761":
                                    if "DNS Computer Name:" in output:
                                        hname = output[output.find("DNS Computer Name:") + 18:]
                                        if "\n" in hname:
                                            host_name = hname[:hname.find("\n")].lower()
                                            host_name = host_name.strip()
                                        if "." in host_name:
                                            domain = host_name[host_name.find(".")+1:]
                                            host_name = host_name[:host_name.find(".")]
                                    elif "DNS Domain Name:" in output:
                                        dname = output[output.find("DNS Domain Name:") + 16:]
                                        if "\n" in dname:
                                            domain = dname[:dname.find("\n")].lower()
                                            domain = domain.strip()
                            elif plugin_id == "10400":
                                remote_registry_accessible = True
                            elif plugin_id == "10180":
                                if "is considered as dead" in output:
                                    skip_asset = False
                                    self.error = self.error + " Asset " + ip + " is considered dead because Nessus ID 10180 said so :(."
                            elif plugin_id == "12634" or plugin_id == "35703":
                                authenticated = True
                            elif plugin_id == "10897":  # keep track of disabled user accounts
                                if "- " in output:
                                    disabled_output = output[output.find("- "):]
                                    disabled_accts = disabled_output.split("- ")
                                    for disa in disabled_accts:
                                        disabled_accounts.append(disa.strip("\n").strip().lower())
                            elif plugin_id == "48337":  # device info
                                if "Computer System Product" in output:
                                    info = output[output.find("Computer System Product"):]
                                    info = info[info.find("\n") + 1:]

                            # cut out domain from host name
                            if not network.valid_ip(host_name) and valid_host_name and "." in host_name and domain is None:
                                domain = host_name[host_name.find(".") + 1:]
                                host_name = host_name[:host_name.find(".")]

                            # Check for Findings / Results from Open Port identified (not typical Nessus finding)
                            with OpenPortFinding(self.db_object, self.modified_by, self.scope_id, self.location_id) as open_port_finding:
                                already_found_internet_accessible_login, result_list = open_port_finding.open_services_finding_result(
                                    self.already_found_result, self.result_list, ip, port, protocol, "", start_time, end_time, "nessus")
                                if already_found_internet_accessible_login is not None:
                                    self.already_found_internet_accessible_login = already_found_internet_accessible_login
                                if result_list is not None:
                                    self.result_list = result_list

                            # Result
                            self.result_list.append(['nessus', plugin_id, ip, port, protocol, output, None, start_time,
                                                     end_time, "nessus - " + plugin_id + " from " + self.file_name,
                                                    title, description, remediation, cvss, severity, plugin_family,
                                                    exploit_available, patch_publication_date, self.modified_by])

                            if port != "0":
                                port_description = report_item.get('svc_name')
                                port_description = Parser.remove_extra_spaces(self, keep_tags.clean_text(port_description))
                                if port_description is None:
                                    port_description = ""
                                # Open port
                                print("420 nessus parser plugin_id: " + str(plugin_id))
                                add_port = True
                                if not network.private_ip(ip):
                                    if not network.nc_verify(ip, port):
                                        add_port = False
                                if add_port:
                                    self.open_port_list.append((ip, port, protocol, port_description, True,
                                                           self.modified_by, self.modified_date, False, start_time,
                                                           end_time, 'nessus - ' + self.file_name))

                            # Clear xml elements that no longer need
                            report_item.clear()

                        # Engagement Device and account for virtual web servers behind a single IP (using reverse proxy)
                        if len(host_names) == 0:
                            host_names.append(host_name)
                        curr_scope_id = self.curr_scope_id
                        if curr_scope_id is None:
                            if network.valid_ip(ip):
                                for scope_ip in self.scope_ips:
                                    if network.check_in_network(scope_ip, ip):
                                        curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                        break

                        if self.curr_scope_id is not None:
                            for h_name in host_names:
                                for key, value in self.scope_website_dictionary.items():
                                    if h_name in key:
                                        curr_scope_id = value
                                        break
                                    elif "www." in h_name:
                                        t_h_name = h_name.replace("www.", "")
                                        if t_h_name in key:
                                            curr_scope_id = value
                                            break
                                if curr_scope_id is not None:
                                    break

                        if curr_scope_id is None:
                            for key, value in self.scope_domain_dictionary.items():
                                if domain in key:
                                    curr_scope_id = value
                                    break
                        if curr_scope_id is None:
                            for key, value in self.scope_website_dictionary.items():
                                if domain in key:
                                    curr_scope_id = value
                                    break

                        if curr_scope_id is not None:
                            host_name = host_names[0]
                            if ip in host_name:
                                host_name = ip
                            if ip.replace(".", "-") in host_name:
                                host_name = ip
                            if len(host_names) > 1:
                                hnames = ", ".join(host_names)
                                info = "Host Names: " + hnames + "\n" + info

                            self.engagement_device_list.append((ip, host_name, domain, os, mac, "", info, "", "", "",
                                    self.modified_by, self.modified_date, self.tool, curr_scope_id))

                    # Clear xml elements that no longer need
                    element.clear()
        except Exception as e:
            print("nessus_parser 293 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        output_dictionary = {}
        output_dictionary["scopes"] = self.scope_list
        output_dictionary["scopes_fields_to_update"] = [('open_ip', 'c'), ('open_port', 'c')]
        output_dictionary["devices"] = self.engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('os', 'ol'), ('mac', 'c')]
        output_dictionary["results"] = self.result_list
        output_dictionary["results_fields_to_update"] = [('output', 'as'), ('tester_output', 'as')]
        output_dictionary["ports"] = self.open_port_list
        output_dictionary["ports_fields_to_update"] = [('port_description', 'as')]

        return output_dictionary


    def get_deviceport(self, ip, port, protocol, report_item, start_time, end_time):
        """ Append open ports for either insert or update (update if description in DB is Null). """
        add_port = True
        if not network.private_ip(ip):
            if not network.nc_verify(ip, port):
                add_port = False
        if add_port:
            description = report_item.get('svc_name')
            description = self.remove_extra_spaces(keep_tags.clean_text(description))
            if str(port) != "0": #dont add port 0 for either UDP or TCP as it is a Nessus thing
                self.open_port_list.append((ip, port, protocol, description, True,
                                   self.modified_by, self.modified_date, False, start_time, end_time, self.tool))

    def grab_os(self, report_item):
        """
        Grab Operating system using plugin_id 11936
        :param report_item:
        :return:
        """
        outputs = list(report_item.iter('plugin_output'))
        operatingsystem = ""
        for o in outputs:
            output = o.text
            if "Remote operating system : " in output:
                operatingsystem = output[output.find("Remote operating system : ") + 26:]
                operatingsystem = operatingsystem[:operatingsystem.find("\n")]
                operatingsystem = operatingsystem.strip()
                if ";" in operatingsystem:
                    operatingsystem = operatingsystem[:operatingsystem.find(";")]
                operatingsystem = keep_tags.clean_text(operatingsystem)
            confidence_level = ""
            if "Confidence level : " in output and operatingsystem != "":
                confidence_level = output[output.find("Confidence level : ") + 19:]
                confidence_level = confidence_level.strip().strip('\n')
                if "The remote host is" in confidence_level:
                    confidence_level = confidence_level[:confidence_level.find("The remote host is")]
                if ";" in confidence_level:
                    confidence_level = confidence_level[:confidence_level.find(";")]
                confidence_level = Parser.remove_extra_spaces(self, html.unescape(keep_tags.clean_text(confidence_level)).replace("\n", " "))
                if " Method" in confidence_level:
                    confidence_level = confidence_level.replace(" Method", "% Method", 1)
                confidence_level = "OS Confidence Level: " + confidence_level + "\n"
            operatingsystem = operatingsystem
            operatingsystem = Parser.remove_extra_spaces(self, html.unescape(operatingsystem))
            break
        return operatingsystem, confidence_level

