import html, os
import sys
import json
from common import keep_tags, dns_functions, network, common, scope_functions
from parsers. parser import Parser


def gobuster(db_path, db_object, key, hashvals):
    """
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """

    try:
        with Parser("gobuster", db_object, key, hashvals) as p:
            p.parse("parsers.vuln.web.gobuster_parser", "GoBusterParser")

    except Exception as e:
        print("GoBusterParser 21 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

class GoBusterParser():
    """ Parse GoBusterParser files. """

    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):
        try:
            if "/" in target:
                target = target.replace("/", "_")
            self.db_object = db_object
            self.output_path = output_path
            self.location_id = location_id
            self.scope_id = scope_id
            self.tool = "gobuster"
            self.target = target
            self.log_id = log_id
            self.log_info = self.db_object.log_record_by_id(log_id)
            self.command = self.log_info['command']
            self.start_time = self.log_info['start_time']
            self.ext = ext
            self.tester_device_list = tester_device_list
            self.file_path = file_path_name
            self.file_name = just_file_name
            self.modified_by = modified_by
            self.modified_date = modified_date

            # Scope IPs
            self.log_info = db_object.view("Log", ['target', 'command', 'source'], ['id'], [log_id], True)
            self.curr_scope_id = None
            if not os.path.isfile(self.log_info[0]['target']) and not os.path.isdir(self.log_info[0]['target']):
                self.curr_scope_id = self.scope_id
            self.current_location_id = self.db_object.grab_current_location()
            if not isinstance(self.current_location_id, int):
                self.current_location_id = None
            self.scope_ips = scope_functions.scope_ips(db_object, self.current_location_id)
            self.scope_ip_dictionary = scope_functions.scope_dictionary(db_object, 'IP', self.current_location_id)

        except Exception as e:
            print("gobuster_parser 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        try:
            self.tags = ""
            self.engagement_device_list = []
            #self.open_port_list = []
            self.result_list = []
            if self.ext == "txt":
                return self.parse_gobuster_file()

        except Exception as e:
            print("GoBusterParser parser 47 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return None, None, None, None, None, None


    def parse_gobuster_file(self):
        """
            Parse gobuster .txt files.
        """
        title = "GoBuster was able to bruteforce identify web server directories/pages."
        successful_description = "The identified directories / pages allows potentially malicious users to " \
                                 "sub-directories or pages that might contain sensitive information."
        forbidden_title = "GoBuster was able to identify directories/pages that were forbidden"
        forbidden_description = "The identified directories / pages that were forbidden might help a malicous user determine valid " \
                               "directories / pages if only valid pages are either forbidden or not redirected."
        redirect_title = "GoBuster was able to identify directories/pages that redirected"
        redirect_description = "The identified directories / pages that redirected to another page might help a malicous user determine valid " \
                               "directories / pages if only valid pages are either redirected or not redirected."
        successful_pages = []
        forbidden_pages = []
        redirect_pages = []
        already_engagement_device = []
        already_device_port = []
        try:
            target = ""
            external_only = self.db_object.external_only()
            with open(self.file_path, 'r') as f:
                # loop through txt file
                for line in f.readlines():
                    line = keep_tags.clean_text(line)
                    # page/dir found
                    website = ""
                    command = self.command
                    if " -u " in command and ("http" in command):
                        website = command[command.find("-u ") + 3:]
                        website = website[:website.find(" " )]
                    if website == "":
                        website = self.file_path[self.file_path.rfind("__")+2:]
                        website = website.replace(".txt", "")
                        if "http_" in website:
                            website = website.replace("http_", "http://")
                        elif "https_" in website:
                            website = website.replace("https_", "https://")
                        if "-" in website:
                            website = website.replace("-", ":")

                    path = line[:line.find(" ")]
                    if "(Status: 200)" in line:
                        successful_pages.append(website + "<a href='" + path + "'>" + path + "</a>")
                    elif "(Status: 403)" in line:
                        forbidden_pages.append(website + "<a href='" + path + "'>" + path + "</a>")
                    elif "(Status: 302)" in line:
                        redirect_pages.append(website + path)

                domain = common.format_website(website)
                if not network.valid_ip(domain):
                    ip = dns_functions.find_dns_records(domain)
                else:
                    ip = domain
                port = network.return_port(website)
                if external_only and network.private_ip(ip):
                    # Engagement Device
                    if domain not in already_engagement_device:
                        already_engagement_device.append(domain)
                        self.engagement_device_list.append(
                            (None, domain, None, None, None, None, None, None, None, None,
                             self.modified_by, self.modified_date, self.tool, self.scope_id))
                else:
                    # Engagement Device
                    if domain not in already_engagement_device:
                        already_engagement_device.append(domain)
                        if self.curr_scope_id is not None:
                            curr_scope_id = self.curr_scope_id
                        if self.curr_scope_id is None:
                            if network.valid_ip(ip):
                                for scope_ip in self.scope_ips:
                                    if network.check_in_network(scope_ip, ip):
                                        curr_scope_id = self.scope_ip_dictionary[scope_ip]
                                        break
                        if curr_scope_id is not None:
                            self.engagement_device_list.append(
                                (ip, domain, None, None, None, None, None, None, None, None,
                                 self.modified_by, self.modified_date, self.tool, curr_scope_id))

                    # Open Port.
                    #if ip not in already_device_port and ip is not None:
                    #    already_device_port.append(ip)
                    #    self.open_port_list.append((ip, port, "tcp", "http", True,
                    #                            self.modified_by, self.modified_date, False, self.start_time,
                    #                            self.start_time, 'gobuster - ' + self.file_name))

                successful = ', '.join(successful_pages)
                forbidden = ', '.join(forbidden_pages)
                redirect = ', '.join(redirect_pages)

                output = ""
                if len(successful_pages) > 0:
                    success_output = "Successful directories/pages: " + successful
                    # Result
                    self.result_list.append(['gobuster', "gobuster-website-successful", domain,
                                             port, "tcp", success_output, None, self.start_time, self.start_time,
                                             "gobuster", title, successful_description, None, None, "0", None,
                                             None, None, self.modified_by])
                if len(forbidden_pages) > 0:
                    forbi_output = "Forbidden directories/pages: " + forbidden
                    # Result
                    self.result_list.append(['gobuster', "gobuster-website-forbidden", domain,
                                             port, "tcp", forbi_output, None, self.start_time, self.start_time,
                                             "gobuster", forbidden_title, forbidden_description, None, None, "0", None,
                                             None, None, self.modified_by])
                if len(redirect_pages) > 0:
                    redirect_output = "Redirected directories/pages: " + redirect
                    # Result
                    self.result_list.append(['gobuster', "gobuster-website_redirect", domain,
                                             port, "tcp", redirect_output, None, self.start_time, self.start_time,
                                             "gobuster", redirect_title, redirect_description, None, None, "0", None,
                                             None, None, self.modified_by])

        except Exception as e:
            print("gobuster_parser 150 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        output_dictionary = {}
        output_dictionary["devices"] = self.engagement_device_list
        output_dictionary["devices_fields_to_update"] = [('os', 'ol'), ('mac', 'c')]
        output_dictionary["results"] = self.result_list
        output_dictionary["results_fields_to_update"] = [('output', 'ol'), ('tester_output', 'ol')]
        #output_dictionary["ports"] = self.open_port_list
        #output_dictionary["ports_fields_to_update"] = [('port_description', 'ol')]

        return output_dictionary
