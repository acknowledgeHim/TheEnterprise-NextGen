import sys
import os
from operator import itemgetter
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from common import print_text
from common import encryption
from common import sqlalchemy_model
from common import network
from common import common
from common.sqlalchemy_db import Interaction

def verify_key_connect_to_emailevent_db(username, passwd):
    """
    Checks the setup/email_event.db which was created using the encryption key
    during the install to make sure the user correctly typed the encryption key.
    Returns True if encryption key was correct, False if not.

    Attributes:
        encrypt_key -- the encryption key used for the SQLCipher database
    """
    try:
        supplied_hashed_pass = encryption.hash_string(passwd)
        base = os.path.dirname(os.path.realpath(__file__)) + "/"
        if "/common" in base:
            base = base.replace("/common/", "/")
        with OurCoolDBObject(base + 'setup/email_event.db', 'common.email_db_model') as db_object:
            hashed_pass = db_object.grab_column_from_single_record("FlaskUser", ["username"], [username], "passwd")

        if hashed_pass == supplied_hashed_pass:
            return True
    except Exception as e:
        print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    print_text.print_error("\tYou incorrectly entered the encryption key.  Please try again!")
    return False

class OurCoolDBObject(Interaction):
    """
    Extends Interaction class while providing pre-defined queries.
    """
    def __init__(self, db_file, module_path='common.sqlalchemy_model', tester=None):
        """
        Creates default queries easily.
        :param sqlite_file: path/to/sqlite_file
        :param pass_phrase: encryption key
        """
        self.current_tester = common.get_tester()
        if tester is not None:
            self.current_tester = tester

        self.module_path = module_path
        Interaction.__init__(self, db_file, self.current_tester)
        self.sqlite_file = db_file
        self.engagement_path = db_file[:db_file.rfind("/") + 1]
        self.base_path = os.path.dirname(os.path.realpath(__file__)) + "/"
        if "/common/" in self.base_path:
            self.base_path = self.base_path.rstrip("/common/") + "/"
        self.key = ''

        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def db_execute_sql(self, sql):
        try:
            self.execute_sql(sql)
        except Exception as e:
            print_text.print_error("\tERROR 62 database object except: " + str(e))
            self.msg = self.msg + str(e) + "\n"

    def grab_column_from_single_record(self, table_name, filter_columns, filter_values, column_to_return):
        """Retrieves just the column_to_return for a single record."""
        try:
            info = self.get(table_name, filter_columns, filter_values, True)
            return info[column_to_return]
        except Exception as e:
            self.msg = self.msg + str(e) + "\n"
            return None

    #----------------------------- Pre-Defined Queries ------------------------------
    def base_off_live_hosts(self):
        """ Get if tools should only be based of live hosts (EngagementDevices w/ IP addresses). """
        return self.grab_column_from_single_record("Engagement", ['id'], [1], "base_results_off_live_hosts_ping")

    def external_only(self):
        """ Get if external ips only or not. """
        return self.grab_column_from_single_record("Engagement", ['id'], [1], "external_only")

    def rerun_tool(self):
        """ Get if allowed to rerun tools for targets already ran against. """
        return self.grab_column_from_single_record("Engagement", ['id'], [1], "rerun_tool")

    def tester_device_list(self, location_id):
        """ Grabs list of all tester device IPs at passed location. """
        return self.dictionary_list("TesterDevice", "tester_ip", ["location_id"], [int(location_id)], True)

    # Grab current location
    def grab_current_location(self):
        current_location =  self.grab_column_from_single_record("CurrentLocation", ["modified_by"], [self.current_tester], "current_location")
        #if current_location is None:
        #    locations = self.view("Location")
        #    current_location = locations[0]['name']
        return current_location

    # Grab all locations
    def grab_all_locations(self):
        return self.view("Location", ["name", "id"])

    # Grab location id from location name
    def grab_location_id_from_name(self, location_name):
        return self.grab_column_from_single_record("Location", ["name"], [location_name], "id")

    # Grab Engagement Number
    def grab_engagement_number(self):
        return self.grab_column_from_single_record("Engagement", ["id"], ["1"], "engagement_number")

    # Engagement Device IPs (LiveHosts)
    def grab_live_hosts(self):
        """Return All EngagementDevice IPs as List"""
        try:
            filter_columns = []
            filter_values = []
            # Check location to test setting to possible limit scope entries to just the location specified or all
            current_location = self.grab_current_location()
            if current_location is not None and current_location != "all_locations":
                filter_columns.append("Scope.location_id")
                filter_values.append(int(current_location))

            return_columns = ["target_ip", "id", "scope_id", "location_id"]
            join_tables = ["Scope.location_id"]
            list_of_dict = self.join_view("EngagementDevice", join_tables, return_columns, filter_columns,
                                               filter_values, True)

            # Make sure only return EngagementDevices that have valid IP & Group by scope_id
            already_found_ip = []
            groups = {}
            for lod in list_of_dict:
                ip = lod['target_ip']
                location_id = lod['location_id']
                if ip is not None and network.valid_ip(ip) and ip + str(location_id) not in already_found_ip:
                    already_found_ip.append(ip + str(location_id))
                    lod['entry'] = ip
                    if lod['scope_id'] in groups:
                        entry = lod['entry']
                        current_entry = groups[lod['scope_id']]['entry']
                        lod['entry'] = current_entry + " " + entry
                    groups[lod['scope_id']] = lod

            # now convert dictionary into list
            non_null_ip = [v for v in groups.values()]

            return non_null_ip
        except Exception as e:
            print_text.print_error("database_object.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    #------------------------ SCOPE Pre-Defined Queries -----------------------------
    def grab_ips(self):
        try:
            if self.base_off_live_hosts():
                print_text.print_msg("Engagement set to only target hosts from live hosts 'ping', so make sure that has "
                                     "been done first or you'll not get any targets to go after (or change the Engagement "
                                     "to not only go after live hosts).")
                return self.grab_live_hosts()
            else:
                return self.scope_ips()
        except Exception as e:
            print_text.print_error("database_object.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def add_scope_id_dictionary_value(self, dictionary_list):
        """
        Takes dictionary_list and for each dictionary adds 'scope_id' key/value
        :param dictionary_list:
        :return:
        """
        new_dictionary_list = []
        if dictionary_list is not None:
            for dl in dictionary_list:
                dl['scope_id'] = dl['id']
                new_dictionary_list.append(dl)
        return new_dictionary_list

    def recon_domains(self):
        try:
            types = ['DOMAIN', 'A']
            filter_columns = ["recon_type"]
            results = []
            for type in types:
                filter_values = [type]
                curr_results = self.view("Recon", ["scope_id", "record", "recon_type"], filter_columns, filter_values, True)
                if curr_results is not None:
                    results = results + curr_results
            domains = []
            for tr in results:
                domains.append[{'entry': tr['record'], 'scope_id': tr['scope_id']}]
                #"entry", "permission", "id", "location_id", "open_ip"]
        except Exception as e:
            print_text.print_error("database_object.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return domains

    def asn_records(self):
        """ ASN recon query filtered by type passed. """
        filter_columns = ["type"]
        filter_values = ['ASN']
        testing_location = self.grab_current_location()
        if testing_location != "all_locations":
            filter_columns.append("Scope.location_id")
            filter_values.append(testing_location)

        records = self.view("Recon", ["id", "type", "record", "scope_id", "Scope.location_id"], filter_columns, filter_values,
                      True)
        entries = []
        for r in records:
            entries.append({'scope_id':r['scope_id'], 'entry':r['record'], 'id':r['id'], 'location_id':r['location_id']})
        return entries

    def generic_scope(self, type):
        """ Sets up the Scope table query filtered by type passed. """
        try:
            filter_columns = ["type", "permission"]
            filter_values = [type, True]
            testing_location = self.grab_current_location()
            if testing_location is not None and testing_location != "all_locations" and testing_location != "None":
                filter_columns.append("location_id")
                filter_values.append(testing_location)
        except Exception as e:
            print_text.print_error("database_object.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return self.add_scope_id_dictionary_value(self.view("Scope", ["entry", "permission", "id", "location_id", "open_ip", "original_entry"], filter_columns, filter_values, True))

    def scope_ips(self):
        """Return All Scope IPs as List."""
        return self.generic_scope("IP")

    def scope_domains(self):
        """Return All Scope Domains as List of Dictionaries"""
        return self.generic_scope("DOMAIN")

    def scope_websites(self):
        """Return All Scope Websites as List"""
        return self.generic_scope("WEBSITE")

    def scope_all(self):
        """ Returns all scope entries"""
        return self.scope_ips() + self.scope_domains() + self.scope_websites()

    def scope_known_open(self, scope_id):
        try:
            scope_info =  self.get("Scope", ["id"], [scope_id])
            return scope_info['open_ip'], scope_info['open_port']
        except:
            return None, None

    #-------------------- End SCOPE Pre-Defined Queries -----------------------------

    #------------------------ LOG Pre-Defined Queries -------------------------------
    def log_record_by_id(self, log_id, print_message=None):
        """ Grab the record from using hashval. """
        try:
            return self.get("Log", ["id"], [log_id])
        except Exception as e:
            print("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def log_record_by_hashval(self, hashval, print_message=None):
        """ Grab the record from using hashval. """
        try:
            return self.get("Log", ["hashval"], [hashval])
        except Exception as e:
            print("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
            return None

    def log_not_finished(self, additional_column_filter=[], additional_column_value=[]):
        """Returns list of dictionaries of pid, target, start_time, source if end_time is blank."""
        list_of_columns_to_return = ["hashval", "pid", "target", "start_time", "source", "celery_info"]
        return self.view("Log", list_of_columns_to_return, ["end_time", "finished"]+additional_column_filter,
                                                                        ["", False]+additional_column_value, True)
    def log_failed(self, additional_column_filter=[], additional_column_value=[]):
        """ Return list of tool's that failed. """
        list_of_columns_to_return = ["hashval", "pid", "target", "start_time", "source", "comment", "end_time"]
        return self.view("Log", list_of_columns_to_return, ["failed"] + additional_column_filter,
                                                                             [True] + additional_column_value, True)

    def log_running(self, additional_column_filter=[], additional_column_value=[]):
        """ Return list of tool's that are running. """
        list_of_columns_to_return = ["id", "pid", "target", "command", "start_time", "source"]
        return self.view("Log", list_of_columns_to_return, ["running"] + additional_column_filter,
                                                                             [True] + additional_column_value, True)

    def log_queued(self, additional_column_filter=[], additional_column_value=[]):
        """ Return list of tool's that are queued. """
        list_of_columns_to_return = ["hashval", "pid", "target", "start_time", "source", "comment", "end_time", "finished", "id", "queued"]
        return self.view("Log", list_of_columns_to_return, ["queued"] + additional_column_filter,
                                                                             [True] + additional_column_value, True)

    def log_finished(self, source):
        """ Return list of tool's that finished. """
        list_of_columns_to_return = ["pid", "target", "end_time", "source", "scope_id", "location_id", "entry"]
        return self.join_view("Log", ["Scope.entry", "Scope.Location.name"], list_of_columns_to_return, ["source", "finished"],
                                                       [source, True], True)

    def log_finished_but_parse_failed(self, additional_column_filter=[], additional_column_value=[]):
        """ Return list of tool's that finished but parse failed. """
        list_of_columns_to_return = ["hashval", "pid", "target", "start_time", "source", "comment", "end_time"]
        return self.view("Log", list_of_columns_to_return, ["finished", "parsed"] + additional_column_filter,
                                                                             [True, False] + additional_column_value, True)

    def get_pid_and_hash_of_log_not_finished(self):
        """Returns a dictionary of pids and hashvals where the hashvals are the key and pid the value if end_time is blank."""
        return self.view("Log", ["hashval", "pid"], ["end_time", "failed"], [None, False], True)

    def get_column_of_logs_not_finished(self, column_name):
        """Return the column_name of all log entries that have a blank end_time, meaning not finished."""
        return self.dictionary_list("Log", column_name, ["end_time"], [None], True)

    def log_by_source(self, source):
        """Returns dictionary of all pids, targets, and end_time from passed source."""
        list_of_columns_to_return = ["pid", "target", "end_time", "source", "scope_id", "location_id", "entry",
                                     "finished", "allow_rerun", "running", "queued", "failed"]
        return self.join_view("Log", ["Scope.entry", "Scope.Location.name"], list_of_columns_to_return, ["source"], [source], True)

    def get_blacklisted_from_log(self):
        list_of_columns_to_return = ["pid", "target", "start_time", "blacklisted"]
        return self.view("Log", list_of_columns_to_return, ["blacklisted"], [True], True)

    def log_target_no_rerun(self, source):
        """ Grabs all targets in log entries for passed source that are not allowed to rerun. """
        list_of_columns_to_return = ["pid", "target", "end_time", "source", "scope_id", "location_id", "entry"]
        return self.join_view("Log", ["Scope.entry", "Scope.Location.name"], list_of_columns_to_return, ["source", "allow_rerun"], [source, False], True)

    def log_target_rerun(self, source):
        """ Grabs all targets in log entries for passed source that are allowed to rerun. """
        list_of_columns_to_return = ["pid", "target", "end_time", "source", "scope_id", "location_id", "entry"]
        return self.join_view("Log", ["Scope.entry", "Scope.Location.name"], list_of_columns_to_return, ["source", "allow_rerun"], [source, True], True)
    #--------------------- End LOG Pre-Defined Queries -------------------------------

    #---------------------- PortScan Pre-Defined Queries -----------------------------

    def portscan_rdp(self):
        """
        Retrieves all RDP servers from open ports in repository.
        :return:
        """
        try:
            rdp_servers_by_description = self.portscan_filter_by_description(r"rdp|mstsc", "tcp")
            rdp_servers_by_port_number = self.portscan_filter_by_port("3389", "tcp")
            rdp_servers_list = rdp_servers_by_description + rdp_servers_by_port_number

            already_done = []
            rdp_servers = []
            for rdp in rdp_servers_list:
                cur_location = str(rdp['location_id'])
                if rdp['ip'] + str(rdp['port']) + "-" + cur_location not in already_done:
                    already_done.append(rdp['ip'] + str(rdp['port']) + "-" + cur_location)

                    rdp['id'] = rdp['scope_id']
                    rdp['entry'] = rdp['ip']
                    rdp_servers.append(rdp)

            return rdp_servers
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return []

    def portscan_vnc(self):
        """
        Retrieve all VNC servers from open ports in repository
        :return:
        """
        try:
            vnc_servers_by_description = self.portscan_filter_by_description(r"vnc", "tcp")
            vnc_servers_by_port_number = self.portscan_filter_by_port("5900|5901|5902|5903|5904|5905", "tcp")
            vnc_servers_list = vnc_servers_by_description + vnc_servers_by_port_number

            already_done = []
            vnc_servers = []
            for vnc in vnc_servers_list:
                cur_location = str(vnc['location_id'])
                if vnc['ip'] + str(vnc['port']) + "-" + cur_location not in already_done:
                    already_done.append(vnc['ip'] + str(vnc['port']) + "-" + cur_location)

                    vnc['id'] = vnc['scope_id']
                    vnc['entry'] = vnc['ip']
                    vnc_servers.append(vnc)

            return vnc_servers
        except Exception as e:
            print_text.print_error(
                "database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return []


    def portscan_websites(self, ips_to_ignore=None):
        """
        Retrieves all websites identified through port scanning.
        Identifies websites based on Port number and Description.
        Combines 2 lists, removing duplicates.
        Formats the found websites and into List of strings (ex. http://10.193.103.47:835)

        :return: List of dicts of websites.
        """
        try:
            # Used to identify target name & needs to be used in case of virtual host issues by trying by IP
            engagement_devices = self.view("EngagementDevice", None, [], [], True, [('target_ip', 'asc'),])
            engagement_devices_dict = {}
            for ed in engagement_devices:
                if ed['target_ip'] is not None and ed['target_ip'] != "":
                    engagement_devices_dict[ed['target_ip']] = ed['target_name']

            website_list_by_description = self.portscan_filter_by_description("web|http|tomcat|iis|apache|nginx|proxy|www", "tcp")
            website_list_by_port_number = self.portscan_filter_by_port("80|443|8080|8081|8443", "tcp")
            website_list = website_list_by_description + website_list_by_port_number

            already_done = []
            websites = []
            for website in website_list:
                cur_location = str(website['location_id'])
                if website['ip'] + str(website['port']) + "-" + cur_location not in already_done and website['ip'] not in ips_to_ignore:
                    already_done.append(website['ip'] + str(website['port']) + "-" + cur_location)
                    port = ""
                    ip = website['ip'].strip()

                    # if public IP then try and use the target_name if not the IP in order to get valid results (in cases of virtual hosts)
                    if not network.is_private(ip) and ip in engagement_devices_dict:
                        ip = engagement_devices_dict[ip]

                    http_string = "http://"
                    if str(website['port']) == "443":
                        http_string = "https://"
                    if str(website['port']) != "443" and str(website['port']) != "80":
                        port = ":" + str(website['port']).strip()
                        website['entry'] = "https://" + ip + port
                        website['id'] = website['scope_id']
                        websites.append(website) #add for https and one below for http

                    website['id'] = website['scope_id']
                    website['entry'] = http_string + ip + port

                    websites.append(website)
            print("447 database_object websites: " + str(websites))

            return websites
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return []


    def portscan_filter_by_description(self, filter_description, protocol="tcp"):
        """ Grab all OpenPorts that are 'like' filter_description and protocol.
        Order query by scope_id then by port (some tools need this ordering)
        :param filter_description: str
        :param protocol: str
        :return: list of dictionaries of DevicePorts that contained filter description and passed protocol
        """
        try:
            list_of_columns_to_return = ["id", "scope_id", "ip", "port", "port_description", "protocol"]

            regexes = {'port_description': filter_description}
            filter_columns = []
            filter_values = []
            if protocol == "tcp":
                filter_columns.append("protocol")
                filter_values.append("tcp")
            elif protocol == "udp":
                filter_columns.append("protocol")
                filter_values.append("udp")

            join_tables = ["EngagementDevice.Scope.id"]

            # Check location to test setting to possible limit scope entries to just the location specified or all
            current_location = self.grab_current_location()
            if current_location != "all_locations":
                list_of_columns_to_return = None
                filter_columns.append("Scope.location_id")
                filter_values.append(int(current_location))
            return self.view_filter_regex("DevicePort", list_of_columns_to_return, filter_columns, filter_values,
                                   regexes, join_tables, sort=[('EngagementDevice.scope_id', 'asc'), ('port', 'asc')])
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def portscan_filter_by_port(self, filter_port_number, protocol="tcp"):
        """
        Finds all IPs that have specified filter_port_number open.
        Order query by scope_id then by port (some tools need this ordering)

        :param filter_port_number: the port to filter on
        :return: List of IPs that have the filter_port open.
        """
        list_of_columns_to_return = ["id", "scope_id", "ip", "port", "protocol"]

        #regexes = {'port': filter_port_number}

        filter_columns = []
        filter_values = []
        if protocol == "tcp":
            filter_columns.append("protocol")
            filter_values.append("tcp")
        elif protocol == "udp":
            filter_columns.append("protocol")
            filter_values.append("udp")

        # Check location to test setting to possible limit scope entries to just the location specified or all
        current_location = self.grab_current_location()
        if current_location != "all_locations":
            filter_columns.append("EngagementDevice.Scope.location_id")
            filter_values.append(int(current_location))

        port_string = str(filter_port_number)
        if "|" in port_string:
            open_ports = []
            ports = port_string.split("|")
            for port in ports:
                tmp_filter_columns = filter_columns
                tmp_filter_values = filter_values
                tmp_filter_columns.append("port")
                tmp_filter_values.append(port.strip())
                tmp_open_ports = self.join_view("DevicePort",
                                            ["EngagementDevice.Scope.id", "EngagementDevice.Scope.location_id"], None,
                                            tmp_filter_columns, tmp_filter_values, True,
                                            [('EngagementDevice.scope_id', 'asc'), ('port', 'asc')], None, True)
                open_ports = open_ports + tmp_open_ports
            return open_ports
        else:
            filter_columns.append("port")
            filter_values.append(port_string.strip())
            return self.join_view("DevicePort", ["EngagementDevice.Scope.id", "EngagementDevice.Scope.location_id"],
                                  None, filter_columns, filter_values, True,
                                  [('EngagementDevice.scope_id', 'asc'), ('port', 'asc')])

        #list_of_columns_to_return = None
        #join_tables = ["EngagementDevice.Scope.id"]
        #return self.view_filter_regex("DevicePort", list_of_columns_to_return, filter_columns, filter_values, regexes,
        #                              join_tables, sort=[('EngagementDevice.scope_id', 'asc'), ('port', 'asc')])

    #------------------- End PortScan Pre-Defined Queries ----------------------------

    #------------------------ Other Pre-Defined Queries ------------------------------
    def get_scope_id_by_entry(self, entry):
        """
        Lookup a entry to see if in Scope and if so grab its scope_id and location_id.
        :param entry:
        :return: tuple (scope_id, location_id)
        """
        scope_id = None
        location_id = None
        if network.valid_ip(entry):
            scope_ips = self.scope_ips()
            for scope_ip in scope_ips:
                # check if in network
                if network.check_in_network(scope_ip['entry'], entry):
                    scope_id = scope_ip['id']
                    location_id = scope_ip['location_id']
                    break
        else:
            scopes = self.scope_domains() + self.scope_websites()
            for scope in scopes:
                if entry == scope['entry']:
                    scope_id = scope['id']
                    location_id = scope['location_id']
                    break
        return scope_id, location_id


    def devices_smb_signing_disabled(self):
        """ Grab all devices that have SMB Signing Disabled finding/result. """
        try:
            findings = self.view("Result", None, ["finding_title"], ["SMB Signing Disabled"], True)
            devices = []
            for finding in findings:
                engagement_devices = self.join_view("EngagementDevice", ["Scope.Location.id"], None, ["id"],
                                                   [finding['engagementdevice_id'], True])
                engagement_device = engagement_devices[0]
                devices.append({'id': engagement_device['id'], 'entry': engagement_device['target_ip'], 'port': '445',
                                'ip': engagement_device['target_ip'], 'scope_id': engagement_device['scope_id'],
                                'location_id': engagement_device['location_id']})
            return devices
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def all_email_servers(self, domain=None, include_relay_servers=False):
        """
        Returns list of dictionaries of email servers.
        Grabs all smtp from Port scanning and from MX records.

        :return: List of dictionaries containing entry and port number of each email server.
        """
        try:
            if domain is not None and "@" in domain:
                domain = domain[domain.find("@")+1:]

            all_smtp_ports = self.portscan_filter_by_port("25|465|587", "tcp")

            list_of_columns_to_return = None
            mx_records = self.join_view("Recon", ["Scope.entry"], list_of_columns_to_return, ["recon_type"], ["MX"], True)
            mxs = []
            ips_to_ignore = []
            if mx_records is not None and len(mx_records) > 0:
                scope_id = mx_records[0]['scope_id']
                location_id = None
                for mx_record in mx_records:
                    if mx_record['associated_info'] is not None and network.valid_ip(mx_record['associated_info']):
                        ips_to_ignore.append(mx_record['associated_info'])
                    if domain is not None:
                        scope_entry = mx_record['entry']
                        if domain in scope_entry:
                            location_id = self.grab_column_from_single_record("Scope", ["id"], [mx_record['scope_id']], "location_id")
                            mxs.append({'id': mx_record['id'], 'entry': mx_record['record'], 'port': '25', 'scope_id': mx_record['scope_id'], 'location_id': location_id})
                    else:
                        location_id = self.grab_column_from_single_record("Scope", ["id"], [mx_record['scope_id']], "location_id")
                        mxs.append({'id': mx_record['id'], 'entry': mx_record['record'], 'port': '25', 'scope_id': mx_record['scope_id'], 'location_id': location_id})

                # Append relay.mail.cogentco.com
                # Check for emailfilter.yaml config file
                if include_relay_servers:
                    email_relay_servers = []
                    if os.path.isfile('tools/vuln/emailfilter.yaml'):
                        import yaml
                        yaml_config = yaml.safe_load(open('tools/vuln/emailfilter.yaml'))
                        if "email_relay_servers_to_bounce_emails_from" in yaml_config and yaml_config['email_relay_servers_to_bounce_emails_from'] != "":
                            if ";" in yaml_config['email_relay_servers_to_bounce_emails_from']:
                                email_relay_servers = yaml_config['email_relay_servers_to_bounce_emails_from'].split(";")
                            else:
                                email_relay_servers = [yaml_config['email_relay_servers_to_bounce_emails_from']]
                    if len(email_relay_servers) == 0:
                        # check if global var in enterprise_user_conf.py
                        try:
                            from enterprise_user_conf import EMAIL_RELAY_SERVERS_TO_BOUNCE_EMAILS_FROM
                            email_relay_server_string = EMAIL_RELAY_SERVERS_TO_BOUNCE_EMAILS_FROM
                            if ";" in email_relay_server_string:
                                email_relay_servers = email_relay_server_string.split(";")
                            else:
                                email_relay_servers = [email_relay_server_string]
                        except:
                            pass

                    for email_relay_server in email_relay_servers:
                        mxs.append({'id': 0, 'entry': email_relay_server, 'port': '25', 'scope_id': scope_id, 'location_id': location_id})

            portscan_smtp = []
            if all_smtp_ports is not None and len(all_smtp_ports) > 0:
                for smtp_port in all_smtp_ports:
                    if (smtp_port['port'] == "25" or smtp_port['port'] == "465" or smtp_port['port'] == "587") and smtp_port['ip'] not in ips_to_ignore: #ignore IPS that are already part of MX
                        #additional_keyvalue = {'entry': smtp_port['ip'], 'id': smtp_port['scope_id']}
                        #portscan_smtp.append({**smtp_port, **additional_keyvalue})
                        mxs.append({'id': smtp_port['scope_id'], 'entry': smtp_port['ip'], 'port': smtp_port['port'], 'scope_id': smtp_port['scope_id'], 'location_id': smtp_port['location_id']})
            email_servers = mxs#common.merge_two_lists_of_dicts(portscan_smtp, mxs, 'entry')

            return email_servers
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

    def all_email_servers_including_relays(self, domain=None):
        return self.all_email_servers(domain, True)

    def all_websites(self):
        """
        Retrieves list of all websites from all sources (port scanning, scope).

        :return: returns list of dictionary website entries.
        """
        try:
            website_scope_entries = self.scope_websites()

            wscope_entries = []
            ips_already_included = []
            if website_scope_entries is not None:
                for wse in website_scope_entries:
                    if wse['open_ip'] is not None and network.valid_ip(wse['open_ip']):
                        ips_already_included.append(wse['open_ip'])
                    port = "80"
                    entry = wse['entry']
                    if "https://" in entry:
                        port = "443"
                    no_http = entry[entry.find("://") + 3:]
                    if ":" in no_http:
                        port = common.regex_exist_in_entry(entry, r'[:]{1}[\d]+')
                        port = port.replace(":", "")
                    wse['port'] = port
                    wse['scope_id'] = wse['id']
                    wscope_entries.append(wse)

            deviceport_entries = self.portscan_websites(ips_already_included)
            if deviceport_entries is not None:
                all_webs= wscope_entries + deviceport_entries
            else:
                all_webs = wscope_entries

            return sorted(all_webs, key=itemgetter('id'))
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"

        return None

    def all_domain_controllers(self):
        """
        Retrieves list of all domain controllers from all sources port scanning.

        :return: returns list of dictionary DC entries.
        """
        try:
            dc_by_port_num = self.portscan_filter_by_port("88", "tcp")
            dc_by_udp_port_num = self.portscan_filter_by_port("389", "udp")

            already_done = []
            dcs = []
            if dc_by_port_num is not None:
                for dc in dc_by_port_num:
                    if dc['ip'] + dc['port'] not in already_done:
                        already_done.append(dc['ip'] + dc['port'])
                        dc['id'] = dc['scope_id']
                        dc['entry'] = dc['ip']
                        dcs.append(dc)
            if dc_by_udp_port_num is not None:
                for dc in dc_by_udp_port_num:
                    if dc['ip'] + dc['port'] not in already_done:
                        already_done.append(dc['ip'] + dc['port'])
                        dc['id'] = dc['scope_id']
                        dc['entry'] = dc['ip']
                        dcs.append(dc)

            return dcs
        except Exception as e:
            print_text.print_error("database object except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            self.msg = self.msg + str(e) + "\n"
        return []

        return None

    #--------------------- End Other Pre-Defined Queries ----------------------------

    # --------------------- Email Event Pre-Defined Queries ---------------------------
    def grab_client_contacts_to_send_notification(self):
        return self.dictionary_list("ClientContact", "email", ["real_time_notification"], [True], True)

    def grab_corp_contacts_to_send_notification(self):
        return self.dictionary_list("CorpContact", "email", ["real_time_notification"], [True], True)

    # --------------------- End Email Event Pre-Definied Queries ----------------------

