import sys
from common import print_text, network
from parsers import models_to_dictionary

class OpenPortFinding():
    def __init__(self, db_object, modified_by, scope_id, location_id):
        """
        Checks if open port is a finding.
        :param db_object:
        :param modified_by:
        :param scope_id:
        :param location_id:
        """
        self.db_object = db_object
        self.modified_by = modified_by
        self.scope_id = scope_id
        self.location_id = location_id

        self.login_services = ["tcp22", "tcp23", "tcp3389", "tcp21", "tcp5900"]

        self.create_finding_for_internet_openport = self.db_object.grab_column_from_single_record("Engagement", ['id'], [1], "create_finding_for_internet_openport")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self


    def open_services_finding_result(self, already_found_result, result_list, ip, port, protocol, full_description,
                                     start_time, end_time, tool_name):
        """ Checks for known Result findings based. """
        try:
            if self.create_finding_for_internet_openport:
                # Add VulnDef Result for Internet Accessible authentication prompt
                if (protocol + port in self.login_services or (full_description is not None and ("telnet" in full_description.lower() or \
                                "ssh" in full_description.lower()))) and not network.private_ip(ip):
                    title = "Internet accessible authentication prompt"
                    plugin_id = tool_name+"-iaap"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result, result_list,
                                                    plugin_id, ip, port, protocol, start_time, end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                # Add VulnDef Result for Unencrypted Telnet service
                if protocol.lower() + port == "tcp23" or (full_description is not None and "telnet" in full_description.lower()):
                    title = "Unencrypted Telnet service"
                    plugin_id = tool_name + "-telnet_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                # Add VulnDef Result for Unencrypted file transfer protocol
                if (protocol.lower() + port == "tcp21" or (full_description is not None and "ftp" in full_description.lower() and "tftp" not in full_description.lower()) ) and protocol.lower() == "tcp":
                    """ Add findings / vulndef for unencrypted file transfer protocol. """
                    title = "Unencrypted file transfer protocol"
                    plugin_id = tool_name + "-ftp_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result, result_list, plugin_id, ip, port, protocol, start_time, end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                # Add VulnDef Result for Unencrypted TFTP service
                if protocol.lower() == "udp" and port == "69":
                    title = "Unencrypted trival file transfer protocol (TFTP)"
                    plugin_id = tool_name + "-tftp_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                    result_list, plugin_id, ip, port, protocol,
                                                                    start_time, end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                # Add VulnDef Result for email service was accessible from the internet
                if (protocol.lower() + port == "tcp25" or (full_description is not None and ("smtp" in full_description.lower() or "mail" in full_description)) ) \
                        and not network.private_ip(ip):
                    title = "Email service was accessible from the internet"
                    plugin_id = tool_name + "-email_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                # Add VulnDef Result for remote desktop protocol
                if protocol.lower() + port == "tcp3389" and not network.private_ip(ip):
                    title = "Remote Desktop Protocol (RDP) accessible from the internet"
                    plugin_id = tool_name + "-rdp_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                """
                # Add VulnDef Result for unnecessary windows services
                if (protocol.lower() + port == "tcp53" or protocol.lower() + port == "udp53" or \
                                    protocol.lower() + port == "tcp135" or protocol.lower() + port == "tcp137" or \
                                    protocol.lower() + port == "tcp139" or protocol.lower() + port == "tcp445" or \
                                    protocol.lower() + port == "tcp1025") and not network.private_ip(ip):
                    title = "Unnecessary Windows services accessible from the internet"
                    plugin_id = tool_name + "-windows_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list
                """
                if (protocol.lower() + port == "udp137" or protocol.lower() + port == "tcp138" or protocol.lower() + port == "tcp139") and not network.private_ip(ip):
                    title = "NetBIOS service accessible from the internet"
                    plugin_id = tool_name + "-netbios_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                if protocol.lower() + port == "tcp135" and not network.private_ip(ip):
                    title = "RPC Endpoint Mapper service accessible from the internet"
                    plugin_id = tool_name + "-portmapper_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                if protocol.lower() + port == "tcp88" and not network.private_ip(ip):
                    title = "LDAP service accessible from the internet"
                    plugin_id = tool_name + "-ldap_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                if protocol.lower() + port == "tcp445" and not network.private_ip(ip):
                    title = "SMB service accessible from the internet"
                    plugin_id = tool_name + "-smb_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                if protocol.lower() + port == "tcp1433" and not network.private_ip(ip):
                    title = "Microsoft SQL service accessible from the internet"
                    plugin_id = tool_name + "-mssql_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                if protocol.lower() + port == "tcp3306" and not network.private_ip(ip):
                    title = "MySQL service accessible from the internet"
                    plugin_id = tool_name + "-mysql_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

                # Add VulnDef Result for SNMP service enabled from the internet
                if protocol.lower() + port == "udp161" and not network.private_ip(ip):
                    title = "SNMP service accessible from the internet"
                    plugin_id = tool_name + "-snmp_safti"
                    tmp_already_found_result, tmp_result_list = self.add_finding_result(already_found_result,
                                                                                        result_list, plugin_id, ip,
                                                                                        port, protocol, start_time,
                                                                                        end_time, title, tool_name)
                    if tmp_already_found_result is not None:
                        already_found_result = tmp_already_found_result
                    if tmp_result_list is not None:
                        result_list = tmp_result_list

        except Exception as e:
            print_text.print_error("Parser finding_for_open_port 141 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return already_found_result, result_list

    def add_finding_result(self, already_found_result, result_list, plugin_id, ip, port, protocol, start_time, end_time, title, tool):
        try:
            # Add to Result
            if str(self.scope_id) + title + ip + protocol + port not in already_found_result:
                already_found_result.append(str(self.scope_id) + title + ip + protocol + port)
                command = plugin_id

                result_list.append([tool, plugin_id, ip, port, protocol, None, None,
                                           start_time, end_time, command, title, None, None, None, None, None, None,
                                           None, self.modified_by])
        except Exception as e:
            print("Parser 507 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return already_found_result, result_list