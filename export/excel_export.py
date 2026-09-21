import sys
from common import print_text
from export.excel_class import ExcelReport

class Excel():

    def __init__(self, db_object, full_client_engagement_path):
        try:
            self.db_object = db_object
            self.output_path = full_client_engagement_path

        except Exception as e:
            print_text.print_error("export excel except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def tab_data(self, excel_report, tab_name, entries, begin_column, header_row, filter_end_column):
        row_number = 0
        current_worksheet = excel_report.add_worksheet(tab_name)
        for row in entries:
            row_number += 1
            excel_report.row_data(current_worksheet, begin_column + str(row_number + 1), row)

        # Add header & autofilter
        excel_report.header(current_worksheet, 0, header_row)
        filter_range = 'A' + str(1) + ":" + filter_end_column + str(row_number + 1)
        excel_report.autofilter(current_worksheet, filter_range)

    def tab_sort(self, excel_report, table_name, join_tables=None):
        try:
            table_rows = self.data(table_name, join_tables)

            ftp = []
            ssh = []
            http = []
            smb = []
            rdp = []
            netbios = []
            rpc = []
            snmp = []
            dns = []
            telnet = []
            email = []
            vnc = []
            ipsec = []
            remaining = []
            header_row = ['Scope', 'Location', 'IP', 'Port', 'Protocol', 'Description', 'Source', "DNS Name"]

            if len(table_rows) > 0:
                filter_end_column = excel_report.convert_to_excel_range(len(header_row) - 1)
                begin_column = excel_report.convert_to_excel_range(0)
                for table_row in table_rows:
                    port = int(table_row['port'])
                    description = table_row['description']
                    if description is None:
                        description = ""
                    protocol = table_row['protocol']

                    dns_name = self.db_object.grab_column_from_single_record("Recon", ["associated_info"], [table_row['ip']], "record")
                    if dns_name is None:
                        dns_name = ""

                    if ("ftp" in description.lower() or port == 21) and protocol.lower() == "tcp":
                        ftp.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("ssh" in description.lower() or port == 22) and protocol.lower() == "tcp":
                        ssh.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("http" in description.lower() or "iis" in description.lower() or "tomcat" in description.lower() or\
                                    "nginx" in description or "web" in description.lower() or \
                                    "apache" in description.lower() or port == 80 or port == 443) and protocol.lower() == "tcp":
                        http.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("smb" in description.lower() or port == 445) and protocol.lower() == "tcp":
                        smb.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("rdp" in description.lower() or port == 3389) and protocol.lower() == "tcp":
                        rdp.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("netbios" in description.lower() or port == 139 or port == 138) and protocol.lower() == "tcp":
                        netbios.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("rpc" in description.lower() or port == 135) and protocol.lower() == "tcp":
                        rpc.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("smtp" in description.lower() or port == 25 or port == 465 or port == 587 or
                                  "pop3" in description.lower() or "imap" in description.lower() or port == 110 or
                          port ==143 or port == 993 or port == 995) and protocol.lower() == "tcp":
                        email.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("snmp" in description.lower() or port == 161) and protocol.lower() == "udp":
                        snmp.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif "dns" in description.lower() or port == 53:
                        dns.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("telnet" in description.lower() or port == 23) and protocol.lower() == "tcp":
                        telnet.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("vnc" in description.lower() or port == 5900) and protocol.lower() == "tcp":
                        vnc.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    elif ("isakmp" in description.lower() or port == 500) and protocol.lower() == "udp":
                        ipsec.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                    table_row['protocol'], description, table_row['source'], dns_name])
                    else:
                        remaining.append([table_row['entry'], table_row['name'], table_row['ip'], table_row['port'],
                                      table_row['protocol'], description, table_row['source'], dns_name])

                if len(ftp) > 0:
                    self.tab_data(excel_report, "FTP Servers", ftp, begin_column, header_row, filter_end_column)
                if len(ssh) > 0:
                    self.tab_data(excel_report, "SSH Servers", ssh, begin_column, header_row, filter_end_column)
                if len(http) > 0:
                    self.tab_data(excel_report, "Web Servers", http, begin_column, header_row, filter_end_column)
                if len(smb) > 0:
                    self.tab_data(excel_report, "SMB Servers", smb, begin_column, header_row, filter_end_column)
                if len(netbios) > 0:
                    self.tab_data(excel_report, "NetBios Servers", netbios, begin_column, header_row, filter_end_column)
                if len(rpc) > 0:
                    self.tab_data(excel_report, "RPC / PortMapper Servers", rpc, begin_column, header_row, filter_end_column)
                if len(rdp) > 0:
                    self.tab_data(excel_report, "RDP Servers", rdp, begin_column, header_row, filter_end_column)
                if len(snmp) > 0:
                    self.tab_data(excel_report, "SNMP Servers", snmp, begin_column, header_row, filter_end_column)
                if len(dns) > 0:
                    self.tab_data(excel_report, "DNS Servers", dns, begin_column, header_row, filter_end_column)
                if len(telnet) > 0:
                    self.tab_data(excel_report, "Telnet Servers", telnet, begin_column, header_row, filter_end_column)
                if len(email) > 0:
                    self.tab_data(excel_report, "Email Servers", email, begin_column, header_row, filter_end_column)
                if len(vnc) > 0:
                    self.tab_data(excel_report, "VNC Servers", vnc, begin_column, header_row, filter_end_column)
                if len(ipsec) > 0:
                    self.tab_data(excel_report, "IPSec Servers", ipsec, begin_column, header_row, filter_end_column)
                if len(remaining) > 0:
                    self.tab_data(excel_report, "Other", remaining, begin_column, header_row, filter_end_column)
        except Exception as e:
            print_text.print_error("export excel except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def data(self, table_name, join_tables, filter_columns=None, filter_values=None, equal=None):
        if join_tables is None:
            return self.db_object.view(table_name, None, filter_columns, filter_values, equal)
        return self.db_object.join_view(table_name, join_tables, None, filter_columns, filter_values, equal)


    def tab(self, excel_report, tab_name, table_name, columns_to_return, header_row, join_tables=None, filter_columns=None, filter_values=None, equal=None):
        try:
            current_worksheet = excel_report.add_worksheet(tab_name)
            table_rows = self.data(table_name, join_tables, filter_columns, filter_values, equal)

            filter_end_column = None
            row_number = 0
            if table_rows is not None and len(table_rows) > 0:
                filter_end_column = excel_report.convert_to_excel_range(len(header_row) - 1)
                begin_column = excel_report.convert_to_excel_range(0)
                for table_row in table_rows:
                    row = []
                    for col in columns_to_return:
                        row.append(table_row[col])
                    row_number += 1
                    excel_report.row_data(current_worksheet, begin_column + str(row_number + 1), row)

                # Add header & autofilter
                excel_report.header(current_worksheet, 0, header_row)
                filter_range = 'A' + str(1) + ":" + filter_end_column + str(row_number + 1)
                excel_report.autofilter(current_worksheet, filter_range)
            else:
                excel_report.row_data(current_worksheet, 'A1', ['There are no ' + tab_name + ' entries.'])
        except Exception as e:
            print_text.print_error("export excel except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def export(self, naming_convention=None):
        """
        Main function called that calls ExcelReport class to generate the report
        """
        try:
            if naming_convention is None:
                naming_convention = "report.xlsx"
            with ExcelReport(self.output_path + naming_convention) as excel_report:
                # Scope tab
                header_row = ['Original Entry', 'Entry', 'Type', 'Location', 'Permission', 'Information',
                              'Description', 'Additional Info']
                columns = ["original_entry", "entry", "type", "name", "permission", "information", "description",
                           "additional"]
                self.tab(excel_report, "Scope", "Scope", columns, header_row, ["Location.name"])

                # Results by Vuln
                header_row = ['Location', 'Device', 'Port', 'Protocol', 'Title', 'Output', 'Tester Output', 'Description', 'Remediation',
                              'CVSS', 'Severity', 'Classification', 'Exploits Available', 'Patch Publication Date',
                              'Scope', 'Tool']
                columns = ["name", "target", "port", "protocol", "finding_title", "output", "tester_output", "finding_description",
                           "finding_remediation", "finding_cvss", "finding_severity", "finding_classification",
                           "finding_exploits_available", "finding_patch_publication_date", "entry", "tool"]
                self.tab(excel_report, "Results", "Result", columns, header_row, ["EngagementDevice.Scope.Location.name", "EngagementDevice.Scope.entry"])

                # Recon tab
                header_row = ['Scope', 'Record', 'Type', 'Info', 'Associated Info', 'Description', 'Organization', 'Tool']
                columns = ["entry", "record", "recon_type", "info", "associated_info", "description", "organization", "source"]
                self.tab(excel_report, "Recon", "Recon", columns, header_row, ["Scope.entry"])

                # Person tab
                header_row = ['Location', 'Organization', 'Name', 'Email', 'Info', 'Associated Info', 'Description', 'Title',
                              'Phone', 'Address', 'Vendor', 'Client', 'Tool']
                columns = ["name", "organization", "full_name", "email", "person_info", "associated_info", "person_description",
                           "title", "phone", "full_address", "vendor", "client", "source"]
                self.tab(excel_report, "Person", "Person", columns, header_row, ["Location.name"])

                # Devices tab
                header_row = ['Scope', 'Location', 'Device', 'IP', 'OS', 'Domain', 'MAC', 'Info', 'Services',
                              'Programs', 'Accounts', 'Tool']
                columns = ["entry", "name", "target_name", "target_ip", "os", "domain", "mac", "info", "services", "programs",
                           "accounts", "source"]
                self.tab(excel_report, "Device", "EngagementDevice", columns, header_row, ["Scope.entry", "Scope.Location.name"])

                # Open ports tab
                header_row = ['Scope', 'Location', 'IP', 'Port', 'Protocol', 'Description', 'Source']
                columns = ["entry", "name", "ip", "port", "protocol", "description", "source"]
                self.tab(excel_report, "All Open Port", "DevicePort", columns, header_row, ["EngagementDevice.Scope.entry", "EngagementDevice.Scope.Location.name"])

                # Open ports grouped by Port #
                self.tab_sort(excel_report, "DevicePort", ["EngagementDevice.Scope.entry", "EngagementDevice.Scope.Location.name"])

                # Log tab
                header_row = ['Scope', 'Location', 'Device', 'Source', 'Start Time', 'End Time', 'Blacklisted', 'Comment']
                columns = ["entry", "name", "target", "source", "start_time", "end_time", "blacklisted", "comment"]
                self.tab(excel_report, "Logging", "Log", columns, header_row, ["Scope.entry", "Scope.Location.name"])

        except Exception as e:
            print_text.print_error("export excel except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

