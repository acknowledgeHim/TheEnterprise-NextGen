import sys
import time
import webbrowser
from lxml import etree
from common import print_text, dns_functions
from common import common, network, keep_tags
from parsers. parser import Parser

def metagoofil_parser(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("metagoofil", db_object, key, hashvals, False) as p:
            p.parse("parsers.recon.metagoofil_parser", "MetagoofilParser")

    except Exception as e:
        print("metagoofil parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class MetagoofilParser():
    """ Parse metagoofilParser files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "metagoofil"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

        domain = self.file_path[self.file_path.rfind("__") + 2:]
        self.domain = domain[:domain.rfind(".txt")]

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .html files. """
        try:
            people_list = []
            result_list = []

            if self.ext == "html":

                filenames_dict = {}

                # Need to associate filenames with data found
                with open(self.file_path, 'r', errors='ignore') as f:
                    html_text = f.read()
                    if "Files and metadata found:" in html_text:
                        files_section = html_text[html_text.find("Files and metadata found:"):]
                        files_section = files_section[:files_section.find("Failed extractions and reasons")]
                        files_info = files_section.split("<h3>").pop()  # remove files and metadata found part
                        for file_info in files_info:
                            filename = None
                            if "<h3>" in file_info:
                                filename = keep_tags.clean_text(file_info[:file_info.find("</h3>")])
                            if filename is not None:
                                info_section = keep_tags.clean_text(file_info)
                                infos = info_section.split("<pre>").pop()  # remove the 1st one which will be junk
                                entries = []
                                for data in infos:
                                    data = keep_tags.clean_text(data)
                                    entries.append(data)
                                filenames_dict[filename] = entries

                with open(self.file_path, 'r', errors='ignore') as f:
                    html_text = f.read()

                    if "User names found:" in html_text:
                        username_section = html_text[html_text.find("User names found:"):]
                        username_section = username_section[username_section.find("<ul>"):]
                        username_section = username_section[:username_section.find("</ul>")]
                        users = username_section.split("</li>")
                        print("93 metagoo parser users: " + str(users))
                        for user in users:
                            user_name = keep_tags.clean_text(user)
                            filename = None
                            for key, value in filenames_dict:
                                for data in value:
                                    if data == user_name:
                                        filename = key
                                        break
                                if filename is not None:
                                    break
                            if filename is not None:
                                people_list.append([self.location_id, user_name, None, None, None, None, None, "", "", "",
                                                False, False, self.tool + " - " + filename, self.modified_by, self.modified_date])
                    if "E-mails found:" in html_text:
                        email_section = html_text[html_text.find("E-mails found:"):]
                        email_section = email_section[email_section.find("<ul>"):]
                        email_section = email_section[:email_section.find("</ul>")]
                        emails = email_section.split("</li>")
                        print("112 metagoo parser emails: " + str(emails))
                        for email in emails:
                            email_address = keep_tags.clean_text(email)
                            filename = None
                            for key, value in filenames_dict:
                                for data in value:
                                    if data == email_address:
                                        filename = key
                                        break
                                if filename is not None:
                                    break
                            if filename is not None:
                                people_list.append([self.location_id, "", email_address, None, None, None, None, "", "", "",
                                                False, False, self.tool + " - " + filename, self.modified_by, self.modified_date])

                    if "Software versions found:" in html_text:
                        software_section = html_text[html_text.find("Software versions found:"):]
                        software_section = software_section[software_section.find("<ul>"):]
                        software_section = software_section[:software_section.find("</ul>")]
                        softwares = software_section.split("</li>")
                        print("132 metagoo parser softwares: " + str(softwares))
                        for software in softwares:
                            software_version = keep_tags.clean_text(software)
                            filename = None
                            for key, value in filenames_dict:
                                for data in value:
                                    if data == software_version:
                                        filename = key
                                        break
                                if filename is not None:
                                    break
                            if filename is not None:
                                result_list.append(
                                    [self.tool, "metagoofil_sofwareversion_detected", filename, "0", "tcp", software_version,
                                     "", self.modified_date, self.modified_date, "metagoofil.py",
                                     "Metadata leaked sensitive information", "Metadata that is stored with files contains "
                                    "potentially sensitive information, including: usernames, sofware versions, emails, "
                                    "and server paths.  This information can help an attacker better plan or execute an "
                                    "attack.", "Either clear out this metadata or utilize generic stock metadata that does "
                                    "not contain sensitive information.", "0.0", "low", "configuration", "", "",
                                     self.modified_by])

                    if "Servers and paths found:" in html_text:
                        serverpath_section = html_text[html_text.find("Servers and paths found:"):]
                        serverpath_section = serverpath_section[serverpath_section.find("<ul>"):]
                        serverpath_section = serverpath_section[:serverpath_section.find("</ul>")]
                        serverpaths = serverpath_section.split("</li>")
                        for server_path in serverpaths:
                            path = keep_tags.clean_text(server_path)
                            filename = None
                            for key, value in filenames_dict:
                                for data in value:
                                    if data == path:
                                        filename = key
                                        break
                                if filename is not None:
                                    break
                            if filename is not None:
                                result_list.append(
                                    [self.tool, "metagoofil_server_path_detected", filename, "0", "tcp", path,
                                     "", self.modified_date, self.modified_date, "metagoofil.py",
                                     "Metadata leaked sensitive information", "Metadata that is stored with files contains "
                                    "potentially sensitive information, including: usernames, sofware versions, emails, "
                                    "and server paths.  This information can help an attacker better plan or execute an "
                                    "attack.", "Either clear out this metadata or utilize generic stock metadata that does "
                                    "not contain sensitive information.", "0.0", "low", "configuration", "", "",
                                     self.modified_by])

                    # Now have to match up the file with the data extracted
                    """
                    if "Files and metadata found:" in html_text:
                        files_section = html_text[html_text.find("Files and metadata found:"):]
                        files_section = files_section[:files_section.find("Failed extractions and reasons")]
                        files_info = files_section.split("<h3>").pop() # remove files and metadata found part
                        for file_info in files_info:
                            filename = None
                            if "<h3>" in file_info:
                                filename = keep_tags.clean_text(file_info[:file_info.find("</h3>")])
                            if filename is not None:
                                info_section = keep_tags.clean_text(file_info)
                                infos = info_section.split("<pre>").pop() # remove the 1st one which will be junk
                                for data in infos:
                                    data = keep_tags.clean_text(data)
                                    # check if in people_list
                                    for p in tmp_people_list:
                                        if data == p[1]:
                                            p[12] = p[12] + " - " + filename
                                            people_list.append(p)
                                        elif data == [2]:
                                            p[12] = p[12] + " - " + filename
                                            people_list.append(p)
                                    # check if in result
                                    for r in tmp_result_list:
                                        if data == r[5]:
                                            r[2] = filename
                                            result_list.append(r)
                    """
                output_dictionary = {}
                if len(people_list) > 0:
                    output_dictionary["person"] = people_list
                    output_dictionary["person_fields_to_update"] = [('person_info', 'c'), ('organization', 'c'),
                                                                    ('person_description', 'c'), ('title', 'c'),
                                                                    ('name', 'c'), ('email', 'c'),
                                                                    ('associated_info', 'c')]
                    output_dictionary["result"] = result_list
                    output_dictionary["result_fields_to_update"] = [('output', 'a')]

                # Try and open html report in web browser
                webbrowser.open(self.file_path)
                print("76 metagoofil parser output_dictionary: " + str(output_dictionary))
                return output_dictionary
            else:
                print_text.print_error("Unsupported file for parsing found, skipping it!")
                return {}
        except Exception as e:
            print("metagoofil parser 92 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
