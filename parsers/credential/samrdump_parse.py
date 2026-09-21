import sys
import datetime
from parsers. parser import Parser

def parse_file(ext, file_path, tool, modified_by, modified_date, scope_id):
    try:
        credential_list = []
        engagement_device = []
        if ext == "txt":
            already_added_engagementdevice = []
            local_admin_group = None
            # 1st loop through and find local "Administrator" account and get its primary group id to see who else is
            #  in that group is therefore is local admin
            with open(file_path, 'r') as samrdump_file:
                for record in samrdump_file:
                    if "," in record and record.count(',') == 10 and "#Name," not in record:
                        parts = record.split(",")
                        if parts[1] == "500":
                            local_admin_group = parts[3]

            with open(file_path, 'r') as samrdump_file:
                for record in samrdump_file:
                    if "," in record and record.count(',') == 10 and "#Name," not in record:
                        device = None
                        if "__s" in file_path:
                            device = file_path[file_path.rfind("/")+1:]
                            device = device[:device.find("__")]
                        record_parts = record.split(",")
                        username = record_parts[0]
                        status = "current"
                        hash_value = None
                        hash_type = "ntlm"

                        disabled = False
                        if record_parts[8] == "TRUE":
                            disabled = True

                        pwdlastset = None
                        if record_parts[6] != "<never>":
                            pwdlastset = record_parts[6]
                            pwdlastset = pwdlastset[:pwdlastset.find(")")]
                            pwdlastset = datetime.datetime.strptime(pwdlastset, '%Y-%m-%d %H:%M:%S')

                        pwdnotexpire = False
                        if record_parts[7] == "TRUE":
                            pwdnotexpire = True

                        da = False
                        la = False
                        if record_parts[1] == "500" or (local_admin_group is not None and local_admin_group == record_parts[3]):
                            la = True

                        comment = record_parts[9]
                        additional = "Bad password count: " + record_parts[4] + ".  " + record_parts[10].rstrip()

                        if device is not None and device not in already_added_engagementdevice:
                            already_added_engagementdevice.append(device)
                            engagement_device.append(["", device, "", "", "", "", "", "", "", "",
                                                      modified_by, modified_date, tool, scope_id])
                        credential_list.append([status, None, username, None, False, hash_value, hash_type, None,
                                                disabled, pwdlastset, pwdnotexpire, da, la, tool, modified_by, device,
                                                comment, additional, "windows"])

        return engagement_device, credential_list
    except Exception as e:
        print("parser samrdump (local account detail) parser 64 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def local_parse(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("samrdump (local account detail)", db_object, key, hashvals, False) as p:
            p.parse("parsers.credential.samrdump_parse", "SamrDumpParse")

    except Exception as e:
        print("parser samrdump (local account detail) parser 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class SamrDumpParse():
    """ Parse SamrDumpParse files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "samrdump (local account detail)"
        self.target = target
        self.log_id = log_id
        self.ext = ext
        self.tester_device_list = tester_device_list
        self.file_path = file_path_name
        self.file_name = just_file_name
        self.modified_by = modified_by
        self.modified_date = modified_date

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def parse(self):
        """ Parse .txt files. """
        try:
            engagement_device, credential_list = parse_file(self.ext, self.file_path, self.tool,
                                                            self.modified_by, self.modified_date, self.scope_id)

            output_dictionary = {}
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('pwdnotexpire', 'u'), ('disabled', 'u')]
            output_dictionary["devices"] = engagement_device
            output_dictionary["devices_fields_to_update"] = [('ip', 'c')]

            return output_dictionary
        except Exception as e:
            print("samrdump (local account detail) parser 86 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}
