import sys
import datetime
from parsers. parser import Parser

def parse_secretsdump_file(ext, file_path, tool, modified_by, modified_date, scope_id, history=False):
    credential_list = []
    engagement_device = []
    if ext == "txt" or ext == "ntds":
        already_added_engagementdevice = []
        device = None
        with open(file_path, 'r') as secretsdump_file:
            for record in secretsdump_file:
                domain = "localhost"
                if "\\" in record:
                    device = record[:record.find("\\")]
                    domain = device
                    record = record[record.find("\\") + 1:]
                record_parts = record.split(":")
                username = record_parts[0]
                status = "current"
                if history and "_history" in username:
                    status = username[username.find("_history")+1:]
                    username = username[:username.find("_history")]
                hash_value = record_parts[2] + ":" + record_parts[3]
                hash_type = "ntlm"

                rid = record_parts[1]

                disabled = False
                if "(status=Disabled" in record:
                    disabled = True

                pwdlastset = None
                if "(pwdLastSet=" in record:
                    pwdlastset = record[record.find("(pwdLastSet=")+12:]
                    pwdlastset = pwdlastset[:pwdlastset.find(")")]
                    try:
                        pwdlastset = datetime.datetime.strptime(pwdlastset, '%Y-%m-%d %H:%M')
                    except:
                        pass

                pwdnotexpire = False
                da = False
                la = False

                if rid == "500" and domain == "localhost":
                    la = True
                elif rid == "500":
                    da = True

                if device is not None and device not in already_added_engagementdevice:
                    already_added_engagementdevice.append(device)
                    engagement_device.append(["", device, "", "", "", "", "", "", "", "",
                                              modified_by, modified_date, tool, scope_id])
                if device is not None:
                    credential_list.append([status, domain, username, None, False, hash_value, hash_type, None,
                                        disabled, pwdlastset, pwdnotexpire, da, la, tool, modified_by, device,
                                        None, None, "windows"])
    print("47 secretsdump_parser credential_list: " + str(credential_list))
    return engagement_device, credential_list

def domain_hashdump(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("secretsdump (domain pwdhashes)", db_object, key, hashvals, False) as p:
            p.parse("parsers.credential.secretsdump_parse", "SecretsDumpParse")

    except Exception as e:
        print("parser secretsdump (domain pwdhashes) 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class SecretsDumpParse():
    """ Parse SecretsDumpParse files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "secretsdump (domain pwdhashes)"
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
            engagement_device, credential_list = parse_secretsdump_file(self.ext, self.file_path, self.tool,
                                                            self.modified_by, self.modified_date, self.scope_id)

            output_dictionary = {}
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('hash_value', 'u'), ('hash_type', 'u')]
            output_dictionary["devices"] = engagement_device
            output_dictionary["devices_fields_to_update"] = [('mac', 'c')]

            return output_dictionary
        except Exception as e:
            print("secretsdump parser 86 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

# DOMAIN PASSWORD HISTORY
def domain_pwdhistory(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("secretsdump (domain pwdhistory)", db_object, key, hashvals, False) as p:
            p.parse("parsers.credential.secretsdump_parse", "SecretsDumpHistoryParse")

    except Exception as e:
        print("parser secretsdump (domain pwdhashes) 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

class SecretsDumpHistoryParse():
    """ Parse SecretsDumpHistoryParse files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "secretsdump (domain pwdhistory)"
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
            engagement_device, credential_list = parse_secretsdump_file(self.ext, self.file_path, self.tool,
                                                            self.modified_by, self.modified_date, self.scope_id, True)
            output_dictionary = {}
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('hash_value', 'u'), ('hash_type', 'u')]
            output_dictionary["devices"] = engagement_device
            output_dictionary["devices_fields_to_update"] = [('mac', 'c')]

            return output_dictionary
        except Exception as e:
            print("secretsdump parser 147 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}


# DOMAIN PASSWORD Last Set
def domain_pwdlastset(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("secretsdump (domain pwdlastset)", db_object, key, hashvals, False) as p:
            p.parse("parsers.credential.secretsdump_parse", "SecretsDumpLastSetParse")

    except Exception as e:
        print("parser secretsdump (domain pwdlastset) 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

class SecretsDumpLastSetParse():
    """ Parse SecretsDumpHistoryParse files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "secretsdump (domain pwdhistory)"
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
            engagement_device, credential_list = parse_secretsdump_file(self.ext, self.file_path, self.tool,
                                                            self.modified_by, self.modified_date, self.scope_id, True)
            output_dictionary = {}
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('hash_value', 'u'), ('hash_type', 'u'),
                                                                ('disabled', 'u'), ('pwdlastset', 'u')]
            output_dictionary["devices"] = engagement_device
            output_dictionary["devices_fields_to_update"] = [('mac', 'c')]

            return output_dictionary
        except Exception as e:
            print("secretsdump parser 147 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}

def local_hashdump(db_path, db_object, key, hashvals):
    """
    Loop thru hashvals, verify blacklist status, update Log, send to Parser, then finally email notifications out.
    :param db_path:
    :param db_object:
    :param hashvals:
    :return:
    """
    try:
        with Parser("secretsdump (local pwdhashes detail)", db_object, key, hashvals, False) as p:
            p.parse("parsers.credential.secretsdump_parse", "SecretsDumpLastSetLocalHashParse")

    except Exception as e:
        print("parser secretsdump (local pwdhashes detail) 23 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


class SecretsDumpLastSetLocalHashParse():
    """ Parse SecretsDumpLastSetLocalHashParse files. """
    def __init__(self, db_object, location_id, scope_id, file_path_name, ext, just_file_name, target, log_id, output_path, tester_device_list, modified_by, modified_date):

        if "/" in target:
            target = target.replace("/", "_")
        self.db_object = db_object
        self.output_path = output_path
        self.location_id = location_id
        self.scope_id = scope_id
        self.tool = "secretsdump (local pwdhashes detail)"
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
            engagement_device, credential_list = parse_secretsdump_file(self.ext, self.file_path, self.tool,
                                                            self.modified_by, self.modified_date, self.scope_id, True)
            output_dictionary = {}
            output_dictionary["credential"] = credential_list
            output_dictionary["credential_fields_to_update"] = [('hash_value', 'u'), ('hash_type', 'u'),
                                                                ('disabled', 'u'), ('pwdlastset', 'u')]
            output_dictionary["devices"] = engagement_device
            output_dictionary["devices_fields_to_update"] = [('mac', 'c')]

            return output_dictionary
        except Exception as e:
            print("secretsdump parser 147 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return {}