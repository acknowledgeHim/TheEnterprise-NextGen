import sys
from common import print_text
from common import network

def engagementdevice_to_dict(db_object, scope_id=None):
    """ Maps all engagement devices in DB per scope to dict for quick lookup. """
    try:
        ed_infos = []
        filter_columns = None
        filter_values = None
        if scope_id is not None:
            filter_columns = ["scope_id"]
            filter_values = [int(scope_id)]
        ed_infos = db_object.view("EngagementDevice", None, filter_columns, filter_values, True)

        edevices_ip = {}
        edevices = {}
        if ed_infos is not None:
            ed_infos = list(ed_infos)
            for ei in ed_infos:
                edevices[ei["target_name"].lower()] = ei["id"]
                if ei["target_ip"] is not None:
                    edevices_ip[ei["target_ip"].lower()] = ei["id"]

        return edevices, edevices_ip
    except Exception as e:
        print_text.print_error("models_to_dict except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def open_ports_to_dict(db_object, engagementdevice_id):
    """ Maps all open ports of engagement device in DB for per engagementdevice to dict for quick lookup. """
    try:
        filter_columns = None
        filter_values = None
        if engagementdevice_id is not None:
            filter_columns = ["engagementdevice_id"]
            filter_values = [int(engagementdevice_id)]
        infos = db_object.view("DevicePort", None, filter_columns, filter_values, True)

        dictionary_values = {}
        if infos is not None:
            infos = list(infos)
            for info in infos:
                dictionary_values[str(info["engagementdevice_id"])] = info["id"]

        return dictionary_values
    except Exception as e:
        print_text.print_error("models_to_dict except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def same_ip_scope(db_object, scope_id):
    try:
        filter_columns = None
        filter_values = None
        if scope_id is not None:
            filter_columns = ["scope_id"]
            filter_values = [int(scope_id)]
        infos = db_object.view("EngagementDevice", None, filter_columns, filter_values, True)

        dictionary_values = {}
        if infos is not None:
            infos = list(infos)
            for info in infos:
                if info['target_ip'] is not None and network.valid_ip(info['target_ip']):
                    dictionary_values[str(info["scope_id"])+":"+str(info['target_ip'])] = [info["id"], info['target_name']]

        return dictionary_values
    except Exception as e:
        print_text.print_error("models_to_dict except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def mx_records_by_scope_dictionary(db_object, scope_id=None):
    try:
        filter_columns = None
        filter_values = None
        if scope_id is not None:
            filter_columns = ["recon_type"]
            filter_values = ['MX']
        infos = db_object.view("Recon", None, filter_columns, filter_values, True)
        dictionary_values = {}
        if infos is not None:
            infos = list(infos)
            for info in infos:
                if info['record'] is not None and info['recon_type'].lower() == "mx":
                    if str(info["scope_id"]) in dictionary_values:
                        dictionary_values[str(info["scope_id"])].append(info["record"])
                    else:
                        dictionary_values[str(info["scope_id"])] = [info["record"]]

        return dictionary_values
    except Exception as e:
        print_text.print_error("models_to_dict except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

def scope_dict(db_object, type):
    try:
        # type is IP, DOMAIN, or WEBSITE
        filter_columns = None
        filter_values = None
        infos = db_object.view("Scope", None, ['type'], [type], True)

        dictionary_values = {}
        if infos is not None:
            infos = list(infos)
            for info in infos:
                entry = info['entry']
                if entry is not None:
                    if type == "IP":
                        if "/" in entry:
                            entry = entry[:entry.find("/")]
                    elif entry.count(".") > 1: # get base domain
                        while entry.count(".") > 1:
                            entry = entry[entry.find(".")+1:]
                    dictionary_values[str(entry)] = [info["id"]]

        return dictionary_values
    except Exception as e:
        print_text.print_error("models_to_dict except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))