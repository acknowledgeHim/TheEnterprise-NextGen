import sys
from common import network, print_text

def valid_host_name(ip, host_name):
    ip_parts = ip.split(".")
    reverse_ip = ".".join(reversed(ip_parts))

    if ip not in host_name and ip.replace(".", "-") not in host_name and reverse_ip not in host_name \
            and reverse_ip.replace(".", "-") not in host_name:
        return True

    return False


def merge_devices(db_object, similar_devices):
    try:
        # used to auto merge engagementdevices
        best_os = ""
        best_domain = ""
        best_mac = ""
        best_info = ""
        best_target_name = ""
        best_services = ""
        best_accounts = ""
        best_programs = ""
        keep_id = similar_devices[0]

        # Loop through to determine best values to keep
        for count, d in enumerate(similar_devices):
            reverse_ip = None
            ip = d['target_ip']
            if ip is not None:
                ip_parts = ip.split(".")
                reverse_ip = ".".join(reversed(ip_parts))
            if d['os'] is not None and len(d['os']) > len(best_os):
                best_os = d['os']
            if d['domain'] is not None and len(d['domain']) > len(best_domain):
                best_domain = d['domain']
            if d['mac'] is not None and len(d['mac']) > len(best_mac):
                best_mac = d['mac']
            if d['info'] is not None and len(d['info']) > len(best_info):
                best_info = best_info + d['info']
            if d['target_name'] is not None and \
                    (len(d['target_name']) > len(best_target_name) or
                                 (ip is not None and network.valid_ip(best_target_name) and not network.valid_ip(d['target_name']))) \
                    and ip is not None and ip not in d['target_name'] and ip.replace(".","-") not in d['target_name'] \
                    and reverse_ip is not None and reverse_ip not in d['target_name'] and reverse_ip.replace(".","-") not in d['target_name']:
                best_target_name = d['target_name']
            if d['services'] is not None and len(d['services']) > len(best_services):
                best_services = best_services +  d['services']
            if d['accounts'] is not None and len(d['accounts']) > len(best_accounts):
                best_accounts = best_accounts + d['accounts']
            if d['programs'] is not None and len(d['programs']) > len(best_programs):
                best_programs = best_programs + d['programs']

            # Merge devices to 1st one
            if count > 0:
                # Merge DevicePort
                db_object.update("DevicePort", {"engagementdevice_id": keep_id}, ['engagementdevice_id'], [d['id']], True)

                # Merge Result
                db_object.update("Result", {"engagementdevice_id": keep_id}, ['engagementdevice_id'], [d['id']], True)

                # Merge Credential
                db_object.update("Credential", {"engagementdevice_id": keep_id}, ['engagementdevice_id'], [d['id']], True)

                # Delete ones that didn't update b/c where duplicates
                db_object.delete("EngagementDevice", d['id'])
                db_object.delete_where("DevicePort", ['engagementdevice_id'], [d['id']], True, True)
                db_object.delete_where("Result", ['engagementdevice_id'], [d['id']], True, True)
                db_object.delete_where("Credential", ['engagementdevice_id'], [d['id']], True, True)

        if best_target_name == "":
            best_target_name = similar_devices[0]['target_ip']

            # Update EngagementDevice w/ best values from all
            db_object.update("EngagementDevice", {"os": best_os, "domain": best_domain, "mac": best_mac, "info": best_info,
                                                  "target_name": best_target_name, "services": best_services,
                                                  "programs": best_programs, "accounts": best_accounts},
                             ['id'], [similar_devices[0]['id']], True)
    except Exception as e:
        print_text.print_error("common_merge 79 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

