import sys
from datetime import datetime
from celery import chord, chain
from common.jobs.celery_app import app
from common import network, common
from common.jobs import tasks
from common.database_object import OurCoolDBObject

def merge_all_devices(db_object):
    try:
        db_path = db_object.db_file
        full_client_path = common.format_target(db_path[:db_path.rfind("/")])

        msg = ""
        chain_commands = []
        chain_commands.append(engagementdevice_merge_same_target_and_domain.si(db_path).set(queue=full_client_path))
        chain_commands.append(engagementdevice_merge_same_ip_and_scope.si(db_path).set(queue=full_client_path))
        chain_result = chain(c for c in chain_commands).apply_async(queue=full_client_path,
                                                                    exchange=full_client_path,
                                                                    routing_key=full_client_path)
        return msg
    except Exception as e:
        print("Failed.  Merge failed with error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

@app.task
def engagementdevice_merge_same_target_and_domain(db_path):
    try:
        db_object = OurCoolDBObject(db_path)

        # loop through all Assets and sort by Scope
        assets = db_object.view("EngagementDevice", ['id', 'target_name', 'target_ip', 'domain', 'scope_id', 'info', 'programs', 'services', 'accounts', 'os'],
                                None, None, True, [('domain', 'asc'), ('target_name', 'asc')])

        # Find best engagement asset to keep
        # And sort assets into dictionaries by scope
        asset_dict_by_scope = {}
        keep_asset_dict = {}
        for asset in assets:
            if asset['domain'] is not None and asset['domain'] != "":
                if str(asset['target_name']).lower() + ":" + asset['domain'].lower() in asset_dict_by_scope:
                    asset_dict_by_scope[asset['target_name'].lower() + ":" + asset['domain'].lower()].append(asset)
                    if (asset['os'] is not None and keep_asset_dict[asset['target_name'].lower() + ":" +
                            asset['domain'].lower()]['info']['os'] is None) or (asset['os'] is not None and
                            keep_asset_dict[asset['target_name'].lower() + ":" +
                            asset['domain'].lower()]['info']['os'] is not None and
                            len(asset['os']) > len(keep_asset_dict[asset['target_name'].lower() + ":" + asset['domain'].lower()]['info']['os'])):
                        keep_asset_dict[asset['target_name'].lower() + ":" + asset['domain'].lower()] = {'id': asset['id'],
                                                                                                    'info': asset}
                else:
                    asset_dict_by_scope[asset['target_name'].lower() + ":" + asset['domain'].lower()] = [asset]
                    keep_asset_dict[asset['target_name'].lower() + ":" + asset['domain'].lower()] = {'id': asset['id'],
                                                                                                'info': asset}

        # merge_engagement_assets(current_user, old_device, delete_edevice_id, keep_device, mergeto_edevice_id)
        # Loop through assets by scope then within scope by asset to start merge
        msgs = []
        for key, assets_by_scope in asset_dict_by_scope.items():
            if len(assets_by_scope) > 1:  # nothing to merge if only 1 ;)
                keep_asset = keep_asset_dict[key]
                keep_asset_id = keep_asset['info']['id']
                for asset in assets_by_scope:
                    delete_asset_id = asset['id']
                    if delete_asset_id != keep_asset_id:
                        msgs.append(merge_engagement_assets(db_object, [asset], delete_asset_id,
                                                                              [keep_asset['info']], keep_asset_id))

        msg = "Success. Looks like there were no Assets with the same Target Name in the same Domain, so nothing was done."
        if len(msgs) > 0:
            msg = ", ".join(msgs)

    except Exception as e:
        msg = "Failed.  Merge failed with error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno)

    return msg

@app.task
def engagementdevice_merge_same_ip_and_scope(db_path):
    try:
        db_object = OurCoolDBObject(db_path)

        # loop through all Assets and sort by Scope
        assets = db_object.view("EngagementDevice", ['id', 'target_name', 'target_ip', 'domain', 'scope_id', 'info', 'services', 'programs', 'accounts', 'os'],
                                None, None, True, [('scope_id', 'asc'), ('target_ip', 'asc')])

        # Find best engagement asset to keep
        # And sort assets into dictionaries by scope
        asset_dict_by_scope = {}
        keep_asset_dict = {}
        for asset in assets:
            if asset['target_ip'] is not None and network.valid_ip(asset['target_ip']):
                if str(asset['scope_id']) + ":" + asset['target_ip'] in asset_dict_by_scope:
                    asset_dict_by_scope[str(asset['scope_id']) + ":" + asset['target_ip']].append(asset)
                    if network.valid_ip(keep_asset_dict[str(asset['scope_id']) + ":" + asset['target_ip']]['info']['target_name']) and not network.valid_ip(asset['target_name']):
                        keep_asset_dict[str(asset['scope_id']) + ":" + asset['target_ip']] = {'id': asset['id'], 'info': asset}
                    elif not network.valid_ip(keep_asset_dict[str(asset['scope_id']) + ":" + asset['target_ip']]['info'][
                                                  'target_name']) and not network.valid_ip(asset['target_name']) \
                            and len(keep_asset_dict[str(asset['scope_id']) + ":" + asset['target_ip']]['info']['target_name']) < len(
                                asset['target_name']):
                        keep_asset_dict[str(asset['scope_id']) + ":" + asset['target_ip']] = {'id': asset['id'], 'info': asset}
                else:
                    asset_dict_by_scope[str(asset['scope_id']) + ":" + asset['target_ip']] = [asset]
                    keep_asset_dict[str(asset['scope_id']) + ":" + asset['target_ip']] = {'id': asset['id'], 'info': asset}

        # merge_engagement_assets(current_user, old_device, delete_edevice_id, keep_device, mergeto_edevice_id)
        # Loop through assets by scope then within scope by asset to start merge
        msgs = []
        for key, assets_by_scope in asset_dict_by_scope.items():
            if len(assets_by_scope) > 1:  # nothing to merge if only 1 ;)
                keep_asset = keep_asset_dict[key]
                keep_asset_id = keep_asset['info']['id']
                for asset in assets_by_scope:
                    delete_asset_id = asset['id']
                    if delete_asset_id != keep_asset_id:
                        msgs.append(merge_engagement_assets(db_object, [asset], delete_asset_id,
                                                                              [keep_asset['info']], keep_asset_id))
        msg = "Success. Duplicate EngagementDevices merged."
        if len(msgs) > 0:
            msg = ", ".join(msgs)

        # Remove duplicate result/findings
        #results_merge_same_asset_vuln()

    except Exception as e:
        print("common/merge_devices 50 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        msg = "Failed.  Error: " + str(e)
    return msg

def merge_engagement_assets(db_object, old_device_list, delete_edevice_id, keep_device_list, mergeto_edevice_id):
    try:
        keep_device = keep_device_list[0]
        old_device = old_device_list[0]
        # If ips different but same device put 'old' ip inside info field (make sure not already there)
        add_old_ip_info = ""
        old_device_ip = old_device['target_ip']
        if old_device_ip is None:
            old_device_ip = ""
        keep_ip = keep_device['target_ip']
        if keep_ip is None:
            keep_ip = ""
        if old_device_ip != keep_ip and keep_device['info'] is not None and old_device_ip not in keep_device['info']:
            add_old_ip_info = "Additional IP: " + old_device_ip

        ip = keep_ip
        if not network.valid_ip(ip) and old_device['target_ip'] is not None and network.valid_ip(old_device['target_ip']):
            ip = old_device['target_ip']

        additional_ip = ""
        if network.valid_ip(keep_device['target_ip']) and network.valid_ip(old_device['target_ip']) and \
            old_device['target_ip'] != keep_device['target_ip']:
            additional_ip = "Additional IP: " + old_device['target_ip'] + "\n"

        # Go through each line of 4 fields to merge and
        engagement_device_list = []
        old_infos = []
        if old_device['info'] is not None:
            old_infos = old_device['info'].split("\n")
        old_accounts = []
        if old_device['accounts'] is not None:
            old_accounts = old_device['accounts'].split("\n")
        old_services = []
        if old_device['services'] is not None:
            old_services = old_device['services'].split("\n")
        old_programs = []
        if old_device['programs'] is not None:
            old_programs = old_device['programs'].split("\n")

        if len(old_infos) > len(old_accounts) and len(old_infos) > len(old_services) and len(old_infos) > len(old_programs):
            longest_length = len(old_infos)
        elif len(old_accounts) > len(old_infos) and len(old_accounts) > len(old_services) and len(old_accounts) > len(old_programs):
            longest_length = len(old_accounts)
        elif len(old_services) > len(old_infos) and len(old_services) > len(old_accounts) and len(old_services) > len(old_programs):
            longest_length = len(old_services)
        else:
            longest_length = len(old_programs)

        # find out what has best OS
        if keep_device['os'] is None:
            keep_device['os'] = ""
        if old_device['os'] is None:
            old_device['os'] = ""
        if len(keep_device['os']) > len(old_device['os']):
            os = keep_device['os']
        else:
            os = old_device['os']

        # find out what has best domain
        if keep_device['domain'] is None:
            keep_device['domain'] = ""
        if old_device['domain'] is None:
            old_device['domain'] = ""
        if len(keep_device['domain']) > len(old_device['domain']):
            domain = keep_device['domain']
        else:
            domain = old_device['domain']

        cnt = 0
        info = ""
        account = ""
        service = ""
        program = ""
        while cnt < longest_length:
            try:
                info = old_infos[cnt] + "\n"
            except:
                info = ""
            try:
                account = old_accounts[cnt] + "\n"
            except:
                account = ""
            try:
                service = old_services[cnt] + "\n"
            except:
                service = ""
            try:
                program = old_programs[cnt] + "\n"
            except:
                program = ""
            cnt = cnt + 1

        field_values = {'id': keep_device['id'], 'info': add_old_ip_info + info + additional_ip, 'accounts': account,
                        'services': service, 'programs': program, 'os': os, 'domain': domain}
        db_object.update('EngagementDevice', field_values)

        # Update DevicePort
        # move ports to keep device
        try:
            db_object.update('DevicePort', {'engagementdevice_id': keep_device['id']}, ['engagementdevice_id'],
                         [old_device['id']])
        except:
            pass
        # delete any that did not move (prob b/c duplicate otherwise)
        db_object.delete_where('DevicePort', ['engagementdevice_id'], [old_device['id']])

        # Update Results
        # move results to keep device
        try:
            db_object.update('Result', {'engagementdevice_id': keep_device['id']}, ['engagementdevice_id'],
                         [old_device['id']])
        except:
            pass
        # delete any that did not move (prob b/c duplicate otherwise)
        db_object.delete_where('Result', ['engagementdevice_id'], [old_device['id']])

        # Delete old EngagementDevice
        db_object.delete('EngagementDevice', delete_edevice_id)

        msg = "Success.  Moved all associations from the deleted Engagement Device to the selected Engagement Device, " \
                  "updated all Result/Findings to 'merge to' Engagement Device and updated all DevicePorts to " \
                  "'merge to' Engagement Device that were associated with old Engagement Device."
    except Exception as e:
        msg = "Failed.  Merge failed with error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno)
        print(msg)

    return msg