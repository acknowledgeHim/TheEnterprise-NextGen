try:
    import json
    import sys
    import time
    import os
    # Used to add parent path so can reference below stuff
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

    from common import print_text, common
    from flask_files import common_flask
    from setup import scope as sc
except Exception as e:
    print("scope_batch_run except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


def scope(command, scope_id, location_id, db_object, log_id, scope_args):
    """ Adding Batch Scope entries """
    try:
        scope_values = json.loads(scope_args)
        command = command.replace('"', '')
        output_file_path = command[:command.find(";")]
        common.create_path(output_file_path)

        entries = scope_values['entries']
        for entry in entries:
            field_values = {'location_id': scope_values['location_id'], 'entry': entry, 'permission': scope_values['permission']}
            print("26 tools/scope_batch_run field_values: " + str(field_values))
            sc.add_scope(db_object, field_values, False)

        comment = "Finished parsing scope file."
        values = dict(id=log_id, comment=comment, running=False, queued=False, finished=True)
        db_object.update("Log", values)

        # Delete bogus scope entry added
        db_object.delete("Scope", scope_id)

        # Create scope_ips.txt, scope_domains.txt, scope_websites.txt files
        base_file_path = db_object.sqlite_file
        if ".out" in base_file_path:
            base_file_path = base_file_path[:base_file_path.rfind("/") + 1] + "hosts/"
        base_file_path = base_file_path.rstrip(" ").rstrip("'").lstrip("'")
        if not os.path.isdir(base_file_path):
            common.makedirs(base_file_path)
        ip_file_name = base_file_path + "/scope_ips.txt"
        scope_ips = db_object.view("Scope", None, ["type"], ["IP"])
        with open(ip_file_name, "w") as scope_file:
            for entry in scope_ips:
                scope_file.write(entry["entry"] + "\n")
        domain_file_name = base_file_path + "/scope_domains.txt"
        scope_domains = db_object.view("Scope", None, ["type"], ["DOMAIN"])
        with open(domain_file_name, "w") as scope_file:
            for entry in scope_domains:
                scope_file.write(entry["entry"] + "\n")
        website_file_name = base_file_path + "/scope_websites.txt"
        scope_websites = db_object.view("Scope", None, ["type"], ["DOMAIN"])
        with open(website_file_name, "w") as scope_file:
            for entry in scope_websites:
                scope_file.write(entry["entry"] + "\n")

    except Exception as e:
        print_text.print_error("scope_batch_run except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
