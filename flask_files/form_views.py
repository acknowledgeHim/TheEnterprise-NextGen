import sys
import re
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session, abort
from flask_files.form_class import FormSetup
from flask_files import common_flask
from menus import email_phishing

def create_engagement(session):
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        menu_items = ""

        from setup.engagement import MANUAL_FIELDS, MORE_MANUAL_FIELDS
        inputs = [["Client Number", "client_number", r'^(?:[\d\-]+)$'],
                    ["Client Name", "client_name", r'^(?:[a-zA-Z_ \-0-9]+)$'],
                    ["Engagement Number", "engagement_number", r'^(?:[a-zA-Z_\-0-9]+)$']] \
                 + MANUAL_FIELDS + MORE_MANUAL_FIELDS

        with FormSetup('create_engagement', '/create_engagement') as form:
            html_form = form.create_form(inputs)

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']
        engagement_path = "" #session.get('engagement_path')

        return render_template('form.html', engagements=engagements, menu_items=menu_items,
                               engagement_path=engagement_path, html_form=html_form)


def edit_form(table_name, id, db_object, model, action='add'):
    try:
        names = None
        fields = None
        extra_html = ""
        if table_name == "Credential":
            from result.credential import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)

            engagementdevices = db_object.dictionary_list("EngagementDevice", "id")
            names = ",".join(db_object.dictionary_list_multiple_fields("EngagementDevice",
                                                                       ["target_name", "Scope.Location.name"], None,
                                                                       None, None, " - "))
            engagementdevices_string = "|".join(str(engagementdevice) for engagementdevice in engagementdevices)
            fields.append(["Engagement Device", "engagementdevice_id", re.compile(engagementdevices_string)])
        elif table_name == "Log" or table_name == "EngagementDevice" or table_name == "Recon":# or table_name == "ForensicLog":
            if table_name == "EngagementDevice":
                from result.engagementdevice import MANUAL_FIELDS
            elif table_name == "Log":
                from menus.log import MANUAL_FIELDS
            elif table_name == "Recon":
                from result.recon import MANUAL_FIELDS

            fields = list(MANUAL_FIELDS)
            scopes = db_object.dictionary_list("Scope", "id")
            names = ",".join(db_object.dictionary_list_multiple_fields("Scope", ["entry", "Location.name"], None, None, None, " - "))
            scopes_string = "|".join(str(scope) for scope in scopes)
            fields.append(["Scope", "scope_id", re.compile(scopes_string)])

        elif table_name == "DevicePort" or table_name == "Result":
            if table_name == "DevicePort":
                from result.deviceport import MANUAL_FIELDS
            else:
                from result.result import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
            engagementdevices = db_object.dictionary_list("EngagementDevice", "id")
            names = ",".join(db_object.dictionary_list_multiple_fields("EngagementDevice", ["target_name", "Scope.Location.name"], None, None, None, " - "))
            engagementdevices_string = "|".join(str(engagementdevice) for engagementdevice in engagementdevices)
            fields.append(["Engagement Device", "engagementdevice_id", re.compile(engagementdevices_string)])
        elif table_name == "Phishing":
            from result.phished import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
            scenarios = db_object.dictionary_list("PhishingScenario", "id")
            names = ",".join(db_object.dictionary_list("PhishingScenario", "scenario"))
            phishingscenario_string = "|".join(str(scenario) for scenario in scenarios)
            fields.append(["Phishing Scenario", "scenario_id", re.compile(phishingscenario_string)])
            locations = db_object.dictionary_list("Location", "id")
            names = ",".join(db_object.dictionary_list("Location", "name"))
            locations_string = "|".join(str(location) for location in locations)
            fields.append(["Location", "location_id", re.compile(locations_string)])
        elif table_name == "Scope":
            if action == "add":
                from setup.scope import MANUAL_FIELDS
            else:
                from setup.scope import UPDATE_MANUAL_FIELDS as MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
            locations = db_object.dictionary_list("Location", "id")
            names = ",".join(db_object.dictionary_list("Location", "name"))
            locations_string = "|".join(str(location) for location in locations)
            fields.append(["Location", "location_id", re.compile(locations_string)])
        elif table_name == "Engagement":
            from setup.engagement import MANUAL_FIELDS, MORE_MANUAL_FIELDS
            fields = list(MANUAL_FIELDS) + list(MORE_MANUAL_FIELDS)
        elif table_name == "CurrentLocation":
            locations = db_object.dictionary_list("Location", "id") + ["all_locations"]
            names = ",".join(db_object.dictionary_list("Location", "name")) + ",all_locations"
            locations_string = "|".join(str(location) for location in locations)
            fields = [["Testing Location", "current_location", re.compile(locations_string)]]
        elif table_name == "ClientContact":
            from setup.client_contact import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
        elif table_name == "CorpContact":
            from setup.corp_contact import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
        elif table_name == "PhishingScenario":
            from menus.email_phishing import ADD_MANUAL_FIELDS
            ADD_MANUAL_FIELDS.insert(0, ["Using the table above enter the email server (and optionally any test #) to use (ex mail.domain.example(6,10,19) where 6,10,19 represent the test #s to utilize)", "email_server", ""])
            ADD_MANUAL_FIELDS.insert(2, ["the PHISHING_URL (leave blank to use the default 'PHISHING_URL' for the scenario)", "phish_url", ""])
            fields = list(ADD_MANUAL_FIELDS)
            scenarios, scenario_names = email_phishing.grab_scenarios()
            fields.append(["Scenario", "scenario", re.compile("|".join(scenario_names))])
            names = ",".join(scenario_names)
            email_servers, email_tests_by_email_server = email_phishing.possible_filter_tests()
            if len(email_servers) > 0:
                extra_html = "<table><tr><thead>"
                header = ""
                row = ""
                for email_server in email_servers:
                    header = header + "<th>" + email_server + "</th>"
                    row = row + "<td>" + email_tests_by_email_server[email_server] + "</td>"
                extra_html = extra_html + header + "</thead></tr><tr>" + row + "</tr></table>"
        elif table_name == "Credential":
            from result.credential import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
        elif table_name == "TesterDevice":
            from setup.tester_device import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
            locations = db_object.dictionary_list("Location", "id")
            names = ",".join(db_object.dictionary_list("Location", "name"))
            locations_string = "|".join(str(location) for location in locations)
            fields.append(["Location", "location_id", re.compile(locations_string)])
        elif table_name == "Location":
            from setup.location import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
        elif table_name == "EmailEvent":
            from setup.email import MANUAL_FIELDS2
            fields = list(MANUAL_FIELDS2)
        elif table_name == "Person":
            from result.person import MANUAL_FIELDS
            fields = list(MANUAL_FIELDS)
            locations = db_object.dictionary_list("Location", "id")
            names = ",".join(db_object.dictionary_list("Location", "name"))
            locations_string = "|".join(str(location) for location in locations)
            fields.append(["Location", "location_id", re.compile(locations_string)])

        values = None
        if id is not None:
            values = db_object.get(table_name, ["id"], [id], True)
        inputs = []
        for field in fields:
            if values is not None:
                if len(field) > 3:
                    field[3] = values[field[1]]
                else:
                    field.append(values[field[1]])
            else:
                field.append(None)

            # add 4th item to inner list which represents all names of foreign field
            if ("_id" in field[1] or "current_location" in field[1]) and names is not None:
                if len(field) > 4:
                    field[4] = names
                else:
                    field.append(names)
            inputs.append(field)

        if id is None:
            form_url = "/insert?table=" + table_name
        else:
            form_url = '/update?table=' + table_name + '&ident=' + str(id)
        if model is not None:
            form_url = form_url + "&model=" + model

        if len(inputs) > 0:
            with FormSetup('edit_entry', form_url) as form:
                html_form = extra_html + form.create_form(inputs, "black_text")
            return html_form

    except Exception as e:
        print("48 flask_files/form_view.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno), file=sys.stderr)
        return "Failed. Error: " + str(e)

    return "Failed.  Could not find record you wanted to edit?"

def mod_fields(table_name, fields):
    if table_name == "PhishingScenario":
        scenarios, scenario_names = email_phishing.grab_scenarios()
        scenario_index  = scenario_names.index(fields['scenario'])
        # need to check smtp_from data_from, etc
        scenario = scenarios[scenario_index]
        fields['scenario_file'] = scenario['filename']
        fields['scenario'] = scenario['subject']
        fields['subject'] = scenario['subject']
        if fields['email_server'].strip() != "" and "(" in fields['email_server']:
            email_server = fields['email_server']
            email_filter_tests = email_server[email_server.find("(")+1:]
            if ")" in email_filter_tests:
                email_filter_tests = email_filter_tests.replace(")", "")
            fields['email_filter_tests_used'] = email_filter_tests

        if fields['smtp_from'].strip() == "":
            fields['smtp_from'] = scenario['smtp_from']
        if fields['data_from'].strip() == "":
            fields['data_from'] = scenario['data_from']
        if fields['read_receipt'].strip() == "":
            fields['read_receipt'] = scenario['read_receipt']
        if fields['signature'].strip() == "":
            fields['signature'] = scenario['signature']
        if fields['phish_url'].strip() == "":
            fields['phish_url'] = scenario['phish_url']

    # Convert all date strings to python date objects
    for key, value in fields.items():
        if value is not None:
            value = value.strip()
        if "_date" in key:
            if value is not None and value != "":
                if "-" in value:
                    fields[key] = datetime.strptime(value, "%Y-%m-%d")
                elif "/" in value:
                    fields[key] = datetime.strptime(value, "%Y/%m/%d")
            else:
                fields[key] = None
        if value == "Y":
            fields[key] = True
        if value == "N":
            fields[key] = False

    return fields

def insert_entry(db_object, table_name, fields):
    try:
        msg = ""
        fields = mod_fields(table_name, fields)
        if table_name == "Scope":
            from setup import scope
            msg = scope.add_scope(db_object, fields, True)
        else:
            # add() returns (True, hashval) on success or (error message, None) on failure -
            # it never raises for a DB-level failure (bad column, constraint violation, etc.),
            # it just swallows the exception internally. Not checking this meant every such
            # failure still reported "Successfully inserted" below.
            success, hashval = db_object.add(table_name, fields)
            if success is not True:
                return "Failed inserting " + table_name + ", error: " + str(success)
        return "Successfully inserted " + table_name + ". " + str(msg)

    except Exception as e:
        print("flask_files/form_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return "Failed inserting " + table_name + ", error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno)

def update_entry(db_object, table_name, fields):
    fields = mod_fields(table_name, fields)

    success, hashval = db_object.update(table_name, fields, ['id'], [fields['id']])
    if success is not True:
        return "Failed updating " + table_name + ", error: " + str(success)
    return "Success.  " + table_name + " was updated."


def tool_form(yaml_file, fields, dropdown_fields=None):
    try:
        extra_html = ""
        form_url = "/run_tool?tool=" + yaml_file

        if len(fields) > 0:
            with FormSetup('edit_entry', form_url) as form:
                html_form = extra_html + form.create_form(fields, "black_text", dropdown_fields)
            return html_form

    except Exception as e:
        print("48 flask_files/form_view.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno), file=sys.stderr)
        return "Failed. Error: " + str(e)

    return "Failed.  The YAML file is probably not valid?"

