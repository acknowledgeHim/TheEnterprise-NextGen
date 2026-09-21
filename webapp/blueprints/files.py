import logging
import os
import re
import sys

import yaml
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import generate_csrf

from common import common, print_text
from common.navigation_menu import NAVIGATION
from flask_files import common_flask
from flask_files.form_class import FormSetup
from tools.parse_file.file_parser import FileParser
from webapp.blueprints.main import home

files_bp = Blueprint("files", __name__)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = set(['nessus', 'gnmap', 'xml', 'json', 'txt', 'png', 'jpg', 'jpeg', 'gif']) # For file uploads


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@files_bp.route('/file_parse')
def file_parse_setup():
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        scopes = db_object.dictionary_list("Scope", "id")
        names = ",".join(db_object.dictionary_list("Scope", "entry"))
        scope_string = "|".join(str(scope) for scope in scopes)

        # find all yaml files
        display = []
        default_output_folder = []
        for folder, foldernames, files in os.walk(db_object.base_path):
            for name in files:
                if name.lower().endswith(".yaml"):
                    full_yaml_file_path = os.path.join(folder, name)
                    config = yaml.safe_load(open(full_yaml_file_path))
                    if config is not None and "callable_yaml" not in config and "tool_name" in config:
                        yaml_file = os.path.join(folder, name)
                        yaml_file = yaml_file[yaml_file.find(db_object.base_path) + len(db_object.base_path):]
                        display.append(config['tool_name'] + " (" + yaml_file + ")")
                        default_output_folder.append(config['output_path'])

        with FormSetup('edit_entry', '/file_parser_run') as form:
            inputs = [['full path to file(s) to parse (blank means it will parse files in the default directory)',
                       'path_to_file_to_parse', '']]
            inputs.append(['tool whose output needs parsing', 'tool_yaml_file', sorted(display)])
            inputs.append(['select the scope that the file(s) data belongs to', 'scope_id', re.compile(scope_string), None, names])
            html_form = form.create_form(inputs, "black_text")

        celery_cmd = session.get('celery_cmd')
        return render_template('main.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                               current_location="Current Working Location: " + session.get('current_location_name'),
                               content='File Parsing (TheEnterprise auto-parses files created when it runs a tool) '
                                       'but here you can parse and add a file\'s contents that was run elsewhere.',
                               celery=html_form, msg="")
    except Exception as e:
        print_text.print_error(
            "file_parse_setup() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@files_bp.route('/file_parser_run', methods=['POST'])
def file_parser_run():
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        scope_id = request.form['scope_id']
        tool_yaml_file = request.form['tool_yaml_file']
        path_to_file_to_parse = request.form['path_to_file_to_parse']

        tool = tool_yaml_file[:tool_yaml_file.find("(")].strip()
        yaml_file = tool_yaml_file[tool_yaml_file.rfind("(")+1:]
        yaml_file = yaml_file[:yaml_file.find(")")]

        config = yaml.safe_load(open(yaml_file))
        output_path = config['output_path']

        field_values = {'tool': tool, 'yaml_file': yaml_file, 'path_to_file_to_parse': path_to_file_to_parse,
                        'scope_id': scope_id}

        location_id = db_object.grab_column_from_single_record("Scope", ["id"], [scope_id], "location_id")
        if location_id is None:
            return home('You did not select a valid Scope from the repository and therefore the files were not parsed!')

        file_parser = FileParser(db_object, engagement_path)
        file_parser.create_parsing_job(field_values, scope_id, location_id, yaml_file, output_path)

        return home('Successfully added file(s) for parsing.  You can check the Jobs to see it running or when '
                        'it has completed.')
    except Exception as e:
        print_text.print_error(
            "file_parser_run() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@files_bp.route('/file_upload', methods=['GET', 'POST'])
def upload_file():
    table_name = request.args['table']
    engagement_path = session.get('engagement_path')

    db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                              session.get('key'), session.get('username'))

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']

        location_id = request.form['location_id']

        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        msg = "Upload failed :("
        if file and allowed_file(file.filename):
            upload_path = engagement_path + "/uploads/" + table_name.lower() + "/" + file.filename + "/"
            common.create_path(upload_path)
            filename = common.generate_filename(file.filename)
            file.save(os.path.join(upload_path, filename))
            if table_name == "Scope":
                from common.jobs import tasks
                with open(os.path.join(upload_path, filename), 'r') as scope_file:
                    s = scope_file.read()
                    scopes = s.split("\n")
                    for scope in scopes:
                        if scope is not None and scope != "":
                            scope = str(scope).strip()
                            fields = {'entry': scope, 'location_id': location_id}
                            msg = tasks.add_scope_to_celery(db_object.engagement_path, session.get('engagement_path'),
                                                            session.get('selected_engagement'), session.get('key'),
                                                            session.get('username'), fields, False)
                return redirect(url_for('records.views', table='Scope'))

            return redirect(url_for('main.home', msg=msg))

    upload_form = "<!doctype html><title>Upload " + table_name + " File</title><h1>Upload " + table_name + "</h1>"\
            "<form method=post enctype=multipart/form-data action='/file_upload?table=" + table_name + "'>" \
            "<input type=\"hidden\" name=\"csrf_token\" value=\"" + generate_csrf() + "\">" \
            "<input type=file name=file>"

    location_form = ""
    # all locations
    locations = db_object.view("Location", ['id', 'name'])
    # Get current location
    curr_location = db_object.view("CurrentLocation", ['current_location'], ['modified_by'], [session.get('username')])[0]['current_location']

    # auto get location id if possible, otherwise ask for it
    if "all_location" in curr_location and len(locations) > 1:
        location_form = "Location for scope entries: <select name=location_id>"
        for location in locations:
            location_form = location_form + "<option value='" + str(location['id']) + "'>" + location['name'] + "</option>"
        location_form = location_form + "</select><br>"
    elif len(locations) == 1:
        location_id = locations[0]['id']
        location_form = "<input type=hidden name=location_id value=" + str(location_id) + ">"
    else:
        for location in locations:
            if curr_location == location['name'] or str(curr_location) == str(location['id']):
                location_id = location['id']
                location_form = "<input type=hidden name=location_id value=" + str(location_id) + ">"
                break

    upload_form = upload_form + location_form + "<input type=submit value='Upload " + table_name + "'></form>"

    return upload_form
