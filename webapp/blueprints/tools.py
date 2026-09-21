import glob
import json
import logging
import re
import sys

import yaml
from flask import Blueprint, redirect, render_template, request, session, url_for
from markupsafe import escape

def _js_str(value):
    """ A JS string literal (quotes included) safe to splice into an inline HTML event-handler
    attribute - json.dumps() handles JS-level escaping (quotes/backslashes), and the caller must
    still HTML-escape the attribute value as a whole (a bare `'` surviving json.dumps could still
    break out of a single-quoted HTML attribute otherwise). """
    return json.dumps(str(value))

from common import keep_tags, print_text
from common.navigation_menu import NAVIGATION
from flask_files import common_flask, form_views
from tools.tool_config import ToolConfig
from webapp.blueprints.main import home

tools_bp = Blueprint("tools", __name__)
logger = logging.getLogger(__name__)


@tools_bp.route('/tool', methods=['GET'])
def tool():
    """ Tool """

    dropdown_fields = []
    form_html = ""
    fields = []
    answers = {}
    replacements = {}
    global_fields = {}

    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        # grab yaml file from passed yaml_config
        yaml_file = keep_tags.clean_text(request.args['tool'])
        if ".yaml" not in yaml_file:
            yaml_file = yaml_file + ".yaml"
        yaml_config = yaml.safe_load(open(db_object.base_path + "/" + yaml_file))
        tool_config = ToolConfig(db_object, db_object.engagement_path, yaml_file)

        if "callable_yaml" in yaml_config:
            tool_name = ""
            yaml_configs = yaml_config['callable_yaml']
            form_html = ""
            for yaml_c in yaml_configs:
                # Now grab all the yaml files that match in callable_yaml
                # 1st grab all user-input needed
                for f in glob.glob(db_object.base_path + yaml_c + ".yaml"):
                    tmp_fields = []
                    tmp_answers = {}
                    tmp_replacements = []
                    tmp_global_fields = []
                    if ".yaml" in f and f != tool_config.yaml_config_file:
                        current_yaml_config = yaml.safe_load(open(f))

                        if "tool_name" in current_yaml_config:
                            sep = ""
                            if tool_name != "":
                                sep = ", "
                            tool_name = current_yaml_config['tool_name']
                            tool_config.load_config_values(current_yaml_config)
                            if tool_config.questions is not None:
                                tmp_fields, tmp_answers, tmp_replacements, tmp_global_fields = tool_config.manual_entry(True)
                                # find questions that have options to tell it is a dropdown field
                                for question in tool_config.questions:
                                    if "options" in question:
                                        dropdown_fields.append(question['name'])

                            if tool_config.selections is not None:
                                for select in tool_config.selections:
                                    names = ",".join(db_object.dictionary_list_multiple_fields(select['table'],
                                                                    select['display_fields'], None, None, None, " - "))
                                    ids = db_object.dictionary_list(select['table'], 'id')
                                    ids_string = "|".join(str(id) for id in ids)
                                    tmp_fields.append([select['table'], select['table'].lower() + "_id",
                                                  re.compile(ids_string), names])

                            # Append results to full list below - make sure fields not already have tmp_fields
                            for tf in tmp_fields:
                                if tf not in fields:
                                    fields.append(tf)

                            answers.update(tmp_answers)
                            replacements.update(tmp_replacements)
                            global_fields.update(tmp_global_fields)

                            session['answers'] = json.dumps(answers)
                            session['replacements'] = json.dumps(replacements)
                            session['global_fields'] = json.dumps(global_fields)

                            if len(fields) > 0:
                                tmp_form_html = "<h3> User-input to launch " + tool_name + "</h3>" + form_views.tool_form(
                                    yaml_file.replace(".yaml", ""), fields, dropdown_fields)
                                logger.debug("tool() tmp_form_html: %s", tmp_form_html)
                                if tmp_form_html is not None:
                                    form_html = form_html + tmp_form_html
                            else:
                                return redirect(url_for('tools.run_tool', tool=request.args['tool']))
        else:
            tool_config.load_config_values()
            tool_name = yaml_config['tool_name']

            if tool_config.questions is not None:
                fields, answers, replacements, global_fields = tool_config.manual_entry(True)

                # find questions that have options to tell it is a dropdown field
                for question in yaml_config['questions']:
                    if "options" in question:
                        dropdown_fields.append(question['name'])

            if tool_config.selections is not None:
                current_location = db_object.grab_current_location()
                location_id = None
                if current_location != "all":
                    location_id = current_location
                for select in tool_config.selections:
                    filter_key = None
                    filter_value = None
                    display_fields = select['display_fields']
                    if "filter" in select:
                        if select['filter'] == "CURRENT_LOCATION" and location_id is not None:
                            if select['table'] == "DevicePort":
                                display_fields.append("EngagementDevice.Scope.Location.name")
                            filter_key = ["location_id"]
                            filter_value = [location_id]
                        else:
                            filter_key = []
                            filter_value = []
                            if isinstance(select['filter'], dict):
                                filter_dictionary = select['filter']
                            else:
                                filter_dictionary = json.loads(select['filter'])
                            for key, value in filter_dictionary.items():
                                filter_key.append(key)
                                filter_value.append(value)
                    names = db_object.dictionary_list_multiple_fields(select['table'], display_fields, filter_key,
                                                                           filter_value)
                    names = ",".join(names)
                    return_fields = db_object.dictionary_list(select['table'], select['return_field'], filter_key,
                                                                   filter_value)
                    single_value = None
                    if "," not in names:
                        single_value = names

                    rfields_string = "|".join(str(rfield) for rfield in return_fields)
                    field_name = select['table'].lower() + "_id"
                    if "name" in select:
                        field_name = select['name']
                    fields.append([select['table'], field_name, re.compile(rfields_string), single_value, names])
                    dropdown_fields.append(field_name)

            session['answers'] = json.dumps(answers)
            session['replacements'] = json.dumps(replacements)
            session['global_fields'] = json.dumps(global_fields)

            if len(fields) > 0:
                form_html = "<h1> User-input to launch " + tool_name + "</h1>" + form_views.tool_form(yaml_file.replace(".yaml", ""), fields, dropdown_fields)
            else:
                return redirect(url_for('tools.run_tool', tool=request.args['tool']))
    except Exception as e:
        print_text.print_error("tool() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    celery_cmd = session.get('celery_cmd')
    return render_template('form.html', engagements=engagements, menu_items=menu_items,
                                   engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                                   current_location="Current Working Location: " + session.get('current_location_name'),
                                   content="", celery="", html_form=form_html)


@tools_bp.route('/run_tool', methods=['GET', 'POST'])
def run_tool():
    """ Run the Tool."""
    try:
        tool_name = ""
        all_errors = ""

        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        # get session objects
        answers = json.loads(session.get('answers'))
        replacements = json.loads(session.get('replacements'))
        global_fields = json.loads(session.get('global_fields'))

        # grab yaml file from passed yaml_config
        yaml_file = keep_tags.clean_text(request.args['tool'])
        if ".yaml" not in yaml_file:
            yaml_file = yaml_file + ".yaml"
        yaml_config = yaml.safe_load(open(db_object.base_path + "/" + yaml_file))
        tool_config = ToolConfig(db_object, db_object.engagement_path, yaml_file)

        if "callable_yaml" in yaml_config:
            tool_config.yaml_configs = tool_config.config['callable_yaml']
            tool_name = ", ".join(tool_config.config['callable_yaml'])
        else:
            tool_config.yaml_configs = [yaml_file]
            tool_name = yaml_config['tool_name']

        all_errors = tool_config.grab_targets_and_generate_commands(request, answers, replacements, global_fields)
        if all_errors is None:
            all_errors = ""
        if tool_config.error is not None:
            all_errors = all_errors + " " + tool_config.error

        all_messages = all_errors + " "  + tool_config.msg

        if all_messages != "":
            return home(all_messages)
        else:
            return home('Successfully started ' + tool_name)

    except Exception as e:
        print_text.print_error(
            "run_tool() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@tools_bp.route("/device/lookup_merge", methods=['POST'])
def lookup_merge():
    try:
        ips = "No matches found, please try searching again!"
        setup_dictionary = common_flask.setup_base_page(session)
        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        search_string = request.form['title']
        div_id = request.form['div_id']

        devices = db_object.join_view("EngagementDevice", ["Scope.Location.name"], None, ["target_name"], [search_string], False)
        if devices is None or len(devices) == 0:
            devices = db_object.join_view("EngagementDevice", ["Scope.Location.name"], None, ["target_ip"], [search_string], False)
        if devices is not None and len(devices) > 0:
            ips = "<ul id='mergeto_selection' class='selection'>"
            for device in devices:
                display = device['target_name'] + " (" + device['target_ip'] + ") @ " + device['name']
                onclick_js = "select_item(" + _js_str(div_id) + ", " + _js_str(device['id']) + ", " + \
                             _js_str(display) + ", " + _js_str(device['id']) + ")"
                ips = ips + "<li class='selection_item' onClick='" + str(escape(onclick_js)) + "'>" + \
                      str(escape(display)) + "</li>"
            ips = ips + "</ul>"
        return ips

    except Exception as e:
        print_text.print_error(
            "lookup_merge() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@tools_bp.route('/device/lookup_info', methods=['POST'])
def lookup_info():
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        info_id = request.form['info_id']
        div_id = request.form['div_id']
        devices = db_object.join_view("EngagementDevice", ["Scope.entry", "Scope.Location.name"], None, ["id"], [info_id], True)[:1]

        info = "No matches found, please try searching again!"
        for device in devices:
            info = '<center><u><b>' + str(escape(device['target_name'])) + '</b></u>'
            info = info + '<br><b>IP</b>: ' + str(escape(device['target_ip']))
            info = info + '<br><b>Location</b>: ' + str(escape(device['name']))
            info = info + '<br><b>Scope</b>: ' + str(escape(device['entry']))
            info = info + '<br><b>OS</b>: ' + str(escape(device['os']))
            info = info + '<br><b>MAC</b>: ' + str(escape(device['mac']))
            info = info + '<br><b>Info</b>: ' + str(escape(device['info']))
            info = info + '<br><b>Source</b>: ' + str(escape(device['source']))
            info = info + '<br><b>Modified By</b>: ' + str(escape(device['modified_by']))
            info = info + '<br><b>Modified Date</b>: ' + str(device['modified_date'])
            info = info + '</center>'

        return info

    except Exception as e:
        print_text.print_error(
            "lookup_info() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
