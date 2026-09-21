import logging

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import generate_csrf

from common import merge_devices
from common.navigation_menu import NAVIGATION
from flask_files import common_flask, form_views
from flask_files.table_class import TableClass
from menus import job

records_bp = Blueprint("records", __name__)
logger = logging.getLogger(__name__)


@records_bp.route('/ajax', methods=['GET', 'POST'])
def ajaxs():
    try:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        json_data = request.get_json(force=True)
        with TableClass(db_object, request.args['table'], True, json_data, session.get('username')) as table_class:
            if 'i' in request.args:
                device = request.args['i']
                device_info = db_object.get('EngagementDevice', ['target_name'], [device], True)
                device_id = device_info['id']
                table_class.global_filters = ["engagementdevice_id"]
                table_class.global_filter_values = [device_id]

            result_dict = table_class.ajax_view()
            return jsonify(result_dict)
    except Exception as e:
        logger.exception("ajaxs failed: %s", e)


@records_bp.route('/view', methods=['GET', 'POST'])
def views():
    try:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        setup_dictionary = common_flask.setup_base_page(session, db_object)
        engagements = setup_dictionary['engagements']
        menu_items = common_flask.loop_through_menu(NAVIGATION)
        engagement_path = session.get('engagement_path')

        data = "<table id=datatables_table></table>"
        with TableClass(db_object, request.args['table'], True, None, session.get('username')) as table_class:
            data, datatable_columns = table_class.list_view()

    except Exception as e:
        logger.exception("views failed: %s", e)
        data = str(e)

    celery_cmd = session.get('celery_cmd')
    return render_template('table_view.html', engagements=engagements, menu_items=menu_items,
                       engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                       current_location="Current Location: " + session.get('current_location_name'),
                       content=data, celery="", datatable_columns=datatable_columns)


@records_bp.route('/detail', methods=['GET', 'POST'])
def detail():
    try:
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        setup_dictionary = common_flask.setup_base_page(session, db_object)
        engagements = setup_dictionary['engagements']
        menu_items = common_flask.loop_through_menu(NAVIGATION)
        engagement_path = session.get('engagement_path')

        device = request.args['i']
        device_info = db_object.get('EngagementDevice', ['target_name'], [device], True)
        device_id = device_info['id']

        data = "<table id=datatables_table></table>"
        with TableClass(db_object, 'DevicePort', True, None, session.get('username')) as table_class:
            table_class.global_filters = ["engagementdevice_id"]
            table_class.global_filter_values = [device_id]
            data, datatable_columns = table_class.list_view()

    except Exception as e:
        logger.exception("detail failed: %s", e)
        data = str(e)

    celery_cmd = session.get('celery_cmd')
    return render_template('detail_view.html', engagements=engagements, menu_items=menu_items,
                       engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                       current_location="Current Location: " + session.get('current_location_name'),
                       content=data, celery="", datatable_columns=datatable_columns)


@records_bp.route('/add', methods=['GET'])
def add():
    try:
        table_name = request.args['table']
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        return "<h1>Insert " + table_name + "</h1>" + form_views.edit_form(table_name, None, db_object, model)

    except Exception as e:
        return "Failed.  Error: " + str(e)


@records_bp.route('/insert', methods=['GET', 'POST'])
def insert():
    try:
        table_name = request.args['table']

        fields = {}
        for key, value in request.form.items():
            if value.strip() == "":
                value = None
            fields[key] = value

        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        msg = form_views.insert_entry(db_object, table_name, fields)

    except Exception as e:
        logger.exception("insert failed: %s", e)
        msg = "Failed. " + table_name + " entry was not inserted.  Error: " + str(e)
    if model is not None:
        return redirect(url_for('records.views', table=table_name, msg=msg, model=model))
    return redirect(url_for('records.views', table=table_name, msg=msg))


@records_bp.route('/edit', methods=['GET'])
def edit():
    try:
        table_name = request.args['table']
        id = request.args['ident']

        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        return "<h1>Edit " + table_name + "</h1>" + form_views.edit_form(table_name, id, db_object, model, "edit")

    except Exception as e:
        return "Failed.  Error: " + str(e)


@records_bp.route('/update', methods=['GET', 'POST'])
def update():
    try:
        table_name = request.args['table']
        id = request.args['ident']

        fields = {"id": str(id)}
        for key, value in request.form.items():
            if value.strip() == "":
                value = None
            fields[key] = value

        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        msg = form_views.update_entry(db_object, table_name, fields)

        if table_name == "CurrentLocation":
            session['current_location'] = fields['current_location']
            field_name = fields['current_location']
            if field_name != "all_locations":
                field_name = db_object.grab_column_from_single_record("Location", ["id"], [field_name], "name")
            session['current_location_name'] = field_name

    except Exception as e:
        logger.exception("update failed: %s", e)
        msg = "Failed. " + table_name + " entry was not updated.  Error: " + str(e)

    if model is not None:
        return redirect(url_for('records.views', table=table_name, msg=msg, model=model))
    return redirect(url_for('records.views', table=table_name, msg=msg))


@records_bp.route('/delete', methods=['GET'])
def delete():
    try:
        table_name = request.args['table']
        model = None
        if 'model' in request.args:
            model = request.args['model']
        id = request.args['ident']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        is_running = False
        if table_name == "Log":
            log = db_object.view("Log", ['running'], ['id'], [id], True)
            if log[0]['running']:
                is_running = True

        if table_name == "Job":
            engagement_path = session.get('engagement_path')
            tasks = job.get_active_tasks(engagement_path)
            results, valid_ids, valid_information = job.get_running_jobs(db_object, 'Active', tasks)
            job.kill_job(db_object, id, valid_information)
            return "Successfully stopped job!"
        elif is_running and table_name == "Log":
            return "You can not delete a Log entry for a running job.  You must first kill the running job."
        else:
            db_object.delete_where(table_name, ["id"], [id], True)
            return "Successfully deleted " + str(table_name) + "."
    except Exception as e:
        return "Failed.  Error: " + str(e)


@records_bp.route('/truncate', methods=['GET'])
def truncate():
    try:
        table_name = request.args['table']

        return '<h1>Delete All ' + table_name + ' Records</h1>' + '<form name="truncate" action="/truncate_confirmed?table=' + table_name + '" ' \
                'method=post enctype="multipart/form-data">' \
                '<input type="hidden" name="csrf_token" value="' + generate_csrf() + '">' \
                'This action is not reversable, so only click the confirm button if you know you want to do this!<p>' \
                '<input type=Submit value="Confirm Delete All"></form>'
    except Exception as e:
        return "Failed.  Error: " + str(e)


@records_bp.route('/truncate_confirmed', methods=['GET', 'POST'])
def truncate_confirmed():
    try:
        table_name = request.args['table']

        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        db_object.truncate(table_name)
        msg = 'Successfully deleted all ' + str(table_name) + ' records.'
    except Exception as e:
        msg = "Failed to delete all " + table_name + " records.  Error: " + str(e)
    return redirect(url_for('records.views', table=table_name, msg=msg))


@records_bp.route('/merge', methods=['GET'])
def merge():
    try:
        table_name = request.args['table']
        model = None
        if 'model' in request.args:
            model = request.args['model']

        if model is None:
            db_object = common_flask.create_db_object(session.get('engagement_path'),
                                  session.get('selected_engagement'), session.get('key'), session.get('username'))
        else:
            db_object = common_flask.just_db_object('setup/email_event.db')

        if table_name == "EngagementDevice":
            merge_devices.merge_all_devices(db_object)

        return "Merging " + str(table_name) + " in the background."
    except Exception as e:
        return "Failed.  Error: " + str(e)
