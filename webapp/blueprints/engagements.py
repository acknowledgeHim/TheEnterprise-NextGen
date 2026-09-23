import os
import shutil

from flask import Blueprint, flash, redirect, render_template, request, session

from enterprise_user_conf import OUTPUT_PATH
from flask_files import common_flask, form_views, insert_views
from webapp.blueprints.main import home

engagements_bp = Blueprint("engagements", __name__)


def _resolve_engagement_path(selected_engagement):
    """ Resolves selected_engagement (untrusted request input) to a real directory strictly
    inside OUTPUT_PATH, or None if it doesn't exist/escapes OUTPUT_PATH (path traversal, or a
    stale link to an engagement that's been deleted or is missing after a data migration). """
    output_real = os.path.realpath(OUTPUT_PATH)
    candidate = os.path.realpath(OUTPUT_PATH + selected_engagement + '/')
    if candidate != output_real and not candidate.startswith(output_real + os.sep):
        return None
    if not os.path.isdir(candidate):
        return None
    return candidate


@engagements_bp.route('/engagement')
def engagement():
    """ Engagement main page."""
    if 'selected_engagement' in session:
        return home()
    else:
        return select_engagement()


@engagements_bp.route('/select_engagement')
def select_engagement():
    if 'selected_engagement' in request.args:
        selected_engagement = request.args['selected_engagement']

        if selected_engagement == "Create New Client/Engagement":
            session['current_location'] = None
            session['current_location_name'] = None
            session['selected_engagement'] = selected_engagement
            return form_views.create_engagement(session)

        # Validate the folder actually exists before touching session state at all - a stale
        # link/bookmark to a deleted engagement (or one that vanished because engagement data
        # moved, e.g. a Docker volume/mount change) used to partially set the session here and
        # then crash a few lines further down, leaving the session stuck pointing at a bad
        # engagement on every subsequent page load until it was cleared manually.
        if _resolve_engagement_path(selected_engagement) is None:
            flash("Failed.  '" + selected_engagement + "' no longer exists.  It may have been deleted, or its "
                  "data is missing (for example, after restoring from a backup or changing where engagement "
                  "data is stored).")
            return redirect('/select_engagement')

        session['current_location'] = None
        session['current_location_name'] = None
        session['selected_engagement'] = selected_engagement
        session['engagement_path'] = OUTPUT_PATH + session.get('selected_engagement') + '/'

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        setup_dictionary = common_flask.setup_base_page(session, db_object)
        new_client_engagements = setup_dictionary['client_engagements']
        selected_engagement_number = new_client_engagements.index(selected_engagement) + 1
        session['selected_engagement_number'] = selected_engagement_number

        # Make sure current location is selected
        locations = db_object.grab_all_locations()
        if locations is not None:
            if len(locations) > 1:
                return select_location()
            elif len(locations) == 1:
                session['current_location'] = locations[0]['id']
                session['current_location_name'] = locations[0]['name']
                current_location_dict = {"current_location": str(locations[0]['id']), 'modified_by': db_object.current_tester}
        else: # add default 'main' location
            add_location_dict = {"name": 'main', 'modified_by': db_object.current_tester}
            record, created = db_object.get_or_create("Location", add_location_dict)
            locations = db_object.grab_all_locations()
            session['current_location'] = locations[0]['id']
            session['current_location_name'] = locations[0]['name']
            current_location_dict = {"current_location": str(locations[0]['id']), 'modified_by': db_object.current_tester}

        record, created = db_object.get_or_create("CurrentLocation", current_location_dict)

        if not created:
            db_object.update("CurrentLocation", current_location_dict, ["modified_by"], [db_object.current_tester])

        return engagement()
    else:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        menu_items = ""

        celery_cmd = session.get('celery_cmd')
        return render_template('select_engagement.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="", celery="", celery_cmd=celery_cmd)


@engagements_bp.route('/select_location')
def select_location():
    db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                              session.get('key'), session.get('username'))
    if 'selected_location' in request.args:
        session['current_location'] = request.args.get('selected_location')
        if session.get('current_location') == "all_locations":
            session['current_location_name'] = "All Locations"
        else:
            session['current_location_name'] = db_object.grab_column_from_single_record("Location", ["id"],
                                                                [request.args.get('selected_location')], "name")

        current_location_dict = {"current_location": session.get('current_location'), 'modified_by': db_object.current_tester}
        curr_location_info =  db_object.view("CurrentLocation", None, ["modified_by"], [db_object.current_tester], True)
        if curr_location_info is not None:
            current_location_dict['id'] = curr_location_info[0]['id']
            db_object.update("CurrentLocation", current_location_dict, ["modified_by"], [db_object.current_tester])
        else:
            db_object.add("CurrentLocation", current_location_dict)

        return engagement()
    else:
        locations = db_object.grab_all_locations()
        location_str = ""
        for location in locations:
            location_str = location_str + "<a class='list-group-item' href='/select_location?selected_location=" + str(location['id']) + "'>" + location['name'] + "</a>"
        location_str = location_str + "<a class='list-group-item' href='/select_location?selected_location=all_locations'>All locations</a>"

        celery_cmd = session.get('celery_cmd')
        return render_template('select_location.html', locations='Select Current Working Location<br>' + location_str,
                               menu_items="", engagement_path=session.get('engagement_path'), celery="", celery_cmd=celery_cmd)


@engagements_bp.route('/create_engagement' , methods=['POST'])
def insert_passed_engagement():
    flash(insert_views.insert_engagement(session, request))
    return engagement()


@engagements_bp.route('/delete_engagement', methods=['GET'])
def delete_engagement():
    """ Permanently removes a client/engagement's folder (all its data, no undo - the confirm
    dialog is the only safety net, matching how record deletes already work elsewhere in the
    app). Deleting an Engagement row through the generic table view is blocked on purpose
    (flask_files/table_class.py) since that would leave an orphaned folder on disk with no way
    to reach it from the UI; this is the actual, supported way to remove one. """
    selected_engagement = request.args.get('selected_engagement', '')
    target_path = _resolve_engagement_path(selected_engagement)
    if target_path is None:
        flash("Failed.  '" + selected_engagement + "' doesn't exist (it may already be deleted).")
        return redirect('/select_engagement')

    try:
        shutil.rmtree(target_path)
    except Exception as e:
        flash("Failed to delete '" + selected_engagement + "': " + str(e))
        return redirect('/select_engagement')

    if session.get('selected_engagement') == selected_engagement:
        session.pop('selected_engagement', None)
        session.pop('engagement_path', None)
        session.pop('current_location', None)
        session.pop('current_location_name', None)

    flash("Successfully deleted '" + selected_engagement + "'.")
    return redirect('/select_engagement')
