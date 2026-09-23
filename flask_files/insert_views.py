import os
import shutil
import sys
from datetime import datetime
from flask_files import common_flask
from common import common, sqlalchemy_model
from setup import current_location
from enterprise_user_conf import OUTPUT_PATH

def validate_input(table_name, inputs, request):
    """ Validates the input based on the regex for that field.
    Returns (field_values, None) on success or (None, reason) on failure - a specific reason
    naming the field, rather than the generic "your posted data was not valid" this used to
    leave insert() to report regardless of which of several different problems actually
    happened. """
    required_fields = sqlalchemy_model.retrieve_required_fields(table_name)
    try:
        # Validate input
        field_values = {}
        for input in inputs:
            post_data = request.form.get(input[1])
            if post_data is None:
                # The submitted form didn't have this field at all - a name mismatch between
                # the rendered form and this list, not the user having left it blank (that's
                # post_data == "", handled below same as always). Distinct case because
                # post_data.strip() on the old code crashed here with an unhandled
                # AttributeError instead of reporting anything useful.
                if input[1] in required_fields:
                    return None, input[0] + " is required but was not submitted."
                post_data = ""
            value = post_data.strip()
            if "_date" in input[1]:
                if value == "":
                    value = None
                else:
                    value = datetime.strptime(value, '%Y-%m-%d')

            if common.regex_exist_in_entry(value, input[2]) == "" and input[1] in required_fields:
                return None, input[0] + " (\"" + str(value) + "\") did not match the required format."

            if value == "Y":
                value = True
            elif value == "N":
                value = False

            field_values[input[1]] = value
        return field_values, None

    except Exception as e:
        print("flask-files/insert_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))#, file=sys.stderr)
        return None, "Error validating input: " + str(e)


def insert(session, inputs, request, table_name, column_names, header_names):
    """ Actually does the inserting. """
    try:
        field_values, validation_error = validate_input(table_name, inputs, request)

        selected_engagement = session.get('selected_engagement')

        repo_file = common_flask.grab_repo_file(session.get('engagement_path'), selected_engagement)

        if table_name == "Engagement":
            created_tables = sqlalchemy_model.initialize(repo_file)
            # initialize() returns False (never raises) if Base.metadata.create_all() failed -
            # continuing past that meant trying to insert into tables that were never created,
            # a much more confusing failure than reporting the real problem right here.
            if not created_tables:
                return "Failed.  Could not create the database tables for this engagement at " + repo_file + ".", None
            common.assign_permissions(repo_file)

        db_object = common_flask.create_db_object(session.get('engagement_path'), selected_engagement,
                                                  session.get('key'), session.get('username'))

        if not isinstance(db_object, str):
            if field_values is not None:
                success, hashval = db_object.add(table_name, field_values)
                # add() returns (True, hashval) on success or (error message, None) on failure -
                # it never raises for a DB-level failure, it just swallows the exception
                # internally (see common/sqlalchemy_db.py). Not checking this meant a failed
                # Engagement insert (this is the table_name=="Engagement" call path -
                # insert_engagement() in this same file) still reported success and handed back
                # a db_object as if the Engagement row existed - it didn't, and every later
                # Scope add crashed on "'NoneType' object is not iterable" trying to read
                # Engagement.external_only for a row that was never created.
                if success is not True:
                    return "Failed inserting " + table_name + ", error: " + str(success), None
                return "Successfully inserted " + table_name + ".", db_object
            else:
                return "Failed.  " + (validation_error or "Your posted data to insert was not valid."), None
        else:
            return "Failed.  Not sure what happened here but problems connecting to the repo.  Try again?", None
    except Exception as e:
        print("flask-files/insert_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        return "Failed.  Error: " + str(e), None


def insert_engagement(session, request):
    """ Creates a new engagement - folder structure, DB tables/rows, default Location - as a
    single all-or-nothing operation. Any failure at any step rolls back everything this
    specific call created (deletes the engagement's own folder, which also removes its DB file,
    and clears the session keys this function itself set) instead of leaving a half-created
    engagement around for other code to trip over later. That's exactly how one Scope add
    crashed on "'NoneType' object is not iterable" for every attempt: an earlier bug here let a
    failed Engagement-row insert still report success and hand back a working-looking
    db_object, leaving an engagement whose folder and default Location existed but whose
    Engagement row didn't.

    The previous version of this function also had a real bug independent of any of that: if
    the *first* create_path() call (the client-level folder) failed, it fell through to using
    the client-level path as engagement_path and called insert() anyway, instead of returning -
    silently creating/inserting into whatever engagement was already in `session`, or crashing
    if there wasn't one. """
    created_path = None
    session_keys_set = []

    def fail(message):
        if created_path:
            try:
                shutil.rmtree(created_path)
            except Exception as cleanup_error:
                message = message + "  (Additionally failed to clean up " + created_path + ": " + str(cleanup_error) + " - remove it manually.)"
        for key in session_keys_set:
            session.pop(key, None)
        return message

    # select_engagement() (webapp/blueprints/engagements.py) sets session['selected_engagement']
    # to the literal string "Create New Client/Engagement" before this function ever runs (it's
    # how it recognized the "show the create form" case). If this call fails before reaching the
    # point where it overwrites that with a real engagement identifier, that placeholder is still
    # sitting in session - engagement()'s `if 'selected_engagement' in session: return home()`
    # would then treat it as a real, selected engagement and crash in home() trying to use an
    # engagement_path that was never set. Clearing it up front means every failure path below,
    # including ones that return before setting anything themselves, leaves session correctly
    # showing no engagement selected.
    session.pop('selected_engagement', None)

    try:
        from setup.engagement import MANUAL_FIELDS, MORE_MANUAL_FIELDS, COLUMN_NAMES, HEADER_NAMES
        inputs = [["Client Number", "client_number", r'^(?:[\d\-]+)$'],
                  ["Client Name", "client_name", r'^(?:[a-zA-Z_ \-0-9]+)$'],
                  ["Engagement Number", "engagement_number", r'^(?:[a-zA-Z_\-0-9]+)$']] \
                 + MANUAL_FIELDS + MORE_MANUAL_FIELDS

        client_number = (request.form.get('client_number') or '').strip()
        client_name = (request.form.get('client_name') or '').strip()
        engagement_number = (request.form.get('engagement_number') or '').strip()
        if not client_number or not client_name or not engagement_number:
            return "Failed.  Client Number, Client Name, and Engagement Number are all required."

        client_segment = client_number + "__" + client_name.replace(" ", "_") + "/"
        client_path = OUTPUT_PATH + client_segment
        # The client-level folder can legitimately already exist (a second engagement for the
        # same client) - create_path() treats "already exists" as success - and isn't ours to
        # roll back even on later failure, since other engagements for this client may already
        # live under it.
        if not common.create_path(client_path):
            return "Failed.  Could not create the necessary folder structure.  Please check your permissions to " + client_path + "."

        selected_engagement = client_segment + engagement_number + "/"
        path = OUTPUT_PATH + selected_engagement
        # Reject a duplicate outright rather than proceeding into it: create_path() treats
        # "already exists" as success, and if this folder is already here for *any* reason
        # (a genuine duplicate submission, or - the case this whole rewrite exists to prevent -
        # a previous creation attempt that failed partway through and didn't get rolled back)
        # a later failure below must not delete it via `created_path` - that folder could hold
        # a perfectly good, already-created engagement. Checking here, before create_path() has
        # touched anything, means `created_path` below is only ever a folder this call itself
        # just brought into existence, safe to roll back unconditionally on any later failure.
        if os.path.isdir(path):
            return "Failed.  An engagement already exists at " + path + ".  Choose a different Client Number, " \
                   "Client Name, or Engagement Number, or select the existing engagement instead of creating a new one."
        if not common.create_path(path):
            return "Failed.  Could not create the necessary folder structure.  Please check your permissions to " + path + "."
        created_path = path  # this folder is new - we just created it, so it's ours to roll back

        session['engagement_path'] = path
        session_keys_set.append('engagement_path')
        session['selected_engagement'] = selected_engagement.rstrip("/")
        session_keys_set.append('selected_engagement')
        session['selected_engagement_number'] = engagement_number
        session_keys_set.append('selected_engagement_number')

        result, db_object = insert(session, inputs, request, "Engagement", COLUMN_NAMES, HEADER_NAMES)
        if db_object is None:
            return fail(result)

        version_success, _ = db_object.add("Information", {'version': '1.0'})
        if version_success is not True:
            return fail("Failed.  Could not finish creating the engagement, error: " + str(version_success))

        location_success, _ = db_object.add("Location", {'name': 'main'})
        if location_success is not True:
            return fail("Failed.  Could not create the engagement's default Location, error: " + str(location_success))

        # Now assign current location as default 'main' location - safe to assume id '1' since
        # this Location insert just above is the very first row this brand-new table has ever
        # had.
        session['current_location'] = '1'
        session_keys_set.append('current_location')
        session['current_location_name'] = 'main'
        session_keys_set.append('current_location_name')
        current_location_dict = {"current_location": '1', 'modified_by': db_object.current_tester}
        current_location_success, _ = db_object.add("CurrentLocation", current_location_dict)
        if current_location_success is not True:
            return fail("Failed.  Could not set the engagement's current location, error: " + str(current_location_success))

        return result

    except Exception as e:
        print("flask-files/insert_views.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno), file=sys.stderr)
        return fail("Failed.  Error: " + str(e))

        return "Failed.  Error: " + str(e)