import sys
import os
from common import common
from setup.client_engagement import ClientEngagement
from setup import profile
from enterprise_user_conf import OUTPUT_PATH
from common.database_object import OurCoolDBObject


def loop_through_menu(menu, count=0):
    """
    Recursively loops through each menu item, if child found then calls itself to loop through sub layer, etc.
    Returns a list of dict (can be many layers deep depending upon # of sub layers).

    :param menu: a nested list where list.0 is Name to display, list.1 is string containing app_name.url_mapper_method.url_append
        and optional list.2 can be a sub list for sub menu.
    :return: string of the current navigation menu
    """
    count += 1

    nav_menu = ''
    for item in menu:
        child_menu = ''
        url = item[1]
        if url is not None:
            if isinstance(url, str):
                nav_menu = nav_menu + '<li><a href="' + url + '">' + item[0]
            else:
                nav_menu = nav_menu + '<li><a href=#>' + item[0]

            if isinstance(item[1], list):
                child_menu =  loop_through_menu(item[1], count)
            if child_menu.strip() != "":
                nav_menu = nav_menu + '<span class="caret"></span></a><ul class="dropdown-menu">' + child_menu + '</ul></li>'
            else:
                nav_menu = nav_menu + '</a></li>'
    return nav_menu


def just_db_object(repo_file):
    db_object = None
    if os.path.isfile(repo_file):
        try:
            db_object = OurCoolDBObject(repo_file)
            return db_object
        except Exception as e:
            print("flask-files/common_flask.py except: " + str(e) + " Error on line {}".format(
                sys.exc_info()[-1].tb_lineno), file=sys.stderr)
    return db_object


def grab_repo_file(engagement_path, selected_engagement):
    """ Grab repo file path + name. """
    client_number = selected_engagement[:selected_engagement.rfind("__")]
    repo_file = engagement_path + client_number + ".out"
    return repo_file


def create_db_object(engagement_path, selected_engagement, key, username):
    """ Sets up the DB Object. """
    try:
        repo_file = grab_repo_file(engagement_path, selected_engagement)
        db_object = None
        if os.path.isfile(repo_file):
            try:
                db_object = OurCoolDBObject(repo_file, 'common.sqlalchemy_model', username)

                return db_object
            except Exception as e:
                print("flask-files/common_flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    except Exception as e:
        print("flask-files/common_flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return "Unable to initialize Repository.  Might want to verify that the client/engagement folder you " \
                   "selected has a .out file there."


def setup_base_page(session, db_object=None):
    try:
        tester = session.get('username')
        only_owner = False
        newer_than = 0
        """
        if db_object is not None and not isinstance(db_object, str):
            tester = db_object.current_tester
        try:
            profile_dictionary = profile.grab_profile()
            only_owner = profile_dictionary["only_owner"]
            newer_than = profile_dictionary["newer_than"]
        except Exception as e:
            print("89 common flask error: " + str(e))
            only_owner = False
            newer_than = 0
        if isinstance(only_owner, str):
            if only_owner == "True":
                only_owner = True
            else:
                only_owner = False
        if isinstance(newer_than, str):
            if newer_than.isdigit():
                newer_than = int(newer_than)
        """
        with ClientEngagement(OUTPUT_PATH, tester, only_owner, newer_than, session.get('key')) as ce:
            client_engagements = ce.grab_client_engagement_list("", None, 2)

        client_engagements.insert(0, "Create New Client/Engagement")

        engagements = "Select Client/Engagement<div class='list-group'>"
        for engagement in client_engagements:
            engagements = engagements + "<a class='list-group-item' href='/select_engagement?selected_engagement=" + engagement + "'>" + engagement + "</a>"

        return {'engagements': engagements + "</div>", 'tester': tester, 'only_owner': only_owner, 'newer_than': newer_than,
                'client_engagements': client_engagements}
    except Exception as e:
        print("flask-files/common_flask.py except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

