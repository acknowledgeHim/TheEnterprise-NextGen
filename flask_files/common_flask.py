import logging
import os
from common import common
from setup.client_engagement import ClientEngagement
from setup import profile
from enterprise_user_conf import OUTPUT_PATH
from common.database_object import OurCoolDBObject

logger = logging.getLogger(__name__)


def _single_visible_link(children):
    """
    Many Setup groups (Location, Scope, Client Contact, ...) list a "View X" entry plus several
    CRUD siblings (Add/Update/Delete X) whose url is None - CLI-only entries the web view already
    skips (see loop_through_menu's docstring) - because those actions are reachable from buttons
    on the View X page itself (see table_class.py's "Insert X"/edit/delete controls). That leaves
    a dropdown that only ever offers one real choice, so it costs a click for nothing. Returns
    that one URL so the caller can render the group as a single direct link instead, or None if
    the group has more than one real choice (e.g. Recon > Amass) and should stay a dropdown.
    """
    visible_links = [child for child in children if child[1] is not None and not isinstance(child[1], list)]
    has_nested_submenu = any(isinstance(child[1], list) for child in children)
    if len(visible_links) == 1 and not has_nested_submenu:
        return visible_links[0][1]
    return None


def loop_through_menu(menu, top_level=True):
    """
    Recursively loops through each menu item, if child found then calls itself to loop through sub layer, etc.
    Emits Bootstrap 5 navbar-nav markup (nav-item/dropdown/dropdown-menu/dropdown-item), since Bootstrap's
    own dropdown JS (data-bs-toggle) replaced the old SmartMenus-based nav.

    :param menu: a nested list where list.0 is Name to display, list.1 is a URL string, None (CLI-only entry,
        skipped in the web view), or a further nested list for a submenu.
    :return: string of the current navigation menu
    """
    nav_menu = ''
    for item in menu:
        name = item[0]
        url = item[1]
        if url is None:
            continue

        if isinstance(url, list):
            single_url = _single_visible_link(url)
            if single_url is not None:
                link_class = "nav-link" if top_level else "dropdown-item"
                item_open = '<li class="nav-item">' if top_level else '<li>'
                nav_menu = nav_menu + item_open + '<a class="' + link_class + '" href="' + single_url + '">' + name + '</a></li>'
                continue

            child_menu = loop_through_menu(url, top_level=False)
            if child_menu.strip() != "":
                item_class = "nav-item dropdown" if top_level else "dropdown dropdown-submenu"
                toggle_class = "nav-link dropdown-toggle" if top_level else "dropdown-item dropdown-toggle"
                # autoClose="outside": without it, Bootstrap's default autoClose=true treats a
                # click on a nested submenu toggle (e.g. Setup > Location) as a click "outside"
                # this dropdown (the toggle link isn't a descendant of *this* menu's own toggle),
                # so it closes this dropdown - and with it, the submenu that click just opened,
                # since the submenu lives inside it. Net effect: clicking a submenu item appeared
                # to do nothing. "outside" only closes on a real click outside the whole menu tree.
                nav_menu = nav_menu + ('<li class="' + item_class + '"><a class="' + toggle_class +
                    '" href="#" role="button" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">' + name +
                    '</a><ul class="dropdown-menu">' + child_menu + '</ul></li>')
        else:
            link_class = "nav-link" if top_level else "dropdown-item"
            item_open = '<li class="nav-item">' if top_level else '<li>'
            nav_menu = nav_menu + item_open + '<a class="' + link_class + '" href="' + url + '">' + name + '</a></li>'
    return nav_menu


def just_db_object(repo_file):
    db_object = None
    if os.path.isfile(repo_file):
        try:
            db_object = OurCoolDBObject(repo_file)
            return db_object
        except Exception as e:
            logger.exception("just_db_object failed: %s", e)
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
                logger.exception("create_db_object failed: %s", e)
    except Exception as e:
        logger.exception("create_db_object failed: %s", e)

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
        logger.exception("setup_base_page failed: %s", e)

