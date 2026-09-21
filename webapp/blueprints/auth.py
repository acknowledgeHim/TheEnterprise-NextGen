from flask import Blueprint, flash, request, session

from common import database_object, keep_tags
from webapp.blueprints.engagements import select_engagement
from webapp.blueprints.main import home

auth_bp = Blueprint("auth", __name__)


@auth_bp.route('/login', methods=['POST'])
def do_login():
    """ Login. """
    user = keep_tags.clean_text(request.form['username'])
    passwd = keep_tags.clean_text(request.form['password'])

    correct_key_entered = database_object.verify_key_connect_to_emailevent_db(user, passwd)
    if correct_key_entered:
        session['key'] = passwd
        session['logged_in'] = True
        session['username'] = user
    else:
        flash('Wrong credential, try again!')
    return select_engagement()


@auth_bp.route("/logout")
def logout():
    session.clear()
    session['logged_in'] = False
    return home()
