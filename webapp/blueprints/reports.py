import logging
import os
import sys

from flask import Blueprint, render_template, request, send_file, session

from common import print_text
from common.navigation_menu import NAVIGATION
from enterprise_user_conf import OUTPUT_PATH
from flask_files import common_flask
from flask_files.form_class import FormSetup
from webapp.blueprints.main import home

reports_bp = Blueprint("reports", __name__)
logger = logging.getLogger(__name__)


@reports_bp.route('/report/excel')
def excel_report():
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))
        engagement_info = db_object.view("Engagement")
        client_name = engagement_info[0]['client_name'].replace(" ", "_")
        engagement_number = engagement_info[0]['engagement_number']
        naming_convention = client_name + "__" + engagement_number + "_report.xlsx"

        from export.excel_export import Excel
        excel_report = Excel(db_object, engagement_path)
        excel_report.export(naming_convention)

        if os.path.isfile(engagement_path + naming_convention):
            return send_file(engagement_path + naming_convention)
        else:
            return home('Successfully generated the report which can be at: ' + engagement_path + naming_convention)
    except Exception as e:
        print_text.print_error("excel_report() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@reports_bp.route('/encrypt/all')
def encrypt_all(msg=''):
    """
    Setup encryption process.
    :return:
    """
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path')
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))
        with FormSetup('edit_entry', '/encrypt/run') as form:
            inputs = [['Encryption Password', 'encrypt_key_password', ''],
                      ['Confirm Encryption Password', 'confirm_encrypt_key_password', '']]
            html_form = form.create_form(inputs, "black_text")

        celery_cmd = session.get('celery_cmd')
        return render_template('main.html', engagements=engagements, menu_items=menu_items,
                               engagement_path="Current Engagement: " + engagement_path, celery_cmd=celery_cmd,
                               current_location="Current Working Location: " + session.get('current_location_name'),
                               content='Please enter the encryption password you would like to use below. '
                                       'This password will be required to decrypt.', celery=html_form, msg=msg)
    except Exception as e:
        print_text.print_error(
            "encrypt_all() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@reports_bp.route('/download_results/out')
def download_out(msg=''):
    """
    Setup encryption process.
    :return:
    """
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path').rstrip("/")
        engagement_num = engagement_path[engagement_path.rfind("/")+1:]

        client = engagement_path[engagement_path.find(OUTPUT_PATH)+len(OUTPUT_PATH):].rstrip("/")
        client_folder = client[:client.rfind("/")]
        client_info = client_folder.split("__")
        client_num = client_info[0]

        engagement_path = engagement_path + "/" + client_num + ".out"
        menu_items = common_flask.loop_through_menu(NAVIGATION)
        fname = engagement_path[engagement_path.rfind("/")+1:]
        return send_file(engagement_path, download_name=fname, as_attachment=True)
    except Exception as e:
        print_text.print_error("download_out() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


@reports_bp.route('/encrypt/run', methods=['POST'])
def encrypt():
    try:
        setup_dictionary = common_flask.setup_base_page(session)
        engagements = setup_dictionary['engagements']

        engagement_path = session.get('engagement_path').rstrip("/")
        engagement_number = engagement_path[engagement_path.rfind("/")+1:]
        client = engagement_path[engagement_path.find(OUTPUT_PATH)+len(OUTPUT_PATH):].rstrip("/")
        client = client[:client.rfind("/")]

        engagement_path = engagement_path + "/"
        menu_items = common_flask.loop_through_menu(NAVIGATION)

        db_object = common_flask.create_db_object(session.get('engagement_path'), session.get('selected_engagement'),
                                                  session.get('key'), session.get('username'))

        encrypt_key = request.form['encrypt_key_password']
        confirm_encrypt_key = request.form['confirm_encrypt_key_password']
        if encrypt_key == confirm_encrypt_key:
            from menus.encrypt_output import EncryptOutput
            with EncryptOutput(db_object, engagement_path) as encrypt_output:
                logger.debug("encrypt() starting EncryptOutput.all()")
                file_location = encrypt_output.all(encrypt_key)
                logger.debug("encrypt() file_location: %s", file_location)
            zip_name = client + "__" + engagement_number + ".zip"
            return send_file(file_location + zip_name, download_name=zip_name, as_attachment=True)
        else:
            return encrypt_all('Encryption Password and Confirm Encryption Password did not match!  Try again!')
    except Exception as e:
        print_text.print_error(
            "encrypt() except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return home('Error trying to encrypt error: ' + str(e))
