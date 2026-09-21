import os

from flask import Flask
from flask_wtf import CSRFProtect

from enterprise_user_conf import FLASK_FILE_UPLOAD_LIMIT, FLASK_KEY, OUTPUT_PATH
from webapp.auth_guard import register_auth_guard
from webapp.logging_config import configure_logging

# templates/ and static/ live at the repo root, not under webapp/ - Flask's
# default (relative to this package's own directory) would miss them.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app():
    app = Flask(__name__,
                template_folder=os.path.join(REPO_ROOT, "templates"),
                static_folder=os.path.join(REPO_ROOT, "static"))
    app.config['SECRET_KEY'] = FLASK_KEY
    app.config['MAX_CONTENT_LENGTH'] = int(FLASK_FILE_UPLOAD_LIMIT) * 1024 * 1024  # file upload limit in MB
    app.config['UPLOAD_FOLDER'] = OUTPUT_PATH + "tmp_file_upload/"  # uploaded files should go to specific client (ie. OUTPUT_PATH/0__Test/0/file_uploads/)

    configure_logging(app)

    CSRFProtect(app)

    from webapp.blueprints.main import main_bp
    from webapp.blueprints.auth import auth_bp
    from webapp.blueprints.engagements import engagements_bp
    from webapp.blueprints.jobs import jobs_bp
    from webapp.blueprints.records import records_bp
    from webapp.blueprints.tools import tools_bp
    from webapp.blueprints.files import files_bp
    from webapp.blueprints.reports import reports_bp

    for blueprint in (main_bp, auth_bp, engagements_bp, jobs_bp, records_bp, tools_bp, files_bp, reports_bp):
        app.register_blueprint(blueprint)

    register_auth_guard(app)

    return app
