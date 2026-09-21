import os
import ssl

from enterprise_user_conf import DEVICE_IP, FLASK_PORT
from webapp import create_app

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('flask_files/flask.crt', 'flask_files/flask.key')

app = create_app()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=DEVICE_IP, port=FLASK_PORT, debug=debug_mode, ssl_context=context)
