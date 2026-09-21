from .shodan import WebAPI
import sys
import print_text
from API_KEYS import SHODAN_API_KEY

class search_shodan():

    def __init__(self, host):
        self.host = host
        self.key = SHODAN_API_KEY #"oCiMsgM6rQWqiTvPxFHYcExlZgg7wvTt"
        if self.key == "":
            print_text.print_error("You need an API key in order to use SHODAN database. You can get one here: http://www.shodanhq.com/")
            sys.exit()
        self.api = WebAPI(self.key)

    def run(self):
        try:
            host = self.api.host(self.host)
            return host['data']
        except:
            print_text.print_error("SHODAN empty reply or error in the call")
            return "error"
