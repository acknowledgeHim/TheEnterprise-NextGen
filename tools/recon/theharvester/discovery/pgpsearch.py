import requests
import sys
import myparser
import print_text

class search_pgp:

    def __init__(self, word):
        self.word = word
        self.total_results = ""
        self.server = "pgp.mit.edu"
        #self.server = "pgp.rediris.es:11371" Not  working at the moment
        self.hostname = "pgp.mit.edu"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        
    def process(self):
        try:
            urly = "http://" + str(self.server) + "/pks/lookup?search=" + self.word + "&op=index"
            r = requests.get(urly)

            self.results = str(r.content)
            self.total_results += self.results
        except Exception as e:
            print_text.print_error("tool pgp search except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_emails(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.hostnames()
