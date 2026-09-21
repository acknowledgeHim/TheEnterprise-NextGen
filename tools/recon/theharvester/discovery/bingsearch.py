import requests
import sys
import myparser
import time
import print_text
from API_KEYS import BING_API_KEY

class search_bing:

    def __init__(self, word, limit, start):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.totalresults = ""
        self.server = "www.bing.com"
        self.apiserver = "api.search.live.net"
        self.hostname = "www.bing.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "50"
        self.limit = int(limit)
        self.bingApi = BING_API_KEY
        self.counter = start

    def do_search(self):
        try:
            urly = "http://" + str(self.server) + "/search?q=%40" + self.word + "&count=50&first=" + str(self.counter)
            r = requests.get(urly)

            self.results = str(r.content)
            self.totalresults += self.results

        except Exception as e:
            print_text.print_error("tool bingsearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def do_search_api(self):
        try:
            urly = "http://" + str(self.apiserver) + "/xml.aspx?Appid=" + self.bingApi + "&query=%40" + self.word + "&sources=web&web.count=40&web.offset=" + str(self.counter)
            r = requests.get(urly)

            self.results = str(r.content)
            self.totalresults += self.results
        except Exception as e:
            print_text.print_error("tool bingsearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def do_search_vhost(self):
        try:
            urly = "http://" + str(self.server) + "/search?q=ip:" + self.word + "&go=&count=50&FORM=QBHL&qs=n&first=" + str(self.counter)
            r = requests.get(urly)

            self.results = str(r.content)
            self.totalresults += self.results
        except Exception as e:
            print_text.print_error("tool bingsearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_allhostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames_all()

    def process(self, api):
        try:
            if api == "yes":
                if self.bingApi == "":
                    print_text.print_msg("Please insert your API key in the discovery/bingsearch.py")
                    sys.exit()
            while (self.counter < self.limit):
                if api == "yes":
                    self.do_search_api()
                    time.sleep(0.3)
                else:
                    self.do_search()
                    time.sleep(1)
                self.counter += 50
                print_text.print_msg("\tSearching " + str(self.counter) + " results...")
        except Exception as e:
            print_text.print_error("tool bingsearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def process_vhost(self):
        # Maybe it is good to use other limit for this.
        while (self.counter < self.limit):
            self.do_search_vhost()
            self.counter += 50
