import requests
import myparser
import time
import sys
import print_text


class search_baidu:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = "www.baidu.com"
        self.hostname = "www.baidu.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.limit = limit
        self.counter = 0

    def do_search(self):
        try:
            urly = "http://" + str(self.server) + "/s?wd=%40" + self.word + "&pn=" + str(self.counter)
            r = requests.get(urly)

            self.results = str(r.content)
            self.total_results += self.results
        except Exception as e:
            print_text.print_error("tool baidusearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def process(self):
        while self.counter <= self.limit and self.counter <= 1000:
            self.do_search()
            time.sleep(1)

            print_text.print_msg("\tSearching " + str(self.counter) + " results...")
            self.counter += 10

    def get_emails(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.hostnames()
