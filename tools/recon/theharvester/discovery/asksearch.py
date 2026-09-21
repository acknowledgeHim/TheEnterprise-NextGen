import requests
import sys
import re
import myparser
from common import print_text


class search_ask:

    def __init__(self, word, limit):
        self.word = word.replace(' ', '%20')
        self.results = ""
        self.total_results = ""
        self.server = "www.ask.com"
        self.hostname = "www.ask.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "100"
        self.limit = int(limit)
        self.counter = 0

    def do_search(self):
        print("22 asksearch")
        try:
            urly = "http://" + str(self.server) + "/web?q=%40" + self.word + "&page=" + str(self.counter)
            print("25 asksearch urly: " + str(urly))
            r = requests.get(urly)
            print("27 asksearch")
            self.results = str(r.content)
            self.total_results += self.results
        except Exception as e:
            print_text.print_error("tool ask except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
        else:
            nexty = "0"
        return nexty

    def get_people(self):
        rawres = myparser.parser(self.total_results, self.word)
        return rawres.people_jigsaw()

    def process(self):
        try:
            print("47 asksearch")
            while (self.counter < self.limit):
                self.do_search()
                more = self.check_next()
                if more == "1":
                    self.counter += 100
                else:
                    break
        except Exception as e:
            print_text.print_error("tool ask except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))