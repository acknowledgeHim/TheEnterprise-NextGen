import sys
import myparser
import time
import requests
from random import randint
import print_text

class search_google:

    def __init__(self, word, limit, start, additional_word_to_search, site_search):
        self.word = word
        self.results = ""
        self.totalresults = ""
        self.server = "www.google.com"
        self.userAgent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; Trident/5.0)" #"(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.headers = {'User-Agent': self.userAgent}
        self.quantity = "100"
        self.limit = limit
        self.counter = start
        self.prev_filetype = ""
        self.filetype = ""

        if ":" in self.word:
            tmp = self.word.split(":")
            self.word = tmp[0]
            self.filetype = tmp[1]

        self.additional_word_to_search = additional_word_to_search
        self.site_search = site_search
        self.q = "q="
        if self.site_search == True:
            self.q = self.q + "site:" + str(self.word)
        elif isinstance(self.site_search, str) and len(self.site_search) > 1:
            self.q = self.q +"site:" + self.site_search
        else:
            self.q = self.q + str(self.word)
        if self.additional_word_to_search is not None and self.additional_word_to_search.strip() != "":
            self.q = self.q + "+" + self.additional_word_to_search

  
    def do_search(self):
        try:
            #urly = "http://" + str(self.server) + "/search?num=" + str(self.quantity) + "&start=" + str(self.counter) + "&hl=en&meta=&q=%40\"" + str(self.word) + "\""
            urly = "http://" + str(self.server) + "/search?num=" + str(self.quantity) + "&start=" + str(
                self.counter) + "&hl=en&meta=&" + self.q

            r = requests.get(urly)

            self.results = str(r.content)
            self.totalresults += self.results
        except Exception as e:
            print_text.print_error("google except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def do_search_files(self, f):
        try:
            #urly = "https://" + str(self.server) + "/search?q=" + str(self.word) + "+filetype%3A"+f+"&start=" + str(self.counter) + "&*#q=" + str(self.word) + "+filetype:"+f+"&safe=active&start=" + str(self.counter) + "&*"
            urly = "https://" + str(self.server) + "/search?" +self.q + "+filetype%3A"+f+"&start=" + str(self.counter) + "&*#" + self.q + "+filetype:"+f+"&safe=active&start=" + str(self.counter) + "&*"

            r = requests.get(urly, headers=self.headers)

            self.results = str(r.content)

            self.totalresults += self.results
        except Exception as e:
            print_text.print_error("google except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def do_search_profiles(self):
        try:
            urly = "http://" + self.server + "/search?num=" + self.quantity + "&start=" + str(self.counter) + "&hl=en&meta=&"+self.q+"+site:www.google.com%20intitle:\"Google%20Profile\"%20\"Companies%20I%27ve%20worked%20for\"%20\"at%20" + self.word + "\""
            r = requests.get(urly)
        except Exception as e:
            print_text.print_error("google except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

        self.results = str(r.content)
        self.totalresults += self.results

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_names(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.names()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self, file_type):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.fileurls(file_type)

    def get_profiles(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.profiles()


    def process(self, search_files=None):
        try:
            if search_files is None:
                while self.counter <= self.limit and self.counter <= 1000:
                    self.do_search()
                    #more = self.check_next()
                    time.sleep(1)
                    print_text.print_msg("\tSearching " + str(self.counter) + " results...")
                    self.counter += 100
        except Exception as e:
            print_text.print_error("\tgooglesearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
            
    def process_profiles(self):
        try:
            while self.counter < self.limit:
                self.do_search_profiles()
                time.sleep(0.3)
                self.counter += 100
                print_text.print_msg("\tSearching " + str(self.counter) + " results...")
        except Exception as e:
            print_text.print_error("\tgooglesearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def process_files(self):
        try:
            self.limit = 50
            while self.counter < self.limit:
                self.do_search_files(self.filetype)
                time.sleep(3 * randint(7,29) + 4)
                if self.prev_filetype != self.filetype:
                    self.prev_filetype = self.filetype
                    self.counter = 0
                self.counter += 10
                print_text.print_msg("\tSearching " + str(self.counter) + " results for file type: " + self.filetype + "...")
        except Exception as e:
            print_text.print_error("\tgooglesearch except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))