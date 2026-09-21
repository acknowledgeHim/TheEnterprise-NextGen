import requests
import sys
import myparser
import re
import time
import print_text
from API_KEYS import GOOGLE_CSE_API_KEY

class search_googleCSE:
    def __init__(self, word, limit, start, additional_word_to_search, site_search):
        self.word = word
        self.files = "pdf"
        self.results = ""
        self.totalresults = ""
        self.server = "www.googleapis.com"
        self.hostname = "www.googleapis.com"
        self.userAgent = "(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6"
        self.quantity = "10"
        self.limit = limit
        self.counter = 1
        self.api_key = GOOGLE_CSE_API_KEY
        self.cse_id = ""
        self.lowRange = start 
        self.highRange = start+100

    def do_search(self):
        try:
            urly = "http://" + str(self.server) + "/customsearch/v1?key=" + self.api_key +"&highRange=" + str(self.highRange) + "&lowRange=" + str(self.lowRange) + "&cx=" +self.cse_id + "&start=" + str(self.counter) + "&q=%40\"" + self.word + "\""
            r = requests.get(urly)

            self.results = str(r.content)
            self.totalresults += self.results
        except Exception as e:
            print_text.print_error("tool googleCSE search except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))


    def do_search_files(self, f):
        try:
            urly = "http://" + str(self.server) + "/customsearch/v1?key=" + self.api_key +"&highRange=" + str(self.highRange) + "&lowRange=" + str(self.lowRange) + "&cx=" +self.cse_id + "&start=" + str(self.counter) + "&q=filetype:" + f +"%20site:" + self.word
            r = requests.get(urly)

            self.results = str(r.content)
            self.totalresults += self.results
        except Exception as e:
            print_text.print_error("tool googleCSE file search except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def check_next(self):
        renext = re.compile('>  Next  <')
        nextres = renext.findall(self.results)
        if nextres != []:
            nexty = "1"
        else:
            nexty = "0"
        return nexty

    def get_emails(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.emails()

    def get_hostnames(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.hostnames()

    def get_files(self):
        rawres = myparser.parser(self.totalresults, self.word)
        return rawres.fileurls(self.files)

   
    def process(self, search_files=None):
        if self.api_key != "":
            try:
                tracker=self.counter + self.lowRange
                while tracker <= self.limit:
                    if search_files is None:
                        self.do_search()
                        # time.sleep(1)
                        ESC = chr(27)
                        sys.stdout.write(ESC + '[2K' + ESC + '[G')
                        sys.stdout.write("\r\t" + "Searching  " + str(self.counter + self.lowRange) + " results ...")
                        sys.stdout.flush()
                        # print "\tSearching " + str(self.counter+self.lowRange) + " results...\t\t\t\t\t\r"
                        if self.counter == 101:
                            self.counter = 1
                            self.lowRange += 100
                            self.highRange += 100
                        else:
                            self.counter += 10
                        tracker = self.counter + self.lowRange
                    else:
                        for f in search_files:
                            self.do_search_files(f)
                            #time.sleep(1)
                            ESC=chr(27)
                            sys.stdout.write(ESC + '[2K' + ESC+'[G')
                            sys.stdout.write("\r\t" + "Searching  " + str(self.counter+self.lowRange) + " results ..." )
                            sys.stdout.flush()
                            #print "\tSearching " + str(self.counter+self.lowRange) + " results...\t\t\t\t\t\r"
                            if self.counter == 101:
                                self.counter = 1
                                self.lowRange +=100
                                self.highRange +=100
                            else:
                                self.counter += 10
                            tracker=self.counter + self.lowRange
            except Exception as e:
                print_text.print_error("google CSE except: " +  str(e) +  " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        else:
            print_text.print_error("\tYou must enter your GOOGLE_CSE_API_KEY in enterprise_conf.py in order to use Google CSE.")

    def store_results(self):
             filename = "debug_results.txt"
             file = open(filename, 'w')
             file.write(self.totalresults)


    def process_files(self, files):
        while self.counter <= self.limit:
            self.do_search_files(files)
            time.sleep(1)
            self.counter += 100
            print_text.print_msg("\tSearching " + str(self.counter) + " results...")
