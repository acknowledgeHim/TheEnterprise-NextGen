import sys
import requests
from common import print_text

class RabbitMQMonitor():

    def __init__(self, hostname, port , username, password):
        # Make connection to RabbitMQ
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def connect(self, action, url):
        try:
            if action == "GET":
                response = requests.get("http://" + self.hostname +":" + str(self.port) + url, auth=(self.username, self.password))
            else:
                response = requests.post("http://" + self.hostname + ":" + self.port + url, auth=(self.username, self.password))
            return response
        except Exception as e:
            print_text.print_error("rabbitmq monitoring except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def get_queued_messages(self):
        try:
            url = "/queues/vhost/celery/get"

            response = self.connect("GET", url)

            print("25 rabbitmq_monitoring response: " + str(response))
        except Exception as e:
            print_text.print_error("rabbitmq monitoring except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
