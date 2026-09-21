import sys
from threading import Timer, Lock
from tools.metasploit.msfrpc import ShellSession
from common import print_text

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMetasploit Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.3'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@cygnos.com'
__status__ = 'Development'

__all__ = [
    'MsfRpcConsole'
]
# Modified by Kevin Huber for Python 3 March 2017


class MsfRpcConsoleType:
    Console = 0
    Meterpreter = 1
    Shell = 2


class MsfRpcConsole(object):

    def __init__(self, rpc, sessionid=None, cb=None):
        """
        Emulates the msfconsole in msf except over RPC.

        Mandatory Arguments:
        - rpc : an msfrpc client object

        Optional Arguments:
        - cb : a callback function that gets called when data is received from the console.
        """
        try:
            self.junk = 0
            self.callback = cb
            self.output_txt = ""

            if sessionid is not None:
                self.console = rpc.sessions.session(sessionid)
                self.type_ = MsfRpcConsoleType.Shell if isinstance(self.console, ShellSession) else MsfRpcConsoleType.Meterpreter
                self.prompt = '>>> '
                self.callback(dict(data='', prompt=self.prompt))
            else:
                self.console = rpc.consoles.console()

                self.type_ = MsfRpcConsoleType.Console

                self.prompt = ''

            self.lock = Lock()

            self.running = True

            self._poller()
        except Exception as e:
            print_text.print_error("tool msfconsole except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def _poller(self):
        try:
            self.lock.acquire()

            if not self.running:
                return

            d = self.console.read()

            if isinstance(d, dict):
                if b'result' in d:
                    if d[b'result'] == b'failure':
                        return

            self.lock.release()

            if self.type_ == MsfRpcConsoleType.Console:
                if b'data' in d:
                    if d[b'data'] or self.prompt != d[b'prompt']:
                        self.prompt = d[b'prompt'].decode('utf-8')
                        data = d[b'data'].decode('utf-8')
                        if self.callback is not None:
                            self.callback(data)
                        else:
                            #print_text.print_msg(data)
                            self.output_txt = self.output_txt + data

                        if "(100% complete)" in data:
                            return self.output_txt
                elif 'result' in d:
                    return
            else:
                if d:
                    if self.callback is not None:
                        self.callback(dict(data=d, prompt=self.prompt))
                    else:
                        #print_text.print_msg(d)
                        self.output_txt = self.output_txt + d
                if "(100% complete)" in d:
                    return self.output_txt

            Timer(0.9, self._poller).start()

        except Exception as e:
            print_text.print_error("tool msfconsole except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def execute(self, command):
        """
        Execute a command on the console.

        Mandatory Arguments:
        - command : the command to execute
        """
        try:
            if not command.endswith('\n'):
                command += '\n'
            self.lock.acquire()

            self.console.write(command)
            self.lock.release()
        except Exception as e:
            print_text.print_error("tool msfconsole except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    def output(self):
        return self.console.read()

    def destroy(self):
        self.console.destroy()

    def __del__(self):
        self.lock.acquire()
        if self.type_ == MsfRpcConsoleType.Console:
            self.console.destroy()
        self.running = False
        self.lock.release()
