'''
.       .1111...          | Title: gp3finder.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | Group Policy preference password finder
                   ..     |
GrimHacker        ..      |
                 ..       |
grimhacker.com  ..        |
@grimhacker    ..         |
----------------------------------------------------------------------------
GPPPFinder - Group Policy Preference Password Finder
    Copyright (C) 2015  Oliver Morton (Sec-1 Ltd)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'''

from __future__ import print_function
import logging
import argparse
import getpass

from lib.mscrypto import MSCrypto
from lib.finder import Finder
from lib.reporter import Reporter

__version__ = "$Revision: 4.0.2 $"
# $Source$


class GPPPFinder(object):
    """Group Policy preference password finder.
       Find and decrypt passwords on share, decrypt given cpassword
       or encrypt given password."""
    def __init__(self, **kwargs):
        """Initialise GPPPFinder"""
        self.log = logging.getLogger(__name__)
        self._ciphertext = kwargs.get('decrypt')
        self._plaintext = kwargs.get('encrypt')
        self._auto = kwargs.get('auto')
        self._remote = kwargs.get('remote', True)
        self._remote_root = kwargs.get('remote_root', r"")
        self._local = kwargs.get('local', False)
        self._local_root = kwargs.get('local_root', r"C:\ProgramData\Microsoft\Group Policy\History")

        if not sum([bool(self._ciphertext), bool(self._plaintext), self._auto]) == 1:  # bool inherits int, so we can add them together.
            # check that only one mode has been specified.
            raise Exception("Must specify only one of encrypt, decrypt, auto.")

        self._outfile = kwargs.get('outfile')
        self._hosts = kwargs.get('hosts')
        self._share = kwargs.get('share')

        self._domain = ""
        self._password = None
        self._user = None
        if kwargs.get('user') is not None:
            self._get_creds(kwargs.get('user'), kwargs.get('password'))

        if self._auto:
            # if running in auto mode, check that the required information has been provided
            if self._remote and not (self._hosts and self._share and self._user is not None and self._password is not None):  # note domain isn't in this check because an empty string is False but is a valid option.
                raise Exception("Must specify host, share and credentials.")
            elif self._local and not self._local_root:
                raise Exception("Must specify local_root.")
            elif not (self._remote or self._local):
                raise Exception("Must specify either local or remote for auto running.")
            else:
                pass

    def _get_creds(self, user, password):
        """Parse credentials for authentication."""
        try:
            if "\\" in user:  # domain\username
                self._domain, self._user = user.split("\\")
            elif "/" in user:  # domain/username:
                self._domain, self._user = user.split("/")
            elif "@" in user:  # username@domain
                self._user, self._domain = user.split("@")
            else:
                self._user = user
        except Exception as e:
            raise Exception("Error parsing user, should be 'user' or 'domain\\user' or 'domain/user' or 'user@domain'.")
        if password is None:
            try:
                self._password = getpass.getpass()
            except Exception as e:
                raise Exception("Error getting password. {0}".format(e))
        else:
            self._password = password

    @property
    def ciphertext(self):
        """Return ciphertext."""
        return self._ciphertext

    @property
    def plaintext(self):
        """Return plaintext."""
        return self._plaintext

    @property
    def auto(self):
        """Return auto."""
        return self._auto

    @property
    def local(self):
        """Return local flag."""
        return self._local

    @property
    def local_root(self):
        """Return local_root."""
        return self._local_root

    @property
    def remote(self):
        """Return remote flag."""
        return self._remote

    @property
    def remote_root(self):
        """Return remote_root."""
        return self._remote_root
    @property
    def outfile(self):
        """Return output filename."""
        return self._outfile

    @property
    def hosts(self):
        """Return hosts to authenticate to."""
        return self._hosts

    @property
    def share(self):
        """Return share to map."""
        return self._share

    @property
    def domain(self):
        """Return domain to authenticate with."""
        return self._domain

    @property
    def user(self):
        """Return user to authenticate with."""
        return self._user

    @property
    def password(self):
        """Return password to authenticate with."""
        return self._password

    def _encrypt(self):
        """Encrypt plaintext."""
        try:
            crypto = MSCrypto()
        except Exception as e:
            raise Exception("Error initalising MSCrypto. {0}".format(e))
        else:
            try:
                warning, ciphertext = crypto.encrypt(self.plaintext)
            except Exception as e:
                raise Exception("Error running encryption. {0}".format(e))
            else:
                return warning, ciphertext

    def _decrypt(self):
        """Decrypt ciphertext."""
        try:
            crypto = MSCrypto()
        except Exception as e:
            raise Exception("Error initalising MSCrypto. {0}".format(e))
        else:
            try:
                plaintext = crypto.decrypt(self.ciphertext)
            except Exception as e:
                raise Exception("Error running decryption. {0}".format(e))
            else:
                return plaintext

    def _autopwn(self):
        """Discover and decrypt."""
        def run_finder(finder):
            self.log.debug("running finder...")
            try:
                finder.run()
            except Exception as e:
                raise Exception("Error running finder. {0}".format(e))
            else:
                self.log.debug("getting cpasswords and password_files from finder...")
                cpasswords = []
                password_files = []
                try:
                    cpasswords = finder.cpasswords
                except Exception as e:
                    self.log.warning("Error getting cpasswords. {0}".format(e))
                try:
                    password_files = finder.password_files
                except Exception as e:
                    self.log.warning("Error getting password files.")
                return cpasswords, password_files

        cpasswords = []
        password_files = []
        if self.remote:
            for host in self.hosts:  # TODO: Threading?
                self.log.info("Working on: {0}".format(host))
                try:
                    self.log.debug("initialising finder for remote search...")
                    finder = Finder(host=host,
                                    share=self.share,
                                    remote_root=self.remote_root,
                                    domain=self.domain,
                                    user=self.user,
                                    password=self.password)
                except Exception as e:
                    self.log.warning("Error initialising finder for remote search. {0}".format(e))
                    continue
                else:
                    try:
                        new_cpasswords, new_password_files = run_finder(finder)
                        cpasswords += new_cpasswords
                        password_files += new_password_files
                    except Exception as e:
                        self.log.warning("Error running finder. {}".format(e))
        elif self.local:
            try:
                self.log.debug("initialising finder for local search...")
                finder = Finder(local_root=self.local_root)
            except Exception as e:
                raise Exception("Error initialising finder for local search. {0}".format(e))
            else:
                cpasswords, password_files = run_finder(finder)
        else:
            raise Exception("Must specify either local or remote autopwning.")

        self.log.debug("reporting...")
        try:
            report = Reporter(cpasswords=cpasswords, password_files=password_files, output_file=self.outfile)
            report.run()
        except Exception as e:
            raise Exception("Error reporting results. {0}".format(e))
        else:
            self.log.info("Reporting complete. Check: '{0}'".format(self.outfile))

    def run(self):
        """Run GPPPFinder."""
        if self.ciphertext is not None:
            try:
                decrypted = self._decrypt()
            except Exception as e:
                self.log.critical("Failed to decrypt. {0}".format(e))
            else:
                print(decrypted)
        elif self.plaintext is not None:
            try:
                warning, encrypted = self._encrypt()
            except Exception as e:
                self.log.critical("Failed to encrypt. {0}".format(e))
            else:
                print(warning)
                print(encrypted)
        elif self.auto is not None:
            try:
                self._autopwn()
            except Exception as e:
                self.log.critical("Failed to auto get and decrypt passwords. {0}".format(e))
            else:
                pass
        else:
            self.log.critical("Nothing to do. Specify encrypt decrypt or auto.")


def print_version():
    """Print command line version banner."""
    print("""

.       .1111...          | Title: gp3finder.py {0}
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | Group Policy preference password finder
                   ..     | Find and decrypt passwords on share or decrypt
GrimHacker        ..      | given cpassword or encrypt given password.
                 ..       | Requires: PyCrypto
grimhacker.com  ..        |           PyWin32 on Windows
@grimhacker    ..         |           Permissions to mount/map shares
----------------------------------------------------------------------------
""".format(__version__))


def setup_logging(verbose=True, log_file=None):
    """Configure logging."""
    if log_file is not None:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s: %(levelname)s: %(module)s: %(message)s",
                            filename=log_file,
                            filemode='w')
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter("%(levelname)s: %(module)s: %(message)s")
        console_handler.setFormatter(formatter)
        if verbose:
            console_handler.setLevel(logging.DEBUG)
        else:
            console_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(console_handler)
    else:
        if verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO
        logging.basicConfig(level=level,
                            format="%(levelname)s: %(module)s: %(message)s")


if __name__ == '__main__':
    print("""
    Group Policy Preference Password Finder (GP3Finder) {0}
    Copyright (C) 2015  Oliver Morton (Sec-1 Ltd)
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it
    under certain conditions. See GPLv2 License.
""".format(__version__))

    parser = argparse.ArgumentParser(description="Group Policy Preference Password Finder.")
    mutex_group = parser.add_mutually_exclusive_group()
    mutex_group.add_argument("-D", "--decrypt", help="cpassword to decrypt.")
    mutex_group.add_argument("-E", "--encrypt", help="plaintext to encrypt.")
    mutex_group.add_argument("-A", "--auto", help="Check for and attempt to decrypt passwords on share.", action="store_true")
    parser.add_argument("-l", "--local", help="Search a local path INSTEAD of remote share.", action="store_true")
    parser.add_argument("-lr", "--local-root", help="Root of local search", default="c:\\ProgramData\\Microsoft\\Group Policy\\History\\")
    parser.add_argument("-rr", "--remote-root", help="Root of remote search. You probably want this to be 'ProgramData\Microsoft\Group Policy\History' if share is C$", default="")
    parser.add_argument("-o", "--outfile", help="Output filename.", default="gp3finder.out")
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument("-t", "--targets", help="Targets to authenticate to (usually a domain controller).", dest="hosts", nargs="+")
    targets.add_argument("-f", "--file", help="File of targets, one per line.")
    parser.add_argument("-v", "--verbose", help="Debug logging", action="store_true")
    parser.add_argument("-V", "--version", help="Print version banner", action="store_true")
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--user", help="Username for authentication domain\\user .")
    auth_group.add_argument("-p", "--password", help="Password to authenticate with, omit to be prompted.")
    auth_group.add_argument("-s", "--share", help="Share to authenticate to.", default="sysvol")

    args = parser.parse_args()

    args_dict = vars(args)

    input_file = args_dict.pop("file")
    hosts = []
    if input_file:
        with open(input_file, "r") as f:
            for line in f:
                hosts.append(line.strip())
        #if args_dict['hosts'] is None:  # Currently don't need this since --target and --file are mutually exclusive, this may change in the future.
        #    args_dict['hosts'] = []
        #args_dict['hosts'] += hosts
        args_dict['hosts'] = hosts

    if args_dict.get("local"):
        args_dict['remote'] = False
    else:
        args_dict['remote'] = True

    setup_logging(args_dict.pop('verbose'))

    if args_dict.pop('version'):
        print_version()
        exit()

    if not sum([bool(args.encrypt), bool(args.decrypt), args.auto]) == 1:  # bool inherits int, so we can add them together.
        print("Specify: encrypt, decrypt or auto.")
        parser.print_usage()
    else:
        try:
            gpppfinder = GPPPFinder(**args_dict)
        except Exception as e:
            logging.critical("Failed to initialise GPPPFinder. {0}".format(e))
        else:
            try:
                gpppfinder.run()
            except Exception as e:
                logging.critical("Failed to run GPPPFinder. {0}".format(e))
