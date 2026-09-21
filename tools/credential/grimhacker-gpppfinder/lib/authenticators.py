'''
.       .1111...          | Title: authenticators.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | SMBAuthenticator - uses either pywin32 or
                   ..     | subprocesses of linux utilities.
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
import sys


class BaseSMBAuthenticator(object):
    """Base authentication class."""
    def __init__(self, **kwargs):
        """Initialise base authentication class"""
        self.log = logging.getLogger(__name__)
        self._allow_deauth = True  # Flag used to indicate whether deauthentication is allowed, set to false when a session already existed which must be maintained.
        try:
            self._host = kwargs['host']
        except Exception as e:
            raise Exception("Target host required. {0}".format(e))
        else:
            if isinstance(self._host, basestring):
                pass
            else:
                raise Exception("Target host must be a string.")

        try:
            self._user = kwargs['user']
        except:
            raise Exception("Target user required.")
        else:
            if isinstance(self._user, basestring):
                pass
            else:
                raise Exception("Target user must be a string.")
        try:
            self._passwd = kwargs['passwd']
        except:
            raise Exception("Target passwd required.")
        else:
            if isinstance(self._passwd, basestring):
                pass
            else:
                raise Exception("Target passwd must be a string.")
        try:
            self._domain = kwargs['domain']
        except:
            raise Exception("Target domain required.")
        else:
            if isinstance(self._domain, basestring):
                pass
            else:
                raise Exception("Target domain must be a string.")
        try:
            self._share = kwargs['share']
        except:
            self._share = "IPC$"
            self.log.debug("share not specified, using default: '{0}'".format(self._share))
        else:
            if isinstance(self._share, basestring):
                pass
            else:
                raise Exception("share must be a string.")

        if self._host.startswith("\\\\"):
            self._host = self._host[2:]  # Strip \\ from start
        else:
            self._host = "{0}".format(self._host)

        self._target = "\\\\{0}\\{1}".format(self._host, self._share)  # Construct target, results in: \\<host>\IPC$ by default.
        self.log.debug("target constructed as: '{0}'".format(self._target))
        self._local_device = None

    @property
    def user(self):
        """Return user used for authentication."""
        return self._user

    @property
    def passwd(self):
        """Return password used for authentication."""
        return self._passwd

    @property
    def domain(self):
        """Return domain name used for authentication."""
        return self._domain

    @property
    def target(self):
        """Return target used for authentication."""
        return self._target

    @property
    def share(self):
        """Return share used for authentication."""
        return self._share

    @property
    def host(self):
        """Return host used for authentication."""
        return self._host

    @property
    def local_device(self):
        """Return local device letter."""
        return self._local_device

    @local_device.setter
    def local_device(self, letter):
        """Set local device letter to self."""
        self._local_device = letter

    def authenticate(self, auth_type="smb"):
        """Authenticate to host with given credentials."""
        raise NotImplemented("Base class does not implement authentication functionality.")

    def deauthenticate(self):
        """Deauthenticate from host."""
        raise NotImplemented("Base class does not implement deauthentication functionality.")

    def map(self):
        """Map remote share to local device."""
        raise NotImplemented("Base class does not implement drive mapping functionality.")

    @property
    def devices(self):
        """Return list of local devices that have shares mapped."""
        raise NotImplemented("Base class does not implement get devices functionality.")

    def _set_allow_deauth(self, value):
        """Define whether deauthentication is allowed."""
        self._allow_deauth = bool(value)

    @property
    def allow_deauth(self):
        """Return whether deauthentication is allowed."""
        return self._allow_deauth


# Declare SMBAuthenticator class for either Windows or *nix
if sys.platform == "win32":
    # print "Running on windows. Using pywin32."
    import win32net
    import win32api
    import pywintypes

    class SMBAuthenticator(BaseSMBAuthenticator):
        """Server Message Block Authenticator class using pywin32."""
        def __init__(self, **kwargs):
            """Initialise SMBAuthenticator. Extends BaseAuthentiactor.__init__()."""
            super(SMBAuthenticator, self).__init__(**kwargs)

        def _net_use_enum(self, server=None, level=1):
            """Run win32net.NetUseEnum and return output"""
            all_connections = []
            resume = 0  # Flag used by the Windows API to indicate if there is more data.
            while True:
                try:
                    # Use pywin32 to get a list of the connections.
                    (connections, total, resume) = win32net.NetUseEnum(server, level, resume)
                except Exception as e:
                    raise  # If there was an error, break out of the infinite loop by reraising the exception.
                else:
                    all_connections = all_connections + connections
                    if not resume:
                        break  # There is no more information to retrieve using win32net.NetUseEnum so break from the loop.
            return all_connections

        @property
        def devices(self):
            """Return list of local devices that are in use."""
            try:
                devices = [drive.strip("\\") for drive in win32api.GetLogicalDriveStrings().split("\x00")]
                # win32api.GetLogicalDriveStrings() returns a null byte separated string of drives like this:
                # 'C:\\\x00D:\\\x00E:\\\x00F:\\\x00Z:\\\x00'
                # (Note it does not distinguish between drive types - which is what we want at the moment,
                # however we could use GetDriveType to check the drive type if needed.)
                # The string is split into a list using the null byte as a delimiter.
                # The resulting list is then iterated over to strip of the trailing "\" (Note it needs escaping, hence "\\")
                # The resulting generator is converted to a list.
            except Exception as e:
                raise
            else:
                return devices

        def _already_authenticated(self):
            """Check if the system is already authenticated to the host."""
            self.log.debug("Checking for an established connection to {0}".format(self._target))
            status = {0: 'Ok',
                      1: 'Paused',
                      2: 'Disconnected',
                      3: 'Network Error',
                      4: 'Connected',
                      5: 'Reconnected'}
            established = False  # Flag used to indicate if there is already a session established.
            try:
                # Use pywin32 to get a list of the connections.
                connections = self._net_use_enum()
            except Exception as e:
                self.log.warning("Could not retrieve list of existing connections. {0}".format(e))
            else:
                for connection in connections:
                    # For each connection in the list check if it is connected to our target.
                    if connection['remote'] == self._target:
                        self.log.debug("connection to '{0}' exists with status '{1}'".format(self._target, status[connection['status']]))
                        if connection['status'] == 0:
                            established = True  # If the status is 'OK', set the established flag to true to indicate that there is an existing connection that we can use.
                        else:
                            self.deauthenticate()  # If the status is not 'OK', deauthenticate because it is no use to us.
                            established = False  # Set the established flag to false to indicate that there is not an existing connect that we can use.
            return established

        def _net_use_add(self, server=None, level=2, data={}):
            """Run win32net.NetUseAdd."""
            try:
                # Use pywin32 to create a connection to the target.
                win32net.NetUseAdd(server, level, data)
            except Exception as e:
                raise  # reraise the exception.

        def authenticate(self, auth_type="smb"):
            """Authenticate to host using given credentials. Overrides BaseAuthenticator.authenticate().
            Returns True if successfully authenticated, otherwise it returns False."""
            if self._already_authenticated():  # Check if there is an existing connection to the target.
                self.log.info("Using established session to '{0}' and disallowing deauthentication.".format(self._target))
                self._set_allow_deauth(False)  # If there is an existing connection set the allow_deauth flag to False so that the connection is not terminated later
                                                # (we didn't set it up so we won't tear it down.)
                return True  # Return True to indicate we have a connection to the target.
            else:
                # Data structure required by NetUseAdd:
                data = {'remote': self._target, 'local': "", 'password': self.passwd, 'username': self.user, 'domainname': self.domain, 'asg_type': 3}  # Note: asg_type:0 is a normal share 3 is an ipc$ share.
                try:
                    # Use pywin32 to create a connection to the target.
                    self._net_use_add(None, 2, data)
                except pywintypes.error as details:
                    self.log.critical("Failed to authenticate to '{0}'. ({1}, '{2}', '{3}')".format(self._target, details[0], details[1], details[2]))
                    self.deauthenticate()  # Clean up the failed authentication.
                    return False  # Return flase to indicate that we did not successfully connect.
                else:
                    self.log.debug("Authenticated to '{0}'".format(self._target))
                    return True  # Return true to indicate we successfully connected to the target.

        def map(self):
            """Map share."""
            if self.local_device is None:  # check if a local device has been set
                letters = ['Z:', 'Y:', 'X:', 'W:', 'V:', 'U:', 'T:', 'S:', 'R:', 'Q:', 'P:', 'O:', 'N:', 'M:', 'L:', 'K:', 'J:', 'I:', 'H:', 'G:', 'F:', 'E:', 'D:', 'C:', 'B:', 'A:']
                devices = self.devices
                for letter in letters:
                    if letter in devices:
                        continue  # if drive letter is already in use, continue to the next drive letter
                    else:
                        self.local_device =letter  # drive letter is not in use, so we will use that.
                        break
            if self.local_device is None:
                raise Exception("Can't find a drive letter to mount on. Unmap some shares and try again.")
            else:
                data = {'remote': self._target, 'local': self.local_device, 'password': self.passwd, 'username': self.user, 'domainname': self.domain, 'asg_type': 0}  # Note: asg_type:0 is a normal share 3 is an ipc$ share.
                try:
                    self._net_use_add(None, 2, data)
                except pywintypes.error as details:
                    self.log.critical("Failed to authenticate to '{0}'. ({1}, '{2}', '{3}')".format(self._target, details[0], details[1], details[2]))
                    self.deauthenticate()  # Clean up the failed authentication.
                except Exception as e:
                    self.log.critical("Failed to authenticate to '{0}'. ({1})".format(self._target, e))

        def deauthenticate(self):
            """Deauthenticate from host. Overrides BaseAuthenticator.deauthenticate()."""
            if self.allow_deauth:  # If the allow_deauth flag is set to True (indicating we are allowed to tear down the connection).
                if self.local_device is not None:
                    mount = self.local_device
                else:
                    mount = self._target
                try:
                    # Use pywin32 to delete the connection to the target.
                    win32net.NetUseDel(None, mount)
                except pywintypes.error as details:
                    self.log.warning("Failed to deauthenticate from '{0}'. ({1}, '{2}', '{3}')".format(mount, details[0], details[1], details[2]))
                else:
                    self.log.debug("Deauthenticated from '{0}'".format(mount))
                    if self.local_device is not None:
                        self.local_device = None  # overrite local device letter with None so that it isn't accidentally used after it has been deauthenticated from.
            else:
                self.log.warning("not allowed to deauthenticate.")

else:
    # print "Not running on Windows. Assuming *nix ."
    import os
    import string
    import random

    from subprocess import CalledProcessError
    from subprocess import Popen, PIPE

    class Command(object):
        def __init__(self, command=None, **kwargs):
            try:
                self.log = logging.getLogger(__name__)
            except Exception as e:
                print("problem setting up log. {0}".format(e))
                self.log = None
            if command is not None and isinstance(command, list):
                self._command = command
            else:
                raise Exception("command must be a list of executable and arguments.")
            self._returncode = None
            self._stdout = ""
            self._stderr = ""

        @property
        def returncode(self):
            """Return the return code of the executed command."""
            return self._returncode

        @returncode.setter
        def returncode(self, code):
            """Store returncode of executed command."""
            self._returncode = code

        @property
        def stdout(self):
            """Return stdout of executed command."""
            return self._stdout

        @stdout.setter
        def stdout(self, out):
            """Store stdout of executed command."""
            self._stdout = out

        @property
        def stderr(self):
            """Return stderr of executed command."""
            return self._stderr

        @stderr.setter
        def stderr(self, err):
            """Store stderr of executed command."""
            self._stderr = err

        @property
        def command(self):
            """Return the command to execute."""
            return self._command

        def execute(self):
            """Run the specified command as a subprocess."""
            cmd = self.command
            self.log.debug("running: '{0}'".format(cmd))
            try:
                proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
            except CalledProcessError as e:
                # self.log.error("{0}: {1}".format(e.errno, e.strerror))
                raise Exception("Failed to execute command as subprocess. {0}: {1}".format(e.errno, e.strerr))
            except Exception as e:
                raise Exception("Failed to execute command as subprocess. {0}".format(e))
            else:
                try:
                    out, err = proc.communicate()
                except Exception as e:
                    raise Exception("Failed to communicate with subprocess. {0}".format(e))
                else:
                    if err is not None:
                        self.stderr = err
                    if out is not None:
                        self.stdout = out
                try:
                    self.returncode = proc.returncode
                except Exception as e:
                    self.log.warning("Failed to set subprocess return code to self. {0}".format(e))

    class SMBAuthenticator(BaseSMBAuthenticator):
        """Server Message Block Authenticator class using Samba and Linux utilities."""
        def __init__(self, **kwargs):
            """Initialise SMBAuthenticator. Extends BaseAuthentiactor.__init__()."""
            super(SMBAuthenticator, self).__init__(**kwargs)

        def deauthenticate(self):
            """Deauthenticate from host."""
            if self.local_device is None:
                # share isn't mapped and authenticate does not require anything to be done to deauthenticate.
                pass
            else:
                # raise NotImplemented("dismounting share not implemented.")
                try:
                    exe = Command(command=['umount', self.local_device])
                    exe.execute()
                except Exception as e:
                    raise Exception("Failed to execute subprocess of umount. {0}".format(e))
                else:
                    if exe.returncode != 0:
                        raise Exception("Failed to execute subprocess of umount. {0}".format(exe.stderr))
                    else:
                        # successfully unmounted
                        self.log.debug("removing directory '{0}'".format(self.local_device))
                        try:
                            os.rmdir(self.local_device)
                        except Exception as e:
                            raise Exception("Failed to delete directory. {0}".format(e))
        @property
        def devices(self):
            """Return list of local devices (file and directory names in local directory)."""
            return os.listdir('.')

        def map(self):
            """Map remote share to local device."""
            def _mkdir():
                """Make directory."""
                while True:
                    # loop until created a name that isn't in the directory.
                    # create a directory name.
                    name = (''.join(random.choice(string.ascii_lowercase) for i in range(5)))  # create random 5 character string
                    # check the name is not already in use in the directory.
                    if name not in self.devices:
                        self.local_device = name
                        break
                self.log.debug("creating directory '{0}'".format(self.local_device))
                try:
                    # create a new directory to use as a mount point.
                    os.mkdir(self.local_device)
                except Exception as e:
                    raise Exception("Failed to create directory to use as mount point. {0}".format(e))

            def _mount():
                """Mount remote share on local device."""
                try:
                    credentials = []
                    credentials.append("username={0}".format(self.user))
                    credentials.append("password={0}".format(self.passwd))
                    if self.domain != "":
                        credentials.append("domain={0}".format(self.domain))
                    creds_string = ",".join(credentials)
                except Exception as e:
                    raise Exception("Failed to create credentials string. {0}".format(e))
                else:
                    try:
                        # mount the share on the directory.
                        exe = Command(command=['mount',
                                               '-t', 'cifs',
                                               self.target,
                                               '-o', creds_string,
                                               self.local_device])
                        exe.execute()
                    except Exception as e:
                        raise Exception("Failed to mount. {0}".format(e))
                    else:
                        if exe.returncode != 0:
                            raise Exception("Failed to mount remote share as device. {0}".format(exe.stderr))
                        else:
                            pass  # mounted share

            try:
                _mkdir()
            except Exception as e:
                raise
            else:
                try:
                    _mount()
                except Exception as e:
                    raise

        def authenticate(self, auth_type="smb"):
            """Authenticate to host using given credentials. Overrides BaseAuthenticator.authenticate().
            Returns True if successfully authenticated, otherwise it returns False."""
            def _build_auth_cmd(self):
                """Build list of command and arguments to execute."""
                cmd = ['smbclient',
                       '-g',
                       '-W',
                       '{0}'.format(self.domain),
                       '{0}'.format(self.target),
                       '-U',
                       '{0}/%{1}'.format(self.user, self.passwd),
                       '-c',
                       'help']
                return cmd

            def _parse_auth_output(self, stdout, stderr, returncode):
                """Parse stdout and stderr from command."""
                # self.log.debug("returncode: {0}".format(returncode))
                if returncode is not None:
                    if returncode == 0:
                        if "failed" in stdout:
                            # So far observed the following:
                            # Connection to 192.168.0.12 failed (Error NT_STATUS_IO_TIMEOUT)
                            # Connection to 192.168.0.20 failed (Error NT_STATUS_HOST_UNREACHABLE)
                            # session setup failed: NT_STATUS_LOGON_FAILURE
                            # tree connect failed: NT_STATUS_BAD_NETWORK_NAME
                            try:
                                reason = stdout.split("(")[1].split(")")[0]
                            except Exception as e:
                                reason = "Unknown"
                            finally:
                                self.log.warning("Failed to authenticate. Reason: {0}".format(reason))
                            return False
                        elif stderr.startswith("Domain=["):
                            # TODO: need to test this is correct.
                            # This seems to be returned whenever the target and share are correct.
                            # i'm not sure if it shows if the username and password are correct
                            return True
                    else:
                        self.log.warning("Failed to authenticate. Reason: returncode {0}".format(returncode))
                        return False

            # Note: this function only tests for authentication because the samba subprocesses need to handle authentication and command as a single operation.
            try:
                cmd = _build_auth_cmd()
            except Exception as e:
                self.log.warning("Failed to build command. {0}".format(e))
            else:
                try:
                    exe = Command(command=cmd)
                except Exception as e:
                    self.log.warning("Failed to initialise Command. {0}".format(e))
                else:
                    try:
                        exe.execute()
                    except Exception as e:
                        self.log.warning("Failed to execute command. {0}".format(e))
                    else:
                        try:
                            result = _parse_auth_output(exe.stdout, exe.stderr, exe.returncode)
                        except Exception as e:
                            self.log.warning("Failed to parse output. {0}".format(e))
                        else:
                            return result
