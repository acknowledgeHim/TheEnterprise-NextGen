'''
.       .1111...          | Title: finder.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | Finds files and uses Extractor to get list
                   ..     | of files with 'password' in them and list of
GrimHacker        ..      | CPassword objects.
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
import os
import fnmatch

from lib.extractor import Extractor
from lib.authenticators import SMBAuthenticator


class Finder(object):
    """Find and decrypt passwords in group policy preferences."""
    def __init__(self, **kwargs):
        """Initialise GPPPFinder"""
        self.log = logging.getLogger(__name__)
        self._local_root = kwargs.get("local_root", None)
        self._remote_root = kwargs.get("remote_root", "")
        if not (isinstance(self._local_root, basestring) or self._local_root is None):
            raise Exception("local_root must be a string or None")

        self._host = kwargs.get("host", None)
        if not (isinstance(self._host, basestring) or self._host is None):
            raise Exception("host must be a string or None")

        self._user = kwargs.get("user", None)
        if not (isinstance(self._user, basestring) or self._user is None):
            raise Exception("user must be a string")

        self._password = kwargs.get("password", None)
        if not (isinstance(self._password, basestring) or self._password is None):
            raise Exception("password must be a string")

        self._domain = kwargs.get("domain", self._host)
        if not (isinstance(self._domain, basestring) or self._domain is None):
            raise Exception("domain must be a string")

        self._share = kwargs.get("share", "sysvol")
        if not (isinstance(self._share, basestring) or self._share is None):
            raise Exception("share must be a string")

        if (self._local_root and self._host) or not (self._local_root or self._host):
            raise Exception("Must specify only one of host and local_root.")
        self._cpasswords = []
        self._password_files = []
        self._files = []

    @property
    def user(self):
        """Return user for authentication."""
        return self._user

    @property
    def password(self):
        """Return password for authentication."""
        return self._password

    @property
    def domain(self):
        """Return domain for authentication."""
        return self._domain

    @property
    def host(self):
        """Return host for authentication."""
        return self._host

    @property
    def share(self):
        """Return share to map."""
        return self._share

    @property
    def local_root(self):
        """Return local_root to search."""
        return self._local_root

    @property
    def remote_root(self):
        """Return remote_root to search."""
        return self._remote_root

    @property
    def files(self):
        """Return list of files."""
        if self._files is None:
            raise Exception("Files haven't been searched for.")
        else:
            return self._files

    @files.setter
    def files(self, file_):
        """Set file_ to self."""
        if self._files is None:
            self._files = []
        if isinstance(file_, list):
            self._files += file_
        elif isinstance(file_, basestring):
            self._files.append(file_)
        else:
            raise Exception("file to set must be list of strings or a string!")

    @property
    def password_files(self):
        """Return list of files that contain 'password'"""
        return self._password_files

    @password_files.setter
    def password_files(self, file_):
        """Set password file to self."""
        if isinstance(file_, list):
            self._password_files += file_
        elif isinstance(file_, basestring):
            self._password_files.append(file_)
        else:
            raise Exception("file to set must be list of strings or a string!")

    @property
    def cpasswords(self):
        """Return cpasswords list"""
        return self._cpasswords

    @cpasswords.setter
    def cpasswords(self, cpasswords):
        """Add cpasswords list to self."""
        if isinstance(cpasswords, list):
            self._cpasswords += cpasswords
        elif isinstance(cpasswords, basestring):
            self._cpasswords.append(cpasswords)
        else:
            raise Exception("cpasswords to set must be list of strings or a string!")
        # self._cpasswords = self._cpasswords + cpasswords

    def _find_files(self, path, pattern="*"):
        """Find files matching pattern recursively, starting at the given path."""
        #self.log.debug("Starting search at: {0}".format(path))
        for root, dirs, files in os.walk(path):
            for name in files:
                if fnmatch.fnmatch(name, pattern):
                    file_ = os.path.join(root, name)
                    self.log.debug("Found file '{0}'".format(file_))
                    self.files = file_

    def _process_files(self, remote_path, local_path):
        """Search each file in files for cpassword"""
        def create_filenames(filename):
            remote_filename = filename.replace(local_path, remote_path, 1)  # replace the first instance of the local path with the remote path.
            return filename, remote_filename

        for file_ in self.files:
            # TODO: consider threading this.
            local_file, remote_file = create_filenames(file_)
            try:
                extractor = Extractor(local_file=local_file, remote_file=remote_file)
            except Exception as e:
                self.log.warning("Error creating instance of Extractor for '{0}'. {1}".format(remote_file, e))
            else:
                try:
                    extractor.run()
                except Exception as e:
                    self.log.warning("Error extracting cpasswords from '{0}'. {1}".format(remote_file, e))
                else:
                    try:
                        self.cpasswords = extractor.cpasswords
                    except Exception as e:
                        self.log.warning("Error adding cpasswords to self from '{0}'. {1}".format(remote_file, e))
                    try:
                        if extractor.password_in_file:
                            self.password_files = remote_file
                    except Exception as e:
                        self.log.warning("Error getting password_in_file for '{0}'. {1}".format(remote_file, e))

    def _find(self, local_path, remote_path=None, pattern="*.xml"):
        """Find and process files."""
        if remote_path is None:
            remote_path = local_path

        self.log.info("Finding files matching '{0}' on share...".format(pattern))
        try:
            self._find_files(pattern=pattern, path=local_path)
        except Exception as e:
            raise
        else:
            self.log.info("Processing files...")
            try:
                self._process_files(local_path=local_path, remote_path=remote_path)
            except Exception as e:
                raise

    def run(self):
        """Run GPPPFinder to find, extract and decrypt passwords."""
        if self.host:
            self.log.info("Mapping share...")
            try:
                mapper = SMBAuthenticator(host=self.host,
                                          user=self.user,
                                          passwd=self.password,
                                          domain=self.domain,
                                          share=self.share)
            except Exception as e:
                raise
            else:
                try:
                    mapper.map()
                except Exception as e:
                    raise Exception("Error running mapper. {0}".format(e))
                else:
                    try:
                        device = mapper.local_device
                        #TODO: Should be using os.path.join here
                        local_path = "{0}{1}{2}".format(device, os.path.sep, self.remote_root)
                        remote_path = "{sep}{sep}{host}{sep}{share}{sep}{path}".format(host=self.host, share=self.share, path=self.remote_root, sep=os.path.sep)
                    except Exception as e:
                        raise
                    else:
                        # TODO: the file names we are interested in are fixed and registered in ldap, just pull them from there? (fall back to this if ldap lookup fails.)
                        self.log.debug("share mapped to '{0}'".format(device))
                        self._find(local_path, remote_path)
                    self.log.info("Deauthenticating...")
                    try:
                        mapper.deauthenticate()
                    except Exception as e:
                        self.log.warning("Failed to deauthenticate. {0}".format(e))
                    else:
                        self.log.debug("deauthenticated.")
        elif self.local_root:
            self._find(self.local_root)
