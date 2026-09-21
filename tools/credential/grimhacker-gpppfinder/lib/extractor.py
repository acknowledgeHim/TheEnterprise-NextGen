'''
.       .1111...          | Title: extractor.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | Checks if files contain 'password'
                   ..     | Extracts cpasswords and usernames from known
GrimHacker        ..      | files.
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

try:
    from xml.etree.cElementTree import ElementTree as ET
except:
    from xml.etree.ElementTree import ElementTree as ET

from lib.data import CPassword


class Extractor(object):
    """Extract cpassword and username from given file."""
    def __init__(self, **kwargs):
        """Initialise CPassExtractor"""
        self.log = logging.getLogger(__name__)
        self._local_file = kwargs.get('local_file', None)
        self._remote_file = kwargs.get('remote_file', None)
        if not isinstance(self._local_file, basestring):
            raise Exception("file must be a string")
        self._password_in_file = None
        self._cpasswords = []

    @property
    def password_in_file(self):
        """Return if password is in file."""
        if self._password_in_file is None:
            with open(self.local_file, "r") as f:
                if "password" in f.read():
                    self.password_in_file = True
                else:
                    self.password_in_file = False
        return self._password_in_file

    @password_in_file.setter
    def password_in_file(self, result):
        """Set if password is in file."""
        if result in [True, False]:
            self._password_in_file = result
        else:
            raise Exception("result must be True or False")

    @property
    def remote_file(self):
        """Return the remote filename."""
        return self._remote_file


    @property
    def local_file(self):
        """Return filename (remote)"""
        return self._local_file

    @property
    def cpasswords(self):
        """Return list of CPassword instances."""
        return self._cpasswords

    @cpasswords.setter
    def cpassword(self, cpassword):
        """Return append instance of CPassword to self."""
        #self.log.debug("setting cpassword to self. {0}".format(cpassword))
        if isinstance(cpassword, CPassword):
            self._cpasswords.append(cpassword)
        else:
            raise Exception("cpassword must be an instance of CPassword")

    def _extract_password(self):
        """Determine if the file is a known structure and if so, extract the password."""
        def _extract_from_defaults():
            """Extract passwords from defaults.xml"""
            self.log.warning("Extraction from defaults.xml not implemented.")
            # TODO: find format of this file and implement.

        def _get_properties_tags():
            """Parse the xml file and return a generator of all the properties tags."""
            tree = ET()
            tree.parse(self.local_file)
            return tree.iterfind(".//Properties")

        def _extract_from_groups():
            """Extract cpassword and username from groups.xml"""
            for properties in _get_properties_tags():
                #self.log.debug("properties.get('cpassword') = {0}".format(properties.get("cpassword")))
                self.cpassword = CPassword(cpassword=properties.get("cpassword"),
                                           user_name=properties.get("userName"),
                                           file=self.remote_file)

        def _extract_from_services():
            """Extract passwords from services.xml"""
            for properties in _get_properties_tags():
                self.cpassword = CPassword(cpassword=properties.get("cpassword"),
                                           user_name=properties.get("accountName"),
                                           file=self.remote_file)

        def _extract_from_scheduledtasks():
            """Extract passwords from scheduledtasks.xml"""
            for properties in _get_properties_tags():
                self.cpassword = CPassword(cpassword=properties.get("cpassword"),
                                           user_name=properties.get("runAs"),
                                           file=self.remote_file)

        def _extract_from_datasources():
            """Extract passwords from datasources.xml"""
            for properties in _get_properties_tags():
                self.cpassword = CPassword(cpassword=properties.get("cpassword"),
                                           user_name=properties.get("username"),
                                           file=self.remote_file)

        def _extract_from_printers():
            """Extract passwords from printers.xml"""
            for properties in _get_properties_tags():
                self.cpassword = CPassword(cpassword=properties.get("cpassword"),
                                           user_name=properties.get("username"),
                                           file=self.remote_file)

        def _extract_from_drives():
            """Extract passwords from drives.xml"""
            for properties in _get_properties_tags():
                self.cpassword = CPassword(cpassword=properties.get("cpassword"),
                                         user_name=properties.get("username"),
                                         file=self.remote_file)

        # _extract_password() logic
        if self.local_file.lower().endswith("defaults.xml"):
            _extract_from_defaults()
        elif self.local_file.lower().endswith("groups.xml"):
            _extract_from_groups()
        elif self.local_file.lower().endswith("services.xml"):
            _extract_from_services()
        elif self.local_file.lower().endswith("scheduledtasks.xml"):
            _extract_from_scheduledtasks()
        elif self.local_file.lower().endswith("printers.xml"):
            _extract_from_printers()
        elif self.local_file.lower().endswith("drives.xml"):
            _extract_from_drives()
        else:
            raise NotImplemented("Extracting from {0} not implemented.".format(self.remote_file))

    def run(self):
        """Run Extractor"""
        self.log.debug("checking if 'password' in '{0}'".format(self.remote_file))
        try:
            result = self.password_in_file
        except Exception as e:
            raise Exception("Error checking if 'password' is in the '{0}'. {1}".format(self.remote_file, e))
        else:
            if result is True:
                self.log.debug("extracting password from '{0}'...".format(self.remote_file))
                self._extract_password()
            else:
                self.log.debug("'password' not in '{0}'.".format(self.remote_file))
