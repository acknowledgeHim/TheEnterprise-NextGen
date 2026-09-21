'''
.       .1111...          | Title: data.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | CPassword stores cpassword and username and
                   ..     | uses MSCrypto to decrypt cpassword and stores
GrimHacker        ..      | as plaintext password.
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

from lib.mscrypto import MSCrypto


class CPassword(object):
    """Object to store cpassword information."""
    def __init__(self, **kwargs):
        """Initialise cpassword object"""
        self.log = logging.getLogger(__name__)
        self._password = kwargs.get('password', None)  # important that this is before cpassword!
        self.set_cpassword(kwargs.get('cpassword'))
        self._user_name = kwargs.get('user_name', None)
        if not isinstance(self._user_name, basestring):
            #raise Exception("user_name must be a string") # nope can set by uid so no username... need to capture that in the future
            self._user_name = str(self._user_name)
        self._file = kwargs.get('file', None)

    def set_cpassword(self, cpassword):
        """Set cpassword to self."""
        #self.log.debug("settign cpassword. {0}".format(cpassword))
        if not isinstance(cpassword, basestring) and cpassword is not None:
            raise Exception("cpassword must be a string or None")
        else:
            self._cpassword = cpassword or "" # set the cpassword (or an empty string if there is no cpassword) to self
            if not cpassword:
                self._set_password("")  # if there is no cpassword, set the password to an empty string.
            else:
                try:
                    # decrypt the cpassword and set the plaintext password to self.
                    self._set_password(self._decrypt_cpassword(cpassword))
                except Exception as e:
                    raise Exception("Error decrypting cpassword and setting to self. {0}".format(e))

    def set_user_name(self, user_name):
        """Set user name to self."""
        if isinstance(user_name, basestring):
            self._user_name = user_name
        else:
            self._user_name = str(user_name)
            #raise Exception("user_name must be a string") # nope, can set by uid so no username... need to capture that in the future....

    def _set_password(self, password):
        """Set password to self."""
        if isinstance(password, basestring):
            self._password = password
        else:
            raise Exception("password must be a string or None")

    @property
    def file(self):
        """Return file information was found in."""
        return self._file

    @property
    def user(self):
        """Return user name."""
        return self._user_name

    @property
    def cpassword(self):
        """Return cpassword."""
        return self._cpassword

    @property
    def password(self):
        """Return password."""
        return self._password

    def _decrypt_cpassword(self, cpassword):
        """Decrypt cpassword to password."""
        self.log.debug("decrypting cpassword...")
        crypto = MSCrypto()  # initialise an instance of Decryptor
        return crypto.decrypt(cpassword)  # run decryptor with the cpassword to get the plaintext.
