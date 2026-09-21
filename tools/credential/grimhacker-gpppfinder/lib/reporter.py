'''
.       .1111...          | Title: reporter.py
    .10000000000011.   .. | Author: Oliver Morton (Sec-1 Ltd)
 .00              000...  | Email: oliverm-tools@sec-1.com
1                  01..   | Description:
                    ..    | reporter for gpppfinder.py
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


class Reporter(object):
    """Reporter to output cpasswords and files with 'password' in them to file."""
    def __init__(self, **kwargs):
        """Initialise reporter object."""
        self.log = logging.getLogger(__name__)
        if not isinstance(kwargs.get('cpasswords', None), list):
            raise Exception("cpasswords must be a list of CPassword instances")
        else:
            self._cpasswords = kwargs.get('cpasswords')
        if not isinstance(kwargs.get('password_files'), list):
            raise Exception("password_files must be a list of file names.")
        else:
            self._password_files = kwargs['password_files']
        if not isinstance(kwargs.get('output_file'), basestring):
            raise Exception("output_file must be a string")
        else:
            self._output_file = kwargs.get('output_file')

    @property
    def cpasswords(self):
        """Return list of CPassword instances to report."""
        return self._cpasswords

    @property
    def password_files(self):
        """Return list of files that contain 'password'"""
        return self._password_files

    @property
    def output_file(self):
        """Return output filename."""
        return self._output_file

    def run(self):
        """Run reporter object."""
        # TODO: decide on a decent output format. This is bad... grepable... but bad...
        self.log.debug("creating output file '{0}'...".format(self.output_file))
        with open(self.output_file, "w") as f:
            f.writelines("user:password:cpassword:file\n")
            for cpassword in self.cpasswords:
                # write username, password, cpassword, file name to output file.
                f.writelines("{0}:{1}:{2}:{3}\n".format(cpassword.user,
                                                        cpassword.password,
                                                        cpassword.cpassword,
                                                        cpassword.file))
            for file_ in self.password_files:
                # write file name of each file that contains 'password' to output file
                f.writelines(":::{0}\n".format(file_))
        self.log.info("{0} cpasswords, {1} files containing 'password'".format(len(self.cpasswords), len(self.password_files)))
