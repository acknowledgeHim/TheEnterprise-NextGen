#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# FILE:     ServerAccess.py
# PURPOSE:  Access of Samba File Shares
# Author: R4PH43L (from stackexchange)
# Modified By: Huber (python3)
"""

import tempfile
import logging
import sys
import os       # Path operations
import re

from socket import getfqdn

from smb.SMBConnection import SMBConnection, OperationFailure
from smb.base import SharedDevice
#from smb.base import SharedFile

from .Networking import resolve_network_tuple

__DEBUG__ = 9

class ServerException(Exception):
    pass

class ServerAccess(object):
    """
        Description: ServerAccess Class and File Handler
                     This is a wrapper and extension class.

        Uses:        PySMB Package by miketeo
                     URL:       github.com/miketeo/pysmb
                     Mail:      miketeo@miketeo.net

    """
    __timeout = 5
    __username = None
    __password = None
    __port = 139
    __server_name = None
    __server_ip = None
    __activeShare = None
    __client = None
    __logger = logging.getLogger()

    __server_shares = []

    # -----------------------------------------------------------------------------
    # Default Methods
    # -----------------------------------------------------------------------------
    def __init__(self, **kwargs):
        """
        Create an Instance. For further documentation please see the corresponding documentation
        on github for the classes of miketeo

        :uses smb.SMBConnection.__init__
        :uses smb.SMBConnection.connect

        :param      **kwargs        For details on the needed structure, please refer to the
                                    documentation of the PySMB-Project
        """
        for key, value in kwargs.items():
            self.__setattr__(key, value)
            if __DEBUG__ > 3:
                if key == "password":
                    value = 'x'*8
                if key != "__logger":
                    self.__logger.debug("  %s      = %s", key, value)

        self.__client = getfqdn()

        # use_ntlm_v2 must be passed as named argument
        kwargs['use_ntlm_v2'] = False
        kwargs['my_name'] = self.__client
        kwargs['remote_name'] = self.__server_name
        if "shared_folder" in kwargs.keys():
            self.shared = kwargs["shared_folder"]
        if "timeout" in kwargs.keys():
            self.__timeout = kwargs["timeout"]
        if "port" in kwargs.keys():
            self.__port = kwargs["port"]

        if not "server_ip" in kwargs.keys():
            kwargs["server_ip"] = resolve_network_tuple(kwargs["server_name"])[0]

        kwargs.pop("server_ip", None)
        kwargs.pop("shared_folder", None)
        kwargs.pop("timeout", None)
        kwargs.pop("server_name", None)

        self.conn = SMBConnection(**kwargs)

        self.__logger.debug("Constructor connects to: \n%s", self)
        assert self.conn.connect("%s"%self.__server_ip, self.__port, timeout=self.__timeout)

    def __del__(self):
        """
        Destruction functionality

        Make sure that connection gets closed

        # TODO: Check if a job should be finished or not

        :uses smb.SMBConnection.close
        """
        try:
            self.conn.close()
        except AttributeError:
            pass

    def __str__(self):
        """
        Parse the object to a readable String.

        returns a xml-structured view ob the object

        replaces password string by eight times 'x' for IT-Security.
        """
        result = ("\n<Server Access Object>")

        for key, value in self.__dict__.items():
            if key == "__password":
                value = 'x'*8
            result += "\n   <{0}>{1}</{0}>".format(key, value)

        result += ("\n</Server Access Object>")

        return result

    def __getattr__(self, name):
        """
        Getter functionality for object attributes.
        This getter funtionality is called AFTER other lookup places.

        :param          name             Name to be checked for attribute linking.

        :exception      AttributeError   No matching getter call was found for the passed parameter
                                         "name" so an AttributeError is raised.

        :attribute      server name      Hostname of the target server
        :attribute      server_ip        IP-Address (IPv4, dotted decimal notation) of the target
                                         server
        :attribute      user             Username for authentication requests of target server
        :attribute      port             TCP-Port to be used for the connection to the server
                                         (default-SMB: 139)
        :attribute      share            it is possible that a user has only rights to access one
                                         specific share on a Samba Server.
                                         Therefore we need the possibility to only connect to a
                                         single share as well as to a whole cluster structure
        """
        name = name.lower()

        if re.match("server.*name", name, re.I) and not "__" in name:
            return self.__server_name
        elif re.match("server.*ip", name, re.I) and not "__" in name:
            return self.__server_ip
        elif name == "user":
            return self.__user
        elif name == "port":
            return self.__port
        elif name == "share":
            return self.__activeShare
        else:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        """
        Setter functionality for object attributes.

        This setter function is called before the object dictionary (obj.__dict__) is called.
        As we are overloading the setter hereby, we need to update the object dictionary after
        implementing our changes.

        !!! ATTENTION !!!
        No setter does automatically call the connect functionality. This is required to be done
        afterwards.

        :attribute      *server*        Wildcards are used as any "name" containing "server" in any
                                        case combination in it will update the server_name AND the
                                        server_ip of the object by performing a Domain Name Service
                                        call to resolute the Hostname and IP of the passed argument.
                                        Value argument could either be hostname (type<string>) or
                                        IP-Address (IPv4, dotted decimal notation)
        :attribute      user            Username to be set for the connection.
        :attribute      password        Password to be used for the User for Client-Server
                                        authentication(CSA)

        :uses      Networking.resolve_network_tuple

        """
        if ((re.match("server.*name", name.lower(), re.I) or
             re.match("server.*ip", name.lower(), re.I)
            ) and not "__" in name.lower()):

            self.__server_ip, self.__server_name = resolve_network_tuple("{}".format(value))
        elif name.lower() == "user":
            self.__user = value
        elif name.lower() == "password":
            self.__password = value
        else:
            self.__dict__[name] = value

    # -----------------------------------------------------------------------------
    # Read-Only Access on Servers
    # -----------------------------------------------------------------------------
    def list_files(self, share=None, path=""):
        """
        List all Files in a certain directory or share or combination of both on a connected
        remote Samba Server

        :exceptions     ?????           For further information on Exceptions that can be raised by
                                        this function, please refer to PySMB Documentation of used
                                        functions.
                                        No Custom Exceptions are raised here.

        :param          share           If passed, this will be the share that will be looked into
                                        and __only__ files from this share will be listed.
        :param          path            If passed, only files of this directory/path (if existing
                                        on the selected share) will be listed.

        :uses           smb.SMBConnection.listPath

        :returns        List<String>
        """
        if share is not None:
            return self.conn.listPath(share, path, 55)
        elif self.shared:
            return self.conn.listPath(self.shared, path, 55)

    def list_directories(self, share=None, path=""):
        """
        List all directories in a certain path or share or combination of both on a connected remote
        Samba Server

        :uses           self.listFiles

        :returns        List<String>
        """
        return ([__dir for __dir in self.listFiles(share, path) if __dir.isDirectory])

    def list_shares(self):
        """
        List all shares the current logged in user has at least read permissions at the currently
        connected remote server.

        :uses           smb.SMBConnection.listShares
        :uses           self.__timeout

        :returns        self.__ServerShares
        """
        self.__server_shares = []
        if self.conn:
            for dev in self.conn.listShares(self.__timeout):
                if dev.type == SharedDevice.DISK_TREE:
                    self.__server_shares.append(dev.name)
        return self.__server_shares

    def get_file(self, filename, share=None):
        """
        Retrieve a copy of a File object at position 0,0 (=beginning of File) from the connected
        remote Server.

        :param          filename        relative Filepath to either server or share (if != ""/None)
        :param          share           share from which the file should be retrieved.

        :uses           smb.SMBConnection.retrieveFile
        :uses           tempfile.NamedTemporaryFile

        :returns        tempfile.NamedTemporaryFile Object
        """
        file_obj = tempfile.NamedTemporaryFile()
        if share is None:
            share = self.shared

        try:
            file_attributes, filesize = self.conn.retrieveFile(share, filename, file_obj)
            # TODO:
            # Use attributes and filesize to check for valid File
            # Otherwise all we get is crap
            file_obj.seek(0, 0)
            self.__logger.debug("Retrieved:  %s", filename)
            self.__logger.debug("Size:       %s", filesize)
            self.__logger.debug("Attributes: %s", file_attributes)
        except OperationFailure:
            file_obj = None
            self.__logger.error("Unable to retrieve: %s using %s", filename, self.conn)
        return file_obj

    # -----------------------------------------------------------------------------
    # Read-Write Access Functionality
    # -----------------------------------------------------------------------------
    def write_file(self, file_obj, filename, share=None):
        """ write passed file_obj to passed filename on specified share """
        if share is None:
            self.shared = share
        filename = os.path.normpath(filename)
        filename = filename.replace('\\', '/')

        __curr_dir = ""
        dirnames = os.path.split(filename)

        for __dir_idx in range(len(dirnames[:-1])):
            __curr_dir = "{0}{1}/".format(__curr_dir, dirnames[__dir_idx])
            self.writeDirectory("{0}".format(__curr_dir))

        try:
            self.conn.storeFile(self.shared, "{}".format(filename), file_obj)
        except:
            raise ServerException("Creating File <{0}> failed using {1}".format(filename, self))

    def write_directory(self, dirpath, share=None):
        """ create passed dirpath on specified share """
        if share is None:
            self.shared = share

        # Check if Path already exists
        if len(self.conn.listPath(self.shared, dirpath)) != 0:
            return
        try:
            self.conn.create_directory(self.shared, dirpath)
        except AttributeError:
            raise ServerException("Creating Directory <{0}> failed using {1}".format(dirpath, self))

    def move_file(self, filename1, filename2):
        """ move file directly on share """
        file_obj = tempfile.NamedTemporaryFile()
        file_attributes, filesize = self.conn.retrieveFile(self.shared, filename1, file_obj)
        self.conn.storeFile(self.shared, filename2, file_obj)
        file_obj.close()

        self.__logger.debug("Moved:      %s to %s", filename1, filename2)
        self.__logger.debug("Size:       %s", filesize)
        self.__logger.debug("Attributes: %s", file_attributes)

        self.conn.deleteFiles(self.shared, filename1)

    def delete_file(self, filename, share=None):
        """ delete a file on a remote share """
        if share is None:
            self.shared = share
        self.conn.deleteFiles(self.shared, filename)

    def delete_directory(self, dirpath, share=None):
        """ delete a directory on a remote share """
        if share is None:
            self.shared = share

        # Check if Path already exists
        if len(self.conn.listPath(self.shared, dirpath)) != 0:
            return
        try:
            self.conn.deleteDirectory(self.shared, dirpath)
        except:
            raise ServerException("Deletion of Directory <{0}>"
                                  " failed using {1}".format(dirpath, self))

def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

if __name__=="__main__":

    import argparse
    import getpass
    from socket import getfqdn

    from . import Networking

    LOGGER = logging.getLogger()

    PARSER = argparse.ArgumentParser(description="Server Access Library")

    PARSER.add_argument('--host', type=str, required=True, dest='host')
    PARSER.add_argument('-u', '--user', type=str, required=True, dest='user')
    PARSER.add_argument('-p', '--password', dest='usePW', default=False, action='store_true')
    PARSER.add_argument('-s', '--share', type=str, dest='share', default="")

    ARGS = PARSER.parse_args(sys.argv[1:])

    HOSTIP, HOSTNAME = Networking.resolve_network_tuple(ARGS.host)

    LOGGER.debug("%s trying to connect to %s", getfqdn(), HOSTNAME)
    if ARGS.usePW:
        PASSWORD = getpass.getpass("Please enter password: ")

    if ARGS.share != "":
        APP = ServerAccess(ARGS.user, PASSWORD, getfqdn(), HOSTNAME, HOSTIP, ARGS.share)
        print(ARGS.share)
        for shareFile in APP.listFiles(ARGS.share):
            if not shareFile.filename in [".", ".."]:
                LOGGER.debug(" %s", shareFile.filename)
    else:
        APP = ServerAccess(ARGS.user, PASSWORD, server_name=HOSTNAME, server_ip=HOSTIP)

        for _share in APP.listShares():
            LOGGER.debug(_share)
            for shareFile in APP.listFiles(_share):
                if not shareFile.filename in [".",".."]:
                    LOGGER.debug(" {}".format(shareFile.filename))