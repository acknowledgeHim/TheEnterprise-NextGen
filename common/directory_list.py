import os
import glob
import grp
import pwd
import datetime
from dateutil.relativedelta import relativedelta


class DirList():

    def __init__(self, path, tester):
        """
        Initialize list.Dir Class used list & display filtered sub folders

        Attributes:
            path -- represents location to get list from (ex. /usr/local/clients/my_client/)
            tester -- the current logged on user (username)
            MODIFIED_DATE_CHECK -- the timestamp used to, if desired, filter sub directories so only ones newer than this date appear
        """
        self.path = path
        self.tester = tester
        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def create_folder(self, path):
        """
        Creates Folder of specified path if not already there.
        Return bool True if successfully created folder, or False if folder not created.

        Arguments:
            path -- the full path including the name of the new folder to create
        """
        if not os.path.exists(path):
            os.makedirs(path)
            return True
        return False

    def formatted_folders(self, sub_dirs):
        """
        Formats folder list removing self.path from each entry.
        Returns the newly formatted folder list.
        """
        formatted_sub_dirs = []
        for sub_dir in sub_dirs:
            formatted_sub_dirs.append(sub_dir.replace(self.path,''))
        return formatted_sub_dirs

    def find_folders(self,depth):
        """
        Retrieves all subdirectories of self.path.
        Return sub_folders from depth specified after stripping of original self.path portion.

        Arguments:
            depth -- number of sub directories to 'walk', must be an int
        """
        sep = ""
        glob_string = ""
        i = 0
        while i < depth :
            if glob_string != "":
                sep = "/"
            glob_string = glob_string + sep +  "*"
            i = i + 1
        glob_string = self.path + "/" + glob_string
        dir_depth = glob.glob(glob_string)
        sub_dirs = filter(lambda d: os.path.isdir(d), dir_depth)
        return sub_dirs

    def __folder_owner_and_group(self, folder):
        """
        Retrieves user/group of folder.
        Returns the user and group.

        Atributes:
            folder -- current folder to retrieve owner and group for (ex. /usr/local/clients/my_client/)
        """
        stat_info = os.stat(folder)
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        user = pwd.getpwuid(uid)[0]
        group = grp.getgrgid(gid)[0]
        return (user, group)

    def dir_filter_by_owner(self, sub_dirs):
        """
        Filter sub directories by owner.
        Return the filtered sub directories or blank List if none found.

        Attributes:
            sub_dirs -- a list of folders to check if tester == owner
        """
        tester_created_folders = []
        for sub_dir in sub_dirs:
            user, group = self.__folder_owner_and_group(sub_dir)
            if user == self.tester:
                tester_created_folders.append(sub_dir)
        return tester_created_folders

    def dir_filter_by_date(self, sub_dirs, newer_than_months):
        """
        Filter sub directories by modified date.
        Return the filtered sub directories or blank List if none found.

        Attributes:
            sub_dirs -- a list of folders to check if modified/created date > now
        """
        newer_than_month_date = datetime.date.today() - relativedelta(months=int(newer_than_months))
        newer_folders = []
        for sub_dir in sub_dirs:
            stat_info = os.stat(sub_dir)
            modified_time = datetime.datetime.fromtimestamp(stat_info.st_mtime).date()
            if modified_time > newer_than_month_date:
                newer_folders.append(sub_dir)
        return newer_folders

    def dir_filter_by_user_inputed_string(self, sub_dirs, search_string):
        """
        Filter sub directories by string provided by user input.
        Return the filtered sub directories or blank List if none found.

        Attributes:
            sub_dirs -- a list of folders to check the name for the search_string
            search_string -- user inputed string used to filter sub directories
        """
        search_string_found_folders = []
        for sub_dir in sub_dirs:
            if search_string.lower() in sub_dir.lower():
                search_string_found_folders.append(sub_dir)
        return search_string_found_folders
