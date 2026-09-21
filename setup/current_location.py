import sys
from common import common, encryption
from common.selection import Selection

def reset_current_testing_location(db_object):
    # Grab all locations in REPO
    try:
        locations = db_object.grab_all_locations()
        if locations is None:
            db_object.add("Location", {'name': 'main', 'modified_by': common.get_tester(), 'hashval': encryption.hash_string('main')})
            locations = db_object.grab_all_locations()

        if len(locations) == 1:
            location_id = str(locations[0]['id'])
        else:
            locations = db_object.dictionary_list("Location", "name") + ["all"]
            count_numbers = db_object.dictionary_list("Location", "id") + [1830]

            with Selection('Since there is more than one location, you must select a location to test, which can be "all locations".\n '
                           'All recon, scans, vulns, etc will be limited to scope entries that are in the location you select here.\n'
                           'This way you can target only the location you want at different moments.', locations, None) as selection:
                location_id = selection.select_option(count_numbers)
            if location_id == 1830:
                location_id = "all_locations"

        # Add / Update current location
        curr_location_info =  db_object.view("CurrentLocation", None, ["modified_by"], [common.get_tester()], True)
        if curr_location_info is not None:
            current_location_dict = {"current_location": location_id, 'id': curr_location_info[0]['id']}
            db_object.update("CurrentLocation", current_location_dict, ["modified_by"], [common.get_tester()], True)
        else:
            db_object.add("CurrentLocation", {'modified_by': common.get_tester(), 'current_location': location_id})
    except Exception as e:
        print("setup/current_location.py 27 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

