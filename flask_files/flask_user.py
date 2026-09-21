from common.selection import Selection
from common.menu_class import Menu, MenuClass

def view_flask_user(db_object, title, menu_items, full_client_engagement_path, quit):
    place_holders = [0, 8, 8]
    with MenuClass(db_object, "WebApp User", place_holders, full_client_engagement_path, False) as create_menu:
        print("8 flask_files/flask_user create_menu.navigation: " + str(create_menu.navigation ))
        create_menu.select_option()