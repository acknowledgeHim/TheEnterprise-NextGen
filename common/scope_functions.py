import sys

def scope_ips(db_object, location_id=None):
    # return list of scope ip entries
    try:
        scopeips = []

        filter_columns = ['type']
        filter_values = ['IP']
        if location_id is not None:
            filter_columns.append('location_id')
            filter_values.append(location_id)
        scopes = db_object.view("Scope", ['entry'], filter_columns, filter_values, True)
        if scopes is not None:
            for scope in scopes:
                scopeips.append(scope['entry'])
    except Exception as e:
        print("18 common/scope_functions error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return scopeips

def scope_items(db_object, type, location_id=None):
    # return list of scope ip entries
    try:
        scopeitems = []

        filter_columns = ['type']
        filter_values = [type]
        if location_id is not None:
            filter_columns.append('location_id')
            filter_values.append(location_id)
        scopes = db_object.view("Scope", ['entry'], filter_columns, filter_values, True)
        if scopes is not None:
            for scope in scopes:
                scopeitems.append(scope['entry'])
    except Exception as e:
        print("36 common/scope_functions error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return scopeitems

def scope_website_ips(db_object, location_id=None):
    # return list of scope ip entries
    try:
        scope_website_ips = []

        filter_columns = ['type']
        filter_values = ['WEBSITE']
        if location_id is not None:
            filter_columns.append('location_id')
            filter_values.append(location_id)
        scopes = db_object.view("Scope", ['open_ip'], filter_columns, filter_values, True)
        if scopes is not None:
            for scope in scopes:
                scope_website_ips.append(scope['open_ip'])
    except Exception as e:
        print("54 common/scope_functions error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
    return scope_website_ips


def scope_dictionary(db_object, type, location_id=None):
    # return dictionary of scope entries
    try:
        scope_dictionary = {}

        filter_columns = ['type']
        filter_values = [type]
        if location_id is not None:
            filter_columns.append('location_id')
            filter_values.append(location_id)
        scopes = db_object.view("Scope", ['entry', 'id'], filter_columns, filter_values, True)
        if scopes is not None:
            for scope in scopes:
                scope_dictionary[scope['entry']] = scope['id']
    except Exception as e:
        print("34 common/scope_functions error: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))

    return scope_dictionary