import json

def parse(command, scope_id, location_id, db_object, log_id, tool=None):
    """
    Split command into parser function and file to parse, separated by a ':'
    :param command:
    :param scope_id:
    :param location_id:
    :param db_object:
    :param log_id:
    :return:
    """
    # update Log entry so that source is tool name
    print("13 tool/manual_parse/parse_selection.py tool: " + str(tool))
    if tool is not None:
        tool_dict = json.loads(tool)
        update_values = dict(id=log_id, source=tool_dict['tool'])
        db_object.update("Log", update_values, "hashval")

    print("Time for some manual parsing ...")