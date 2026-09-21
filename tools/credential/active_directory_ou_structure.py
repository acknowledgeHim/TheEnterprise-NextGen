import ldap3
from ldap3 import Server, Connection, SUBTREE, ALL
total_entries = 0

try:
    #s = Server('172.30.33.121', port=636, use_ssl=True, get_info=ALL)
    s = Server('172.16.121.33', port=389, use_ssl=False, get_info=ALL)
    admin_username = "cla2019ipt@prod.healthcare.wi.local"
    admin_password = "P@sswerd"
    c = Connection(s, user=admin_username, password=admin_password)
    c.bind()
    #c.start_tls()

    c.search(search_base = 'dc=prod, dc=healthcare, dc=wi, dc=local', search_filter = '(objectClass=OrganizationalUnit)')#, search_scope = SUBTREE, paged_size = 5)

    total_entries += len(c.response)

    for entry in c.response:
        print(entry)

    print('Total entries retrieved:', total_entries)
except Exception as e:
    print("22 error: " + str(e))


server_uri = 'ldap://prod.healthcare.wi.local'
search_base = 'dc=example,dc=com'
search_filter = '(objectClass=OrganizationalUnit)'
attrs = ['*']

server = ldap3.Server(server_uri)
with ldap3.Connection(server, auto_bind=True) as conn:
    conn.search(search_base, search_filter, attributes=attrs)
    print(conn.entries)