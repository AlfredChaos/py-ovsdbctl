from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp import constants
# from ovsdbapp.schema.open_vswitch import impl_idl
from ovsdbapp.schema.ovn_northbound import impl_idl


# ovsdb_connection = connection.Connection(
#     idl=connection.OvsdbIdl.from_server(
#         'unix:/run/openvswitch/db.sock', 'Open_vSwitch'),
#     timeout=constants.DEFAULT_TIMEOUT)
# api = impl_idl.OvsdbIdl(ovsdb_connection)
# result = api.br_exists("br-gen").execute(check_error=True)
# print(result)
# result = api.del_br("br-gen").execute(check_error=True)
# print(result)

ovndb_connection = connection.Connection(
    idl=connection.OvsdbIdl.from_server(
        'unix:/run/ovn/ovnnb_db.sock', 'OVN_Northbound'), 
    timeout=constants.DEFAULT_TIMEOUT)
ovn_api = impl_idl.OvnNbApiIdlImpl(ovndb_connection)
result = ovn_api.ls_list().execute(check_error=True)
for r in result:
    i = vars(r)
    print(i)
    x = dict(i)
    print(x['_row'])