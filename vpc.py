import sys
from random import randint
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp import constants
from ovsdbapp.schema.ovn_northbound import impl_idl as ovnnb
from ovsdbapp.schema.ovn_southbound import impl_idl as ovnsb


class southbound(object):
    
    def __init__(self):
        self.ovnsb = None
        self._conn_ovn_sock()

    def _conn_ovn_sock(self):
        conn = connection.Connection(
            idl=connection.OvsdbIdl.from_server(
                'unix:/run/ovn/ovnsb_db.sock', 'OVN_Southbound'), 
            timeout=constants.DEFAULT_TIMEOUT)
        self.ovnsb = ovnsb.OvnSbApiIdlImpl(conn)

    def _make_chassis_dict(self, row):
        chassis = {
            "uuid": str(row.uuid),
            "hostname": row.hostname,
            "name": row.name,
            "external_ids": row.external_ids,
            "other_config": row.other_config,
        }
        encaps = []
        for encap in row.encaps:
            encaps.append(str(encap.uuid))
        chassis['encaps'] = encaps
        return chassis

    def get_all_chassis(self):
        chassis_list = []
        chasses = self.ovnsb.chassis_list().execute(check_error=True)
        for chassis in chasses:
            chassis_list.append(self._make_chassis_dict(chassis))
        return chassis_list


class vpc(object):

    def __init__(self, router, external_network, vpc_network):
        self.ovnnb = None
        self.gw_chassis = None
        # localnet = physicalNet logical_switchs uuid
        self.localnet_uuid = external_network
        self.vpc_switch_uuid = vpc_network
        self.router_name = router
        self.router = None
        self.physical_net = None
        self.private_cidr = None
        self.vpc_external_cidr = None
        self.vpc_external_ip = None
        self._conn_ovn_sock()
        self.set_private_networks()
        
    def _conn_ovn_sock(self):
        conn = connection.Connection(
            idl=connection.OvsdbIdl.from_server(
                'unix:/run/ovn/ovnnb_db.sock', 'OVN_Northbound'), 
            timeout=constants.DEFAULT_TIMEOUT)
        self.ovnnb = ovnnb.OvnNbApiIdlImpl(conn)

    def _make_logical_switch_dict(self, row):
        ports = []
        logical_switch = {
            'uuid': str(row.uuid),
            'acls': row.acls,
            'dns_records': row.dns_records,
            'external_ids': row.external_ids,
            'forwarding_groups': row.forwarding_groups,
            'load_balancer': row.load_balancer,
            'load_balancer_group': row.load_balancer_group,
            'name': row.name,
            'other_config': row.other_config,
            'qos_rules': row.qos_rules
        }
        for port in row.ports:
            ports.append(self._make_logical_switch_port_dict(port))
        logical_switch['ports'] = ports
        return logical_switch

    def _make_logical_switch_port_dict(self, row):
        ls_port = {
            'uuid': str(row.uuid),
            'addresses': row.addresses,
            'dhcpv4_options': row.dhcpv4_options,
            'dhcpv6_options': row.dhcpv6_options,
            'dynamic_addresses': row.dynamic_addresses,
            'enabled': row.enabled,
            'external_ids': row.external_ids,
            'ha_chassis_group': row.ha_chassis_group,
            'name': row.name,
            'options': row.options,
            'parent_name': row.parent_name,
            'port_security': row.port_security,
            'tag': row.tag,
            'tag_request': row.tag_request,
            'type': row.type,
            'up': row.up
        }
        return ls_port

    def _make_logical_router_dict(self, row):
        ports = []
        logical_router = {
            'uuid': str(row.uuid),
            'external_ids': row.external_ids,
            'load_balancer': row.load_balancer,
            'load_balancer_group': row.load_balancer_group,
            'name': row.name,
            'options': row.options,
            'policies': row.policies,
            'static_routes': row.static_routes,
        }
        for port in row.ports:
            ports.append(self._make_logical_router_port_dict(port))
        logical_router['ports'] = ports
        return logical_router

    def _make_logical_router_port_dict(self, row):
        lr_port = {
            'uuid': str(row.uuid),
            'enabled': row.enabled,
            'external_ids': row.external_ids,
            'gateway_chassis': row.gateway_chassis,
            'ha_chassis_group': row.ha_chassis_group,
            'ipv6_prefix': row.ipv6_prefix,
            'ipv6_ra_configs': row.ipv6_ra_configs,
            'mac': row.mac,
            'name': row.name,
            'networks': row.networks,
            'options': row.options,
            'peer': row.peer,
        }
        return lr_port
    
    def _make_nat_dict(self, row):
        nat = {
            'uuid': str(row.uuid),
            'allowed_ext_ips': row.allowed_ext_ips,
            'exempted_ext_ips': row.exempted_ext_ips,
            'external_ids': row.external_ids,
            'external_ip': row.external_ip,
            'external_mac': row.external_mac,
            'external_port_range': row.external_port_range,
            'logical_ip': row.logical_ip,
            'logical_port': row.logical_port,
            'options': row.options,
            'type': row.type,
        }
        return nat
    
    def set_external_networks(self, cidr):
        self.vpc_external_cidr = cidr
        self.vpc_external_ip = cidr.split('/')[0]

    def set_private_networks(self):
        if not self.vpc_switch_uuid:
            print('private network not specific')
            raise
        logical_switch = self.ovnnb.ls_get(
            switch=self.vpc_switch_uuid).execute(check_error=True)
        ls = self._make_logical_switch_dict(logical_switch)
        self.private_cidr = ls['other_config']['subnet']
    
    # 指定prefix=02:ac:10
    def _assign_mac_address(self):
        mac = ":".join(["%02x" % x for x in map(lambda x: randint(0, 255), range(6))])
        return mac

    def set_gateway_chassis(self, chassis):
        self.gw_chassis = chassis
        if not self.gw_chassis:
            south = southbound()
            chasses = south.get_all_chassis()
            if len(chasses) == 0:
                print("chassis not exist.")
                raise
            self.gw_chassis = chasses[0]['name']

    def list_logical_switch(self):
        logical_switch_list = []
        logical_switchs = self.ovnnb.ls_list().execute(check_error=True)
        for logical_switch in logical_switchs:
            logical_switch_list.append(self._make_logical_switch_dict(logical_switch))
        return logical_switch_list
    
    def list_logical_router(self):
        logical_router_list = []
        logical_routers = self.ovnnb.lr_list().execute(check_error=True)
        for logical_router in logical_routers:
            logical_router_list.append(self._make_logical_router_dict(logical_router))
        return logical_router_list
    
    def create_vpc_router(self):
        if not self.gw_chassis:
            print('gateway chassis not set')
            raise
        try:
            logical_router = self.ovnnb.lr_add(
                router=self.router_name, may_exist=True, options={
                    "chassis": self.gw_chassis}).execute(check_error=True)
            self.router = self._make_logical_router_dict(logical_router)
        except Exception as e:
            print(f'create vpc router {self.router_name} fail = {e}')
            raise
    
    def router_connect_switch(self, router_port, 
                              switch_port, switch, 
                              mac_address, ip_address):
        # create router_port and add mac&ip
        try:
            lr_port = self.ovnnb.lrp_add(self.router_name, router_port, 
                                        mac=mac_address, networks=[ip_address], 
                                        may_exist=True).execute(check_error=True)
            lr_port = self._make_logical_router_port_dict(lr_port)
        except Exception as e:
            print(f'vpc router add port {router_port} fail = {e}')
            raise
        # create switch_port
        try:
            ls_port = self.ovnnb.lsp_add(switch, switch_port, 
                                        may_exist=True).execute(check_error=True)
            ls_port = self._make_logical_switch_port_dict(ls_port)
        except Exception as e:
            print(f'logical_switch {switch} add port fail = {e}')
            raise
        try:
            # set ls_port type router
            self.ovnnb.lsp_set_type(port=ls_port['uuid'], 
                                    port_type='router').execute(check_error=True)
            # set ls_port mac address
            self.ovnnb.lsp_set_addresses(port=ls_port['uuid'],
                                        addresses=[mac_address]).execute(check_error=True)
            # connection
            options = {
                'router-port' : lr_port['name'],
            }
            self.ovnnb.lsp_set_options(port=ls_port['uuid'], **options).execute(check_error=True)
        except Exception as e:
            print(f'logical_switch_port {switch_port} set attribute fail = {e}')
            raise
        
    # type: snat, dnat or dnat_and_snat
    def add_nat(self, nat_type, external_ip, logical_ip):
        self.ovnnb.lr_nat_add(self.router_name, 
                              nat_type, external_ip=external_ip, 
                              logical_ip=logical_ip).execute(check_error=True)
        
    def add_static_route(self, prefix, nexthop):
        self.ovnnb.lr_route_add(self.router_name, prefix, 
                                nexthop).execute(check_error=True)
    
    def get_logical_router(self):
        router = self.ovnnb.lr_get(self.router_name).execute(check_error=True)
        return self._make_logical_router_dict(router)

    def create_vpc(self, chassis=None, vpc_gateway_cidr=None, 
                   vpc_external_cidr=None, external_gateway=None):
        if not vpc_gateway_cidr:
            print("virtual private gateway not exit")
            raise
        if not vpc_external_cidr:
            print("router connect external_network required cidr")
            raise
        if not external_gateway:
            print("external_gateway required")
            raise
        # create vpc gateway router
        self.set_external_networks(cidr=vpc_external_cidr)
        self.set_gateway_chassis(chassis)
        print(f'###Get gateway chassis = {self.gw_chassis}')
        self.create_vpc_router()
        print(f'###Get vpc router = {self.router}')
        # connect router and vpc_network
        router_port = 'connect_to_switch_' + self.vpc_switch_uuid
        switch_port = 'internal_connect_to_router_' + self.router['uuid']
        mac_address = self._assign_mac_address()
        print(f'###Get router internal port MAC = {mac_address}')
        self.router_connect_switch(router_port, switch_port, 
                                   switch=self.vpc_switch_uuid, 
                                   mac_address=mac_address, 
                                   ip_address=vpc_gateway_cidr)
        # connect router and localnet
        router_port = 'connect_to_switch_' + self.localnet_uuid
        switch_port = 'external_connect_to_router_' + self.router['uuid']
        mac_address = self._assign_mac_address()
        print(f'###Get router external port MAC = {mac_address}')
        self.router_connect_switch(router_port, switch_port, 
                                   switch=self.localnet_uuid, 
                                   mac_address=mac_address, 
                                   ip_address=self.vpc_external_cidr)
        # create snat
        self.add_nat("snat", self.vpc_external_ip, self.private_cidr)
        # set static_routes
        prefix = "0.0.0.0/0"
        nexthop = external_gateway
        self.ovnnb.lr_route_add(self.router['uuid'], prefix, nexthop, 
                                may_exist=True).execute(check_error=True)

    def remove_vpc(self):
        router = self.get_logical_router()
        # remove snat
        try:
            nats = self.ovnnb.lr_nat_list(self.router_name).execute(check_error=True)
            for nat in nats:
                nat_dict = self._make_nat_dict(nat)
                self.ovnnb.lr_nat_del(self.router_name, "snat", 
                                    match_ip=nat_dict['external_ip'], 
                                    if_exists=True).execute(check_error=True)
        except Exception as e:
            print(f'Remove snat fail = {e}')
        else:
            print(f'###Remove snat success')
        # remove external_switch_port
        try:
            switch_port = 'external_connect_to_router_' + router['uuid']
            self.ovnnb.lsp_del(switch_port, self.localnet_uuid, 
                            if_exists=True).execute(check_error=True)
        except Exception as e:
            print(f'Remove external_switch_port fail = {e}')
        else:
            print(f'###Remove external_switch_port success')
        # remove internal_switch_port
        try:
            switch_port = 'internal_connect_to_router_' + router['uuid']
            self.ovnnb.lsp_del(switch_port, self.vpc_switch_uuid, 
                            if_exists=True).execute(check_error=True)
        except Exception as e:
            print(f'Remove internal_switch_port fail = {e}')
        else:
            print(f'###Remove internal_switch_port success')
        # remove logical_router
        try:
            self.ovnnb.lr_del(self.router_name, if_exists=True).execute(check_error=True)
        except Exception as e:
            print(f'Remove logical_router {self.router_name} fail = {e}')
        else:
            print(f'###Rmove vpc router {self.router_name} success')


router = "develop"
# ovirt管理页面网络的外部ID
external_network = "928262e8-d7f6-4f4a-b829-89efcbc5e230"
vpc_network = "7a55719c-3314-46fe-86c8-2d842df564c5"
vpc_gateway_cidr = "192.168.1.1/24"
external_cidr = "172.16.21.110/24"
external_gateway = "172.16.21.254"


def main():
    method = None
    v = vpc(router, external_network, vpc_network)
    if len(sys.argv) > 1:
        method = sys.argv[1]
    else:
        print('Error: vpc required method')
        return
    if method not in ['create', 'remove']:
        print('Error: unsupport method, please input create or remove')
        return
    print(f'###Execute vpc method {method}')
    if method == 'create':
        v.create_vpc(vpc_gateway_cidr=vpc_gateway_cidr,
                     vpc_external_cidr=external_cidr,
                     external_gateway=external_gateway)
    if method == 'remove':
        v.remove_vpc()


if __name__ == '__main__':
    main()