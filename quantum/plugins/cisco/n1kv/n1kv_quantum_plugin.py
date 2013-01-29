# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Cisco Systems, Inc.
# All Rights Reserved.
# @author: Aruna Kushwaha, Cisco Systems, Inc.


import logging
import os
import sys

from quantum.api.v2 import attributes
from quantum.common import constants as q_const
from quantum.common import exceptions as q_exc
from quantum.common import topics
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_db
from quantum.extensions import providernet as provider
from quantum.extensions import n1kv_profile as n1kv_profile
from quantum.openstack.common import context
from quantum.openstack.common import quantum_cfg
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common.rpc import proxy

from quantum.plugins.cisco.n1kv import n1kv_configuration as n1kv_conf
from quantum.plugins.cisco.db import n1kv_db_v2

from quantum import policy

from quantum.plugins.cisco.db import n1kv_profile_db
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.n1kv import n1kv_client
from quantum.plugins.cisco.common import cisco_constants as const

from keystoneclient.v2_0 import client as keystone_client
from novaclient.v1_1 import client as nova_client

LOG = logging.getLogger(__name__)
VM_NETWORK_NUM = 0
TENANT = const.NETWORK_ADMIN


class N1kvQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                         l3_db.L3_NAT_db_mixin,
                         n1kv_profile_db.Profile_db_mixin):
    """Implement the Quantum abstractions using Open vSwitch.

    Depending on whether tunneling is enabled, either a GRE tunnel or
    a new VLAN is created for each network. An agent is relied upon to
    perform the actual OVS configuration on each host.

    The provider extension is also supported. As discussed in
    https://bugs.launchpad.net/quantum/+bug/1023156, this class could
    be simplified, and filtering on extended attributes could be
    handled, by adding support for extended attributes to the
    QuantumDbPluginV2 base class. When that occurs, this class should
    be updated to take advantage of it.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True
    supported_extension_aliases = ["provider", "profile", "n1kv_profile",
                                    "router"]

    def __init__(self, configfile=None):
        n1kv_db_v2.initialize()
        #cred.Store.initialize()
        self._parse_network_vlan_ranges()
        n1kv_db_v2.sync_vlan_allocations(self.network_vlan_ranges)
        self.enable_tunneling = n1kv_conf.N1KV['enable_tunneling']
        self.tunnel_id_ranges = []
        if self.enable_tunneling:
            self._parse_tunnel_id_ranges()
            n1kv_db_v2.sync_tunnel_allocations(self.tunnel_id_ranges)
        self._setup_vsm()
        self._poll_policies()

    def _setup_vsm(self):
        #setup VSM connection
        LOG.debug('_setup_vsm')
        self.agent_vsm = True
        self._send_register_request()

    def _poll_policies(self):
        #Poll policies
        n1kvclient = n1kv_client.Client()
        self._add_policy_profiles(n1kvclient)
        LOG.debug('_poll_policies')

    def _add_policy_profiles(self, n1kvclient):
        """Populate Profiles of type Policy on init."""
        profiles = n1kvclient.list_profiles()
        for profile in profiles[const.SET]:
            _profile_id = profile[const.PROPERTIES][const.ID]
            _profile_name = profile[const.PROPERTIES][const.NAME]
            self.add_profile(TENANT,
                             _profile_id, _profile_name, const.POLICY)

    def _parse_network_vlan_ranges(self):
        self.network_vlan_ranges = {}
        ranges = n1kv_conf.N1KV['network_vlan_ranges']
        ranges = ranges.split(',')
        for entry in ranges:
            entry = entry.strip()
            if ':' in entry:
                try:
                    physical_network, vlan_min, vlan_max = entry.split(':')
                    self._add_network_vlan_range(physical_network.strip(),
                        int(vlan_min),
                        int(vlan_max))
                except ValueError as ex:
                    LOG.error("Invalid network VLAN range: \'%s\' - %s",
                        entry, ex)
                    sys.exit(1)
            else:
                self._add_network(entry)
        LOG.info("Network VLAN ranges: %s", self.network_vlan_ranges)

    def _add_network_vlan_range(self, physical_network, vlan_min, vlan_max):
        self._add_network(physical_network)
        self.network_vlan_ranges[physical_network].append((vlan_min, vlan_max))

    def _add_network(self, physical_network):
        if physical_network not in self.network_vlan_ranges:
            self.network_vlan_ranges[physical_network] = []

    def _parse_tunnel_id_ranges(self):
        ranges = n1kv_conf.N1KV['tunnel_id_ranges']
        ranges = ranges.split(',')
        for entry in ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                self.tunnel_id_ranges.append((int(tun_min), int(tun_max)))
            except ValueError as ex:
                LOG.error("Invalid tunnel ID range: \'%s\' - %s", entry, ex)
                sys.exit(1)
        LOG.info("Tunnel ID ranges: %s", self.tunnel_id_ranges)

    # TODO(rkukura) Use core mechanism for attribute authorization
    # when available.

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
            "extension:provider_network:view",
            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
            "extension:provider_network:set",
            network)

    def _extend_network_dict_provider(self, context, network):
#        if self._check_provider_view_auth(context, network):
        binding = n1kv_db_v2.get_network_binding(context.session,
            network['id'])
        network[provider.NETWORK_TYPE] = binding.network_type
        if binding.network_type == const.TYPE_VXLAN:
            network[provider.PHYSICAL_NETWORK] = None
            network[provider.SEGMENTATION_ID] = binding.segmentation_id
            network[n1kv_profile.MULTICAST_IP] = binding.multicast_ip
        elif binding.network_type == const.TYPE_VLAN:
            network[provider.PHYSICAL_NETWORK] = binding.physical_network
            network[provider.SEGMENTATION_ID] = binding.segmentation_id

    def _process_provider_create(self, context, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return (None, None, None)

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)

        if not network_type_set:
            msg = _("provider:network_type required")
            raise q_exc.InvalidInput(error_message=msg)
        elif network_type == const.TYPE_VLAN:
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
            if segmentation_id < 1 or segmentation_id > 4094:
                msg = _("provider:segmentation_id out of range "
                        "(1 through 4094)")
                raise q_exc.InvalidInput(error_message=msg)
        elif network_type == const.TYPE_VXLAN:
            if physical_network_set:
                msg = _("provider:physical_network specified for VXLAN "
                        "network")
                raise q_exc.InvalidInput(error_message=msg)
            else:
                physical_network = None
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
        else:
            msg = _("provider:network_type %s not supported" % network_type)
            raise q_exc.InvalidInput(error_message=msg)

        if network_type in [const.TYPE_VLAN]:
            if physical_network_set:
                if physical_network not in self.network_vlan_ranges:
                    msg = _("unknown provider:physical_network %s" %
                            physical_network)
                    raise q_exc.InvalidInput(error_message=msg)
            elif 'default' in self.network_vlan_ranges:
                physical_network = 'default'
            else:
                msg = _("provider:physical_network required")
                raise q_exc.InvalidInput(error_message=msg)

        return (network_type, physical_network, segmentation_id)

    def _check_provider_update(self, context, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)

        msg = _("plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def _extend_network_dict_profile(self, context, network):
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _extend_port_dict_profile(self, context, port):
        #if self._check_provider_view_auth(context, network):
        binding = n1kv_db_v2.get_port_binding(context.session,
                port['id'])
        port[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _process_profile(self, context, attrs):
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)

        profile_id_set = attributes.is_attr_set(profile_id)
        if not (profile_id_set):
            msg = _("n1kv_profile:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)
            return None
        if not (self.network_profile_exist(context, profile_id)):
            msg = _("n1kv_profile:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)

        return (profile_id)

    #TBD: remove added for compilation
    def _send_register_request(self):
        LOG.debug('_send_register_request')

    def _send_create_network_request(self, network):
        LOG.debug('_send_create_network_request: %s', network['id'])
        profile = self.get_profile_by_id(network[n1kv_profile.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_fnd(profile)
        if network[provider.NETWORK_TYPE] == const.TYPE_VXLAN:
            n1kvclient.create_bridge_domain(network)
        n1kvclient.create_vmnd(network)

    def _send_update_network_request(self, network):
        LOG.debug('_send_update_network_request: %s', network['id'])
        profile = self.get_profile_by_id(network[n1kv_profile.PROFILE_ID])
        body = {'name': network['name'],
                'id': network['id'],
                'networkDefinition': profile['name'],
                'vlan': network[provider.SEGMENTATION_ID]}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_vmnd(network['name'], body)

    def _send_delete_network_request(self, network):
        LOG.debug('_send_delete_network_request: %s', network['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_vmnd(network['name'])

    def _send_create_subnet_request(self, context, subnet):
        network = self.get_network(context, subnet['network_id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_ip_pool(subnet)
        body = {'ipPoolName': subnet['name']}
        n1kvclient.update_vmnd(network['name'], body=body)
        LOG.debug('_send_create_subnet_request: %s', subnet['id'])

    def _send_update_subnet_request(self, subnet):
        LOG.debug('_send_update_subnet_request: %s', subnet['id'])

    def _send_delete_subnet_request(self, id):
        LOG.debug('_send_delete_subnet_request: %s', id)

    def _send_create_port_request(self, port):
        vm_network = n1kv_db_v2.get_vm_network(port[n1kv_profile.PROFILE_ID],
                                                port['network_id'])
        if vm_network:
            vm_network_name = vm_network['name']
            self._send_update_port_request(port, vm_network_name)
        else:
            global VM_NETWORK_NUM
            VM_NETWORK_NUM = VM_NETWORK_NUM + 1
            vm_network_name = 'vm_network_' + str(VM_NETWORK_NUM)
            n1kv_db_v2.add_vm_network(vm_network_name,
                                     port[n1kv_profile.PROFILE_ID],
                                     port['network_id'])
            n1kvclient = n1kv_client.Client()
            n1kvclient.create_port(port, vm_network_name)
        LOG.debug('_send_create_port_request: %s', port['id'])

    def _send_update_port_request(self, port, vm_network_name):
        body = {'portId': port['id'],
                'macAddress': port['mac_address']}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_port(vm_network_name, body)
        LOG.debug('_send_update_port_request: %s', port['id'])

    def _send_delete_port_request(self, id):
        LOG.debug('_send_delete_port_request: %s', id)

    def _get_segmentation_id(self, context, id):
        session = context.session
        binding_seg_id = n1kv_db_v2.get_network_binding(session, id)
        return binding_seg_id.segmentation_id

    def create_network1(self, tenant_id, network_id, network_context):
        """
        """
        LOG.debug('Aruna subplugin: create network')

    def create_network(self, context, network):
        (network_type, physical_network,
         segmentation_id) = self._process_provider_create(context,
            network['network'])

        profile_id = self._process_profile(context, network['network'])

        LOG.debug('Aruna: create network: profile_id=%s', profile_id)
        session = context.session
        with session.begin(subtransactions=True):
            if not network_type:
                # tenant network
                (physical_network, network_type, segmentation_id,
                    multicast_ip) = n1kv_db_v2.alloc_network(session,
                                                             profile_id)
                LOG.debug('Physical_network %s, seg_type %s, seg_id %s,'
                          'multicast_ip %s', physical_network, network_type,
                          segmentation_id, multicast_ip)
                if not (segmentation_id):
                    raise q_exc.TenantNetworksDisabled()
            else:
                # provider network
                if network_type == const.TYPE_VLAN:
                    n1kv_db_v2.reserve_specific_vlan(session, physical_network,
                        segmentation_id)
            net = super(N1kvQuantumPluginV2, self).create_network(context,
                network)
            n1kv_db_v2.add_network_binding(session, net['id'], network_type,
                physical_network, segmentation_id, multicast_ip, profile_id)

            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)

        #TODO: later move under port
        self._send_create_network_request(net)
            # note - exception will rollback entire transaction
        LOG.debug("Created network: %s", net['id'])
        return net

    def update_network(self, context, id, network):
        self._check_provider_update(context, network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            net = super(N1kvQuantumPluginV2, self).update_network(context, id,
                network)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
        self._send_update_network_request(net)
        LOG.debug("Updated network: %s", net['id'])
        return net

    def delete_network(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            binding = n1kv_db_v2.get_network_binding(session, id)
            network = self.get_network(context, id)
            super(N1kvQuantumPluginV2, self).delete_network(context, id)
            if binding.network_type == const.TYPE_VXLAN:
                n1kv_db_v2.release_tunnel(session, binding.segmentation_id,
                    self.tunnel_id_ranges)
            elif binding.network_type == const.TYPE_VLAN:
                n1kv_db_v2.release_vlan(session, binding.physical_network,
                    binding.segmentation_id,
                    self.network_vlan_ranges)
                # the network_binding record is deleted via cascade from
                # the network record, so explicit removal is not necessary
        if self.agent_vsm:
            self._send_delete_network_request(network)
        LOG.debug("Deleted network: %s", id)

    def get_network(self, context, id, fields=None):
        net = super(N1kvQuantumPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_profile(context, net)
        LOG.debug("Get network: %s", id)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(N1kvQuantumPluginV2, self).get_networks(context, filters,
            None)
        for net in nets:
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)

        LOG.debug("Get networks")
        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        LOG.debug("Abs out of if\n")
        if n1kv_profile.PROFILE_ID in port['port']:
            LOG.debug("Abs if PORT\n")
            profile_id = self._process_profile(context, port['port'])

            LOG.debug('Aruna: create port: profile_id=%s', profile_id)
            session = context.session
            with session.begin(subtransactions=True):
                pt = super(N1kvQuantumPluginV2, self).create_port(context,
                    port)
                n1kv_db_v2.add_port_binding(session, pt['id'], profile_id)
                self._extend_port_dict_profile(context, pt)

            self._send_create_port_request(pt)
            LOG.debug("Created port: %s", pt)
            return pt
        else:
            tenant_id = port['port']['tenant_id']
            instance_id = port['port']['device_id']
            device_owner = port['port']['device_owner']

            port_id = self._get_instance_port_id(tenant_id, instance_id)
            LOG.debug("Abs PORT UUID: %s\n", port_id)
            pt = self.get_port(context, port_id['port_id'])
            pt['device_owner'] = device_owner
            if 'fixed_ip' in port:
                fixed_ip = port['port']['fixed_ip']
                pt['fixed_ips'] = fixed_ip
            pt['device_id'] = instance_id
            port['port'] = pt
            pt = self.update_port(context, pt['id'], port)
            LOG.debug("Abs PORT: %s\n", pt)
            return pt

    def _get_instance_port_id(self, tenant_id, instance_id):
        keystone = cred._creds_dictionary['keystone']
        url = keystone.keys()[0]
        kc = keystone_client.Client(username=keystone[url]['username'],
                                    password=keystone[url]['password'],
                                    tenant_id=tenant_id,
                                    auth_url=url)
        tenant = kc.tenants.get(tenant_id)
        tenant_name = tenant.name
        nc = nova_client.Client(keystone[url]['username'],
                                keystone[url]['password'],
                                tenant_name,
                                url,
                                no_cache=True)
        serv = nc.servers.get(instance_id)
        port_id = serv.__getattr__('metadata')

        return port_id

    def update_port(self, context, id, port):
        if self.agent_vsm:
            original_port = super(N1kvQuantumPluginV2, self).get_port(context,
                id)
        port = super(N1kvQuantumPluginV2, self).update_port(context, id, port)
        self._extend_port_dict_profile(context, port)
        if self.agent_vsm:
            if original_port['admin_state_up'] != port['admin_state_up']:
                self._send_update_port_request(port)
        return port

    def delete_port(self, context, id):
        self._send_delete_port_request(id)
        return super(N1kvQuantumPluginV2, self).delete_port(context, id)

    def get_port(self, context, id, fields=None):
        port = super(N1kvQuantumPluginV2, self).get_port(context, id, fields)
        self._extend_port_dict_profile(context, port)
        LOG.debug("Get port: %s", id)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        ports = super(N1kvQuantumPluginV2, self).get_ports(context, filters,
            fields)
        for port in ports:
            self._extend_port_dict_profile(context, port)

        LOG.debug("Get ports")
        return [self._fields(port, fields) for port in ports]

    def create_subnet(self, context, subnet):
        LOG.debug('Create subnet')
        sub = super(N1kvQuantumPluginV2, self).create_subnet(context, subnet)
        self._send_create_subnet_request(context, sub)
        LOG.debug("Created subnet: %s", sub['id'])
        return sub

    def update_subnet(self, context, id, subnet):
        LOG.debug('Update subnet')
        sub = super(N1kvQuantumPluginV2, self).update_subnet(context, subnet)
        self._send_update_subnet_request(sub)
        LOG.debug("Updated subnet: %s", sub['id'])
        return sub

    def delete_subnet(self, context, id):
        LOG.debug('Delete subnet: %s', id)
        self._send_subnet_delete_request(id)
        return super(N1kvQuantumPluginV2, self).delete_subnet(context, id)

    def get_subnet(self, context, id, fields=None):
        subnet = super(N1kvQuantumPluginV2, self).get_subnet(context, id,
                                                            fields)
        LOG.debug("Get subnet: %s", id)
        return self._fields(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None):
        subnets = super(N1kvQuantumPluginV2, self).get_subnets(context, filters,
            fields)
        LOG.debug("Get subnets")
        return [self._fields(subnet, fields) for subnet in subnets]
