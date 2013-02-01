# vim: tabstop=4 shiftwidth=4 softtabstop=4
#   
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Aruna Kushwaha, Cisco Systems, Inc.
# @author: Rudrajit Tapadar, Cisco Systems, Inc.
# @author: Abhishek Raut, Cisco Systems, Inc.



import logging
import sys
import itertools

from keystoneclient.v2_0 import client as keystone_client
from novaclient.v1_1 import client as nova_client

from quantum import policy

from quantum.api.v2 import attributes
from quantum.common import constants as q_const
from quantum.common import exceptions as q_exc
from quantum.common import topics
from quantum.common import rpc as q_rpc

from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_db
from quantum.db import l3_rpc_base

from quantum.extensions import providernet as provider
from quantum.extensions import n1kv_profile as n1kv_profile

from quantum.openstack.common import context
from quantum.openstack.common import cfg as quantum_cfg
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common.rpc import proxy

from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.db import n1kv_db_v2
from quantum.plugins.cisco.db import n1kv_profile_db
from quantum.plugins.cisco.n1kv import n1kv_configuration as n1kv_conf
from quantum.plugins.cisco.n1kv import n1kv_client


LOG = logging.getLogger(__name__)
VM_NETWORK_NUM = itertools.count()  # thread-safe increment operations


class N1kvRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                       l3_rpc_base.L3RpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, notifier):
        self.notifier = notifier

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self])

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details"""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s details requested from %(agent_id)s"),
                  locals())
        port = n1kv_db_v2.get_port(device)
        if port:
            binding = n1kv_db_v2.get_network_binding(None, port['network_id'])
            entry = {'device': device,
                     'network_id': port['network_id'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up'],
                     'network_type': binding.network_type,
                     'segmentation_id': binding.segmentation_id,
                     'physical_network': binding.physical_network}
            # Set the port status to UP
            n1kv_db_v2.set_port_status(port['id'], q_const.PORT_STATUS_ACTIVE)
        else:
            entry = {'device': device}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent"""
        # (TODO) garyk - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s no longer exists on %(agent_id)s"),
                  locals())
        port = n1kv_db_v2.get_port(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            n1kv_db_v2.set_port_status(port['id'], q_const.PORT_STATUS_DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def tunnel_sync(self, rpc_context, **kwargs):
        """Update new tunnel.

        Updates the datbase with the tunnel IP. All listening agents will also
        be notified about the new tunnel IP.
        """
        tunnel_ip = kwargs.get('tunnel_ip')
        # Update the database with the IP
        tunnel = n1kv_db_v2.add_tunnel_endpoint(tunnel_ip)
        tunnels = n1kv_db_v2.get_tunnel_endpoints()
        entry = dict()
        entry['tunnels'] = tunnels
        # Notify all other listening agents
        self.notifier.tunnel_update(rpc_context, tunnel.ip_address,
                                    tunnel.id)
        # Return the list of tunnels IP's to the agent
        return entry


class AgentNotifierApi(proxy.RpcProxy):
    '''Agent side of the N1kv rpc API.

    API version history:
        1.0 - Initial version.

    '''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)
        self.topic_tunnel_update = topics.get_topic_name(topic,
                                                         const.TUNNEL,
                                                         topics.UPDATE)

    def network_delete(self, context, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, network_type, segmentation_id,
                    physical_network):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       network_type=network_type,
                                       segmentation_id=segmentation_id,
                                       physical_network=physical_network),
                         topic=self.topic_port_update)

    def tunnel_update(self, context, tunnel_ip, tunnel_id):
        self.fanout_cast(context,
                         self.make_msg('tunnel_update',
                                       tunnel_ip=tunnel_ip,
                                       tunnel_id=tunnel_id),
                         topic=self.topic_tunnel_update)


class N1kvQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                         l3_db.L3_NAT_db_mixin,
                         n1kv_profile_db.N1kvProfile_db_mixin):
    """
    Implement the Quantum abstractions using Cisco Nexus1000V

    Read README file for the architecture, new features, and 
    workflow

    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True
    supported_extension_aliases = ["provider", "profile", "n1kv_profile",
                                    "router"]

    def __init__(self, configfile=None):
        """
        Initialize Nexus1000V Quantum plugin

        1. Initialize DB
        2. Establish communication with Cisco Nexus1000V
        3. Retrieve port-profiles
        """
        n1kv_db_v2.initialize()
        #cred.Store.initialize()
        # TBD Begin : To be removed. No need for this parameters
        self._parse_network_vlan_ranges()
        n1kv_db_v2.sync_vlan_allocations(self.network_vlan_ranges)
        self.enable_tunneling = n1kv_conf.N1KV['enable_tunneling']
        self.tunnel_id_ranges = []
        if self.enable_tunneling:
            self._parse_tunnel_id_ranges()
            n1kv_db_v2.sync_tunnel_allocations(self.tunnel_id_ranges)
        # TBD end 
        self._setup_vsm()
        # TBD : Temporary change to enabld dhcp. To be removed
        self.setup_rpc()

    def setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.callbacks = N1kvRpcCallbacks(self.notifier)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def _setup_vsm(self):
        """ Establish Communication with Cisco Nexus1000V VSM """
        LOG.debug('_setup_vsm')
        self.agent_vsm = True
        self._send_register_request()

    def _poll_policies(self, tenant_id):
        """ Retrieve Port-Profiles from Cisco Nexus1000V VSM """
        LOG.debug('_poll_policies')
        n1kvclient = n1kv_client.Client()
        self._add_policy_profiles(n1kvclient, tenant_id)

    def _add_policy_profiles(self, n1kvclient, tenant_id):
        """Populate Profiles of type Policy on init."""
        profiles = n1kvclient.list_profiles()
        for profile in profiles[const.SET]:
            profile_id = profile[const.PROPERTIES][const.ID]
            profile_name = profile[const.PROPERTIES][const.NAME]
            self.add_profile(tenant_id,
                             profile_id, profile_name, const.POLICY)

    # TBD Begin : To be removed. Needs some change in logic before removal
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

    # TBD End 

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
            "extension:provider_network:view",
            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
            "extension:provider_network:set",
            network)

    def _extend_network_dict_provider(self, context, network):
        """ Add extended network parameters """
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
            if segmentation_id < 5000:
                msg = _("provider:segmentation_id out of range "
                        "(5000+)")
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
        """ Handle Provider network updates """
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

        # TBD : Need to handle provider network updates
        msg = _("plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def _extend_network_dict_profile(self, context, network):
        """ Add the extended parameter network profile to the network """
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _extend_port_dict_profile(self, context, port):
        """ Add the extended parameter port profile to the port """
        #if self._check_provider_view_auth(context, network):
        binding = n1kv_db_v2.get_port_binding(context.session,
                port['id'])
        port[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _process_profile(self, context, attrs):
        """ Validate profile exists """
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)

        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            msg = _("n1kv_profile:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)
        if not self.network_profile_exist(context, profile_id):
            msg = _("n1kv_profile:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)

        return (profile_id)

    #TBD: remove added for compilation
    def _send_register_request(self):
        LOG.debug('_send_register_request')

    def _send_create_network_request(self, network):
        """ Send Create network request to VSM """
        LOG.debug('_send_create_network_request: %s', network['id'])
        profile = self.get_profile_by_id(network[n1kv_profile.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_network_segment_pool(profile)
        if network[provider.NETWORK_TYPE] == const.TYPE_VXLAN:
            n1kvclient.create_bridge_domain(network)
        n1kvclient.create_network_segment(network)

    def _send_update_network_request(self, network):
        """ Send Update network request to VSM """
        LOG.debug('_send_update_network_request: %s', network['id'])
        profile = self.get_profile_by_id(network[n1kv_profile.PROFILE_ID])
        body = {'name': network['name'],
                'id': network['id'],
                'networkDefinition': profile['name'],
                'vlan': network[provider.SEGMENTATION_ID]}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment(network['name'], body)

    def _send_delete_network_request(self, network):
        """ Send Delete network request to VSM """
        LOG.debug('_send_delete_network_request: %s', network['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_network_segment(network['name'])

    def _send_create_subnet_request(self, context, subnet):
        """ Send Create Subnet request to VSM """
        LOG.debug('_send_create_subnet_request: %s', subnet['id'])
        network = self.get_network(context, subnet['network_id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_ip_pool(subnet)
        body = {'ipPoolName': subnet['name']}
        n1kvclient.update_network_segment(network['name'], body=body)

    # TBD Begin : Need to implement this function
    def _send_update_subnet_request(self, subnet):
        """ Send Create Subnet request to VSM """
        LOG.debug('_send_update_subnet_request: %s', subnet['id'])

    def _send_delete_subnet_request(self, id):
        """ Send Delete Subnet request to VSM """
        LOG.debug('_send_delete_subnet_request: %s', id)
    # TBD End : 

    def _send_create_port_request(self, port):
        """ Send Create Port request to VSM """
        LOG.debug('_send_create_port_request: %s', port['id'])
        vm_network = n1kv_db_v2.get_vm_network(port[n1kv_profile.PROFILE_ID],
                                                port['network_id'])
        if vm_network:
            vm_network_name = vm_network['name']
            self._send_update_port_request(port, vm_network_name)
        else:
            current_vm_network_num = VM_NETWORK_NUM.next()
            vm_network_name = 'vm_network_' + str(current_vm_network_num)
            n1kv_db_v2.add_vm_network(vm_network_name,
                                     port[n1kv_profile.PROFILE_ID],
                                     port['network_id'])
            n1kvclient = n1kv_client.Client()
            n1kvclient.create_n1kv_port(port, vm_network_name)

    def _send_update_port_request(self, port, vm_network_name):
        """ Send Update Port request to VSM """
        LOG.debug('_send_update_port_request: %s', port['id'])
        body = {'portId': port['id'],
                'macAddress': port['mac_address']}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_n1kv_port(vm_network_name, body)

    def _send_delete_port_request(self, id):
        """ Send Delete Port request to VSM """
        LOG.debug('_send_delete_port_request: %s', id)

    def _get_segmentation_id(self, context, id):
        """ Send Delete Port request to VSM """
        session = context.session
        binding_seg_id = n1kv_db_v2.get_network_binding(session, id)
        return binding_seg_id.segmentation_id

    def create_network(self, context, network):
        """ Create network based on Network Profile """
        self._poll_policies(network['network']['tenant_id'])
        (network_type, physical_network,
         segmentation_id) = self._process_provider_create(context,
            network['network'])

        profile_id = self._process_profile(context, network['network'])

        LOG.debug('create network: profile_id=%s', profile_id)
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
                if not segmentation_id:
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
        """ Update network Parameters """
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
        """ Delete Network """
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
        """ Read Network """
        LOG.debug("Get network: %s", id)
        net = super(N1kvQuantumPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_profile(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        """ Read All Networks """
        LOG.debug("Get networks")
        nets = super(N1kvQuantumPluginV2, self).get_networks(context, filters,
            None)
        for net in nets:
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)

        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        """ 
        Create Quantum port
        
        Create Port will be called twice when using this plugin
        Once directly, and another through Nova

        If it call directly it must have the port-profile ID set

        If called from Nova, then the metadata should be present
        to identify the pre created port

        """
        if n1kv_profile.PROFILE_ID in port['port']:
            profile_id = self._process_profile(context, port['port'])
            LOG.debug('create port: profile_id=%s', profile_id)
            session = context.session
            with session.begin(subtransactions=True):
                pt = super(N1kvQuantumPluginV2, self).create_port(context,
                    port)
                n1kv_db_v2.add_port_binding(session, pt['id'], profile_id)
                self._extend_port_dict_profile(context, pt)

            self._send_create_port_request(pt)
            LOG.debug("Created port: %s", pt)
            return pt
        elif 'device_id' in port['port'].keys():
            if port['port']['device_id'].startswith('dhcp'):
                # Grab profile id from the network
                network_id = port['port']['network_id']
                network = self.get_network(context, network_id)
                port['port']['n1kv:profile_id'] = network['n1kv:profile_id']
                tenant_id = port['port']['tenant_id']
                instance_id = port['port']['device_id']
                device_owner = port['port']['device_owner']
                # Create this port
                cport = self.create_port(context, port)
                LOG.debug("Abs PORT UUID: %s\n", port)
                pt = self.get_port(context, cport['id'])
                pt['device_owner'] = device_owner
                if 'fixed_ip' in port:
                    fixed_ip = cport['fixed_ip']
                    pt['fixed_ips'] = fixed_ip
                pt['device_id'] = instance_id
                port['port'] = pt
                pt = self.update_port(context, pt['id'], port)
                LOG.debug("Abs PORT: %s\n", pt)
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
        """ Get the port IDs from the meta data """
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
        """ Update port parameters """
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
        """ Delete port """
        self._send_delete_port_request(id)
        return super(N1kvQuantumPluginV2, self).delete_port(context, id)

    def get_port(self, context, id, fields=None):
        """ Read port """
        LOG.debug("Get port: %s", id)
        port = super(N1kvQuantumPluginV2, self).get_port(context, id, fields)
        self._extend_port_dict_profile(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        """ Read all ports """
        LOG.debug("Get ports")
        ports = super(N1kvQuantumPluginV2, self).get_ports(context, filters,
            fields)
        for port in ports:
            self._extend_port_dict_profile(context, port)

        return [self._fields(port, fields) for port in ports]

    def create_subnet(self, context, subnet):
        """ Create Subnet for a given network """
        LOG.debug('Create subnet')
        sub = super(N1kvQuantumPluginV2, self).create_subnet(context, subnet)
        self._send_create_subnet_request(context, sub)
        LOG.debug("Created subnet: %s", sub['id'])
        return sub

    def update_subnet(self, context, id, subnet):
        """ Update Subnet """
        LOG.debug('Update subnet')
        sub = super(N1kvQuantumPluginV2, self).update_subnet(context, subnet)
        self._send_update_subnet_request(sub)
        LOG.debug("Updated subnet: %s", sub['id'])
        return sub

    def delete_subnet(self, context, id):
        """ Delete a Subnet """
        LOG.debug('Delete subnet: %s', id)
        self._send_delete_subnet_request(id)
        return super(N1kvQuantumPluginV2, self).delete_subnet(context, id)

    def get_subnet(self, context, id, fields=None):
        """ Read a Subnet """
        LOG.debug("Get subnet: %s", id)
        subnet = super(N1kvQuantumPluginV2, self).get_subnet(context, id,
                                                            fields)
        return self._fields(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None):
        """ Read all the Subnets """
        LOG.debug("Get subnets")
        subnets = super(N1kvQuantumPluginV2, self).get_subnets(context, filters,
            fields)
        return [self._fields(subnet, fields) for subnet in subnets]
