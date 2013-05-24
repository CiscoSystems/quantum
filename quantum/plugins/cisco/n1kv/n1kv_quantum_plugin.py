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
# @author: Sergey Sudakovich, Cisco Systems, Inc.


import logging
import sys
import itertools
import threading
import time

from novaclient.v1_1 import client as nova_client
from oslo.config import cfg as quantum_cfg

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
from quantum.db import agents_db

from quantum.extensions import providernet as provider

from quantum.openstack.common import context
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common.rpc import proxy
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api

from quantum.plugins.cisco.extensions import n1kv_profile as n1kv_profile
from quantum.plugins.cisco.extensions import network_profile
from quantum.plugins.cisco.extensions import policy_profile
from quantum.plugins.cisco.extensions import credential
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.common import config as conf
from quantum.plugins.cisco.common import cisco_exceptions
from quantum.plugins.cisco.db import n1kv_db_v2
from quantum.plugins.cisco.db import n1kv_profile_db
from quantum.plugins.cisco.db import network_db_v2
from quantum.plugins.cisco.n1kv import n1kv_client


LOG = logging.getLogger(__name__)
POLL_DURATION = 10

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
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

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

    def vxlan_sync(self, rpc_context, **kwargs):
        """Update new vxlan.

        Updates the datbase with the vxlan IP. All listening agents will also
        be notified about the new vxlan IP.
        """
        vxlan_ip = kwargs.get('vxlan_ip')
        # Update the database with the IP
        vxlan = n1kv_db_v2.add_vxlan_endpoint(vxlan_ip)
        vxlans = n1kv_db_v2.get_vxlan_endpoints()
        entry = dict()
        entry['vxlans'] = vxlans
        # Notify all other listening agents
        self.notifier.vxlan_update(rpc_context, vxlan.ip_address,
                                    vxlan.id)
        # Return the list of vxlans IP's to the agent
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
        self.topic_vxlan_update = topics.get_topic_name(topic,
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

    def vxlan_update(self, context, vxlan_ip, vxlan_id):
        self.fanout_cast(context,
                         self.make_msg('vxlan_update',
                                       vxlan_ip=vxlan_ip,
                                       vxlan_id=vxlan_id),
                         topic=self.topic_vxlan_update)


class N1kvQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                         l3_db.L3_NAT_db_mixin,
                         # n1kv_profile_db.N1kvProfile_db_mixin,
                         n1kv_db_v2.NetworkProfile_db_mixin,
                         n1kv_db_v2.PolicyProfile_db_mixin,
                         network_db_v2.Credential_db_mixin):
    """
    Implement the Quantum abstractions using Cisco Nexus1000V

    Read README file for the architecture, new features, and
    workflow

    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = False
    supported_extension_aliases = ["provider", "agent",
                                   "n1kv_profile", "network_profile",
                                   "policy_profile", "router", "credential"]

    def __init__(self, configfile=None):
        """
        Initialize Nexus1000V Quantum plugin

        1. Initialize DB
        2. Establish communication with Cisco Nexus1000V
        3. Retrieve port-profiles
        """
        n1kv_db_v2.initialize()
        cred.Store.initialize()
        # TBD Begin : To be removed. No need for this parameters
        # If no api_extensions_path is provided set the following
        if not quantum_cfg.CONF.api_extensions_path:
            quantum_cfg.CONF.set_override(
                'api_extensions_path',
                'quantum/plugins/cisco/extensions')
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
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.conn.consume_in_thread()

    def _setup_vsm(self):
        """ Establish Communication with Cisco Nexus1000V VSM """
        LOG.debug('_setup_vsm')
        self.agent_vsm = True
        self._send_register_request()
        PollVSM().start()

    def _poll_policies(self, event_type=None, epoch=None, tenant_id=None):
        """
        Retrieve Policy Profiles from Cisco Nexus1000V
        """
        LOG.debug('_poll_policies')
        n1kvclient = n1kv_client.Client()
        policy_profiles = n1kvclient.list_events(event_type, epoch)
        for profile in policy_profiles['body'][const.SET]:
            if const.NAME in profile:
                cmd = profile[const.PROPERTIES]['cmd']
                cmds = cmd.split(';')
                cmdwords = cmds[1].split()
                time = profile[const.PROPERTIES]['time']
                profile_name = profile[const.PROPERTIES][const.NAME]
                if 'no' in cmdwords[0]:
                    p = self._get_policy_profile_by_name(profile_name)
                    if p:
                        self._delete_policy_profile(p['id'])
                elif const.ID in profile[const.PROPERTIES]:
                    profile_id = profile[const.PROPERTIES][const.ID]
                    self._add_policy_profile(profile_name, profile_id, tenant_id)
        self._remove_all_fake_policy_profiles()

    # TBD Begin : To be removed. Needs some change in logic before removal
    def _parse_network_vlan_ranges(self):
        self.network_vlan_ranges = {}
        ranges = conf.CISCO_N1K.network_vlan_ranges
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

    def _parse_vxlan_id_ranges(self):
        ranges = conf.CISCO_N1K.vxlan_id_ranges
        ranges = ranges.split(',')
        for entry in ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                self.vxlan_id_ranges.append((int(tun_min), int(tun_max)))
            except ValueError as ex:
                LOG.error("Invalid vxlan ID range: \'%s\' - %s", entry, ex)
                sys.exit(1)
        LOG.info("Tunnel ID ranges: %s", self.vxlan_id_ranges)

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

    def _process_network_profile(self, context, attrs):
        """ Validate network profile exists """
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            raise cisco_exceptions.NetworkProfileIdNotFound(profile_id=profile_id)
        if not self.network_profile_exists(context, profile_id):
            raise cisco_exceptions.NetworkProfileIdNotFound(profile_id=profile_id)
        return (profile_id)

    def _process_policy_profile(self, context, attrs):
        """ Validates whether policy profile exists """
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            msg = _("n1kv:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)
        if not self.policy_profile_exists(context, profile_id):
            msg = _("n1kv:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)

        return (profile_id)

    #TBD: remove added for compilation
    def _send_register_request(self):
        LOG.debug('_send_register_request')

    def _send_create_fabric_network_request(self, profile):
        """
        Send Create fabric network request to VSM.
        """
        LOG.debug('_send_create_fabric_network')
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_fabric_network(profile)

    def _send_create_network_profile_request(self, context, profile):
        """
        Send Create network profile request to VSM.
        :param context:
        :param profile:
        :return:
        """
        LOG.debug('_send_create_network_profile_request: %s', profile['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_network_segment_pool(profile)

    def _send_delete_network_profile_request(self, profile):
        """
        Send Delete network profile request to VSM.
        :param profile:
        :return:
        """
        LOG.debug('_send_delete_network_profile_request: %s', profile['name'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_network_segment_pool(profile['name'])

    def _send_create_network_request(self, context, network):
        """
        Send Create network request to VSM.
        :param context:
        :param network:
        :return:
        """
        LOG.debug('_send_create_network_request: %s', network['id'])
        profile = self.get_network_profile(context,
                    network[n1kv_profile.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        if network[provider.NETWORK_TYPE] == const.TYPE_VXLAN:
            n1kvclient.create_bridge_domain(network)
        n1kvclient.create_network_segment(network, profile)

    def _send_update_network_request(self, network):
        """ Send Update network request to VSM """
        LOG.debug('_send_update_network_request: %s', network['id'])
        profile = n1kv_db_v2.get_network_profile(network[n1kv_profile.PROFILE_ID])
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
        if network[provider.NETWORK_TYPE] == const.TYPE_VXLAN:
            name = network['name'] + '_bd'
            n1kvclient.delete_bridge_domain(name)
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
    # TBD End.

    def _send_delete_subnet_request(self, subnet):
        """ Send Delete Subnet request to VSM """
        LOG.debug('_send_delete_subnet_request: %s', id)
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_ip_pool(subnet['name'])

    def _send_create_port_request(self, context, port):
        """ Send Create Port request to VSM """
        LOG.debug('_send_create_port_request: %s', port)
        vm_network = n1kv_db_v2.get_vm_network(port[n1kv_profile.PROFILE_ID],
                                                port['network_id'])
        if vm_network:
            vm_network_name = vm_network['name']
            n1kvclient = n1kv_client.Client()
            n1kvclient.create_n1kv_port(port, vm_network_name)
            vm_network['port_count'] = self._update_port_count(vm_network['port_count'],
                                                               action='increment')
            n1kv_db_v2.update_vm_network(vm_network_name, vm_network['port_count'])
        else:
            policy_profile = n1kv_db_v2.get_policy_profile(\
                                port[n1kv_profile.PROFILE_ID])
            vm_network_name = "vmn_" + str(port[n1kv_profile.PROFILE_ID]) +\
                              "_" + str(port['network_id'])
            port_count = 1
            n1kv_db_v2.add_vm_network(vm_network_name,
                                     port[n1kv_profile.PROFILE_ID],
                                     port['network_id'],
                                     port_count)
            n1kvclient = n1kv_client.Client()
            n1kvclient.create_vm_network(port, vm_network_name, policy_profile)
            n1kvclient.create_n1kv_port(port, vm_network_name)

    def _send_update_port_request(self, port, vm_network_name):
        """ Send Update Port request to VSM """
        LOG.debug('_send_update_port_request: %s', port['id'])
        body = {'portId': port['id'],
                'macAddress': port['mac_address']}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_n1kv_port(vm_network_name, port['id'], body)

    def _update_port_count(self, port_count, action):
        """ Increments/Decrements port count by 1 based on action.
            action: increment or decrement
        """
        if action == 'increment':
            port_count = port_count + 1
        elif action == 'decrement':
            port_count = port_count - 1
        return port_count

    def _send_delete_port_request(self, context,id):
        """ Send Delete Port request to VSM """
        LOG.debug('_send_delete_port_request: %s', id)
        port = self.get_port(context, id)
        vm_network = n1kv_db_v2.get_vm_network(port[n1kv_profile.PROFILE_ID],
                                               port['network_id'])
        vm_network['port_count'] = self._update_port_count(vm_network['port_count'],
                                                           action='decrement')
        n1kv_db_v2.update_vm_network(vm_network['name'], vm_network['port_count'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_n1kv_port(vm_network['name'], id)
        if vm_network['port_count'] == 0:
            n1kv_db_v2.delete_vm_network(port[n1kv_profile.PROFILE_ID],
                                         port['network_id'])
            n1kvclient.delete_vm_network(vm_network['name'])

    def _get_segmentation_id(self, context, id):
        """ Send Delete Port request to VSM """
        session = context.session
        binding_seg_id = n1kv_db_v2.get_network_binding(session, id)
        return binding_seg_id.segmentation_id

    def create_network(self, context, network):
        """ Create network based on Network Profile """
        (network_type, physical_network,
         segmentation_id) = self._process_provider_create(context,
            network['network'])
        self._add_dummy_profile_for_test(network)
        profile_id = self._process_network_profile(context, network['network'])

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
        self._send_create_network_request(context, net)
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
                n1kv_db_v2.release_vxlan(session, binding.segmentation_id,
                    self.vxlan_id_ranges)
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
        self._add_dummy_profile_for_test(port)

        profile_id_set = False
        if n1kv_profile.PROFILE_ID in port['port']:
            profile_id = port['port'].get(n1kv_profile.PROFILE_ID)
            profile_id_set = attributes.is_attr_set(profile_id)

        if profile_id_set:
            # If it is a dhcp port, profile id is
            # populated with network profile id.
            profile_id = self._process_policy_profile(context,
                                                      port['port'])
            LOG.debug('create port: profile_id=%s', profile_id)
            session = context.session
            with session.begin(subtransactions=True):
                pt = super(N1kvQuantumPluginV2, self).create_port(context,
                    port)
                n1kv_db_v2.add_port_binding(session, pt['id'], profile_id)
                self._extend_port_dict_profile(context, pt)
            self._send_create_port_request(context, pt)
            LOG.debug("Created port: %s", pt)
            return pt
        elif 'device_id' in port['port'].keys():
            if port['port']['device_id'].startswith('dhcp'):
                # Grab profile id from the network
                LOG.debug("create dhcp port")
                p_profile_name = conf.CISCO_N1K.default_policy_profile
                p_profile = self._get_policy_profile_by_name(p_profile_name) 
                port['port']['n1kv:profile_id'] = p_profile['id']
                tenant_id = port['port']['tenant_id']
                instance_id = port['port']['device_id']
                device_owner = port['port']['device_owner']
                # Create this port
                cport = self.create_port(context, port)
                LOG.debug("DHCP PORT UUID: %s\n", port)
                pt = self.get_port(context, cport['id'])
                pt['device_owner'] = device_owner
                if 'fixed_ip' in port:
                    pt['fixed_ips'] = cport['fixed_ip']
                pt['device_id'] = instance_id
                port['port'] = pt
                pt = self.update_port(context, pt['id'], port)
                return pt
            else:
                tenant_id = port['port']['tenant_id']
                instance_id = port['port']['device_id']
                device_owner = port['port']['device_owner']
                port_id = self._get_instance_port_id(tenant_id, instance_id)
                LOG.debug("PORT UUID: %s\n", port_id)
                pt = self.get_port(context, port_id['port_id'])
                pt['device_owner'] = device_owner
                if 'fixed_ip' in port:
                    pt['fixed_ips'] = port['port']['fixed_ip']
                pt['device_id'] = instance_id
                port['port'] = pt
                pt = self.update_port(context, pt['id'], port)
                return pt

    def _add_dummy_profile_for_test(self, obj):
        """
        Method to be patched by the test_n1kv_plugin module to 
        inject n1kv:profile_id into the network/port object, since the plugin
        tests for its existence. This method does not affect 
        the plugin code in any way.
        """
        pass

    def _get_instance_port_id(self, tenant_id, instance_id):
        """ Get the port IDs from the meta data """
        keystone_conf = quantum_cfg.CONF.keystone_authtoken
        keystone_auth_url = '%s://%s:%s/v2.0/' % (keystone_conf.auth_protocol,
                                                  keystone_conf.auth_host,
                                                  keystone_conf.auth_port)
        nc = nova_client.Client(keystone_conf.admin_user,
                                keystone_conf.admin_password,
                                keystone_conf.admin_tenant_name,
                                keystone_auth_url,
                                no_cache=True)
        serv = nc.servers.get(instance_id)
        port_id = serv.__getattr__('metadata')
        LOG.debug("Got port ID from nova: %s", port_id)

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
                vm_network = n1kv_db_v2.get_vm_network(port[n1kv_profile.PROFILE_ID],
                                                port['network_id'])
                self._send_update_port_request(port, vm_network['name'])
        return port

    def delete_port(self, context, id):
        """ Delete port """
        self._send_delete_port_request(context, id)
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
        subnet = self.get_subnet(context, id)
        self._send_delete_subnet_request(subnet)
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
        subnets = super(N1kvQuantumPluginV2, self).get_subnets(context,
                                                               filters,
                                                               fields)
        return [self._fields(subnet, fields) for subnet in subnets]

    def create_network_profile(self, context, network_profile):
        self._replace_fake_tenant_id_with_real(context)
        _network_profile = super(N1kvQuantumPluginV2, self).create_network_profile(context, network_profile)
        seg_min, seg_max = self._get_segment_range(_network_profile['segment_range'])
        if _network_profile['segment_type'] == const.TYPE_VLAN:
            self.network_vlan_ranges = {}
            self._add_network_vlan_range(_network_profile['physical_network'],
                            int(seg_min),
                            int(seg_max))
            n1kv_db_v2.sync_vlan_allocations(self.network_vlan_ranges)
        elif _network_profile['segment_type'] == const.TYPE_VXLAN:
            self.vxlan_id_ranges = []
            self.vxlan_id_ranges.append((int(seg_min), int(seg_max)))
            n1kv_db_v2.sync_vxlan_allocations(self.vxlan_id_ranges)
        #self._send_create_fabric_network_request(_network_profile)
        self._send_create_network_profile_request(context, _network_profile)
        return _network_profile

    def delete_network_profile(self, context, id):
        _network_profile = super(N1kvQuantumPluginV2, self).delete_network_profile(context, id)
        seg_min, seg_max = self._get_segment_range(_network_profile['segment_range'])
        if _network_profile['segment_type'] == const.TYPE_VLAN:
            self.network_vlan_ranges = {}
            self._add_network_vlan_range(_network_profile['physical_network'],
                            int(seg_min),
                            int(seg_max))
            n1kv_db_v2.delete_vlan_allocations(self.network_vlan_ranges)
        elif _network_profile['segment_type'] == const.TYPE_VXLAN:
            self.delete_vxlan_ranges = []
            self.delete_vxlan_ranges.append((int(seg_min), int(seg_max)))
            n1kv_db_v2.delete_vxlan_allocations(self.delete_vxlan_ranges)
        self._send_delete_network_profile_request(_network_profile)

class PollVSM (threading.Thread, N1kvQuantumPluginV2):
    def run(self):
        while True:
            self._poll_policies(event_type="port_profile")
            time.sleep(POLL_DURATION)
