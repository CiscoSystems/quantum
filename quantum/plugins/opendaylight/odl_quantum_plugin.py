# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Arvind Somya, Cisco Systems, Inc.
# @author: Kyle Mestery, Cisco Systems, Inc.

import base64
import httplib
import json
import uuid

from oslo.config import cfg

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.common import constants as q_const
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import agents_db
from quantum.db.db_base_plugin_v2 import QuantumDbPluginV2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_rpc_base
from quantum.db.securitygroups_db import SecurityGroupDbMixin
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.opendaylight import config  # noqa
from quantum.plugins.opendaylight import odl_db
from quantum.plugins.opendaylight import odl_xml_snippets


LOG = logging.getLogger(__name__)


DEFAULT_CONTAINER = 'default'
DEFAULT_PRIORITY = 1
SWITCH_LIST_PATH = '/controller/nb/v2/switch/%s/nodes/'
SWITCH_GET_PATH = '/controller/nb/v2/switch/%s/node/%s/%s'
HOST_LIST_PATH = '/controller/nb/v2/host/%s/'
FLOW_LIST_PATH = '/controller/nb/v2/flow/%s/'
FLOW_CREATE_PATH = '/controller/nb/v2/flow/%s/%s/%s/%s'
SUBNET_LIST_PATH = '/controller/nb/v2/subnet/%s'
SUBNET_CREATE_PATH = '/controller/nb/v2/subnet/%s/%s'
HOST_ADD_PATH = '/controller/nb/v2/host/%s/%s'


class SegmentationManager(object):
    def get_segmentation_id(self, session, network_id):
        segment = odl_db.get_network_binding(session, network_id)
        return segment['segmentation_id']

    def allocate_network_segment(self, session, network_id):
        LOG.debug(_("Allocating segment for network"))
        # Check segmentation type
        if cfg.CONF.ODL.tenant_network_type == 'vlan':
            # Grab a free vlan id
            segment_id = odl_db.allocate_network_segment(
                session, network_id, 'vlan',
                cfg.CONF.ODL.network_vlan_ranges)
        elif cfg.CONF.ODL.tenant_network_type == 'gre':
            # Grab a free tunnel id
            segment_id = odl_db.allocate_network_segment(
                session, network_id, 'gre',
                cfg.CONF.ODL.network_tunnel_ranges)
            LOG.debug(_("GRE segment_id: %d") % segment_id)

    def delete_segment_binding(self, session, network_id):
        LOG.debug(_("Deleting segment allocation"))
        odl_db.del_network_binding(None, network_id)


class ODLRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                      l3_rpc_base.L3RpcCallbackMixin,
                      sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    RPC_API_VERSION = '1.1'

    def __init__(self, notifier):
        self.notifier = notifier

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.'''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    def odl_port_create(self, rpc_context, *args, **kwargs):
        LOG.debug(_("Port create RPC call received"))
        obj = ODLQuantumPlugin()
        obj._create_port_add_flows(rpc_context, kwargs)

    def odl_port_delete(self, rpc_context, *args, **kwargs):
        LOG.debug(_("Port delete RPC call received"))
        obj = ODLQuantumPlugin()
        obj._delete_port_del_flow(rpc_context, kwargs)

    def get_segment_id(self, rpc_context, *args, **kwargs):
        LOG.debug(_("Getting segment id for port"))
        port = kwargs['port_id']
        obj = ODLQuantumPlugin()
        port = obj.get_port(rpc_context, port)
        network_id = port['network_id']
        segmgr = SegmentationManager()

        return segmgr.get_segmentation_id(None, network_id)

    def get_port_from_device(cls, device):
        port = odl_db.get_port_from_device(device)
        if port:
            port['device'] = device
        return port


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin):

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def port_update(self, context, port, segmentation_id):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       segmentation_id=segmentation_id),
                         topic=self.topic_port_update)


class ODLQuantumPlugin(QuantumDbPluginV2, SecurityGroupDbMixin):

    _supported_extension_aliases = ["provider", "router", "agent",
                                    "binding", "quotas", "security-group"]

    def __init__(self):
        odl_db.initialize()
        self.controllers = []
        controllers = cfg.CONF.ODL.controllers.split(',')
        self.controllers.extend(controllers)
        self.conn = False
        self.ovs_ports = {}
        self.phy_br_port_id = None
        self.segmentation_manager = SegmentationManager()
        self.setup_rpc()

    def setup_rpc(self):
        LOG.debug(_("Setting up RPC handlers"))
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify
        self.callbacks = ODLRpcCallbacks(self.notifier)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def _rest_call(self, action, uri, headers, data=None):
        LOG.debug(_("Making rest call to controller at %s") % uri)

        data = data or {}
        (ip, port, username, password) = self.controllers[0].split(':')
        conn = httplib.HTTPConnection(ip, port)

        # Add auth
        auth = 'Basic %s' % \
               base64.encodestring('%s:%s' % (username, password)).strip()
        headers['Authorization'] = auth

        conn.request(action, uri, data, headers)
        response = conn.getresponse()
        respstr = response.read()

        return (response.status, respstr)

    def _get_phy_br_port_id(self, context, switch_id,
                            container=DEFAULT_CONTAINER):
        LOG.debug(_("Getting physical bridge port openflow id"))
        if self.phy_br_port_id:
            return self.phy_br_port_id

        uri = SWITCH_GET_PATH % (container, 'OF', switch_id)
        headers = {}
        (status, response) = self._rest_call('GET', uri,
                                             headers, json.dumps({}))
        response = json.loads(response)
        if status == 200:
            for connector in response["nodeConnectorProperties"]:
                if str(connector['properties']['name']['nameValue']) == \
                    str(cfg.CONF.ODL.physical_bridge):
                    self.phy_br_port_id = connector['nodeconnector']['@id']
                    return self.phy_br_port_id

        return False

    def _add_port_drop_flow(self, context, switch_id, port_id,
                            of_port_id, priority, container):
        duuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_DROP_PACKET_XML % \
            (switch_id, of_port_id, duuid, priority)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, duuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, duuid, port_id, 'drop')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _add_static_host(self, context, mac_address, switch_id, of_port_id,
                         node_ip, segmentation_id, container):
        query_args = '?dataLayerAddress=%s&nodeType=OF&nodeId=%s&'
        query_args += 'nodeConnectorType=OF&nodeConnectorId=%s&vlan=%s'
        query_args = query_args % (mac_address, switch_id, of_port_id,
                                   segmentation_id)
        uri = HOST_ADD_PATH % (container, node_ip)
        uri = uri + query_args
        (status, response) = self._rest_call('POST', uri, {}, json.dumps({}))
        if status == 201:
            LOG.debug(_("Host added"))
            #odl_db.add_port_flow(context.session, fuuid, port_id, 'setVlan')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _port_outbound_setvlan_flow(self, context, switch_id, port_id,
                                    of_port_id, segmentation_id, priority,
                                    container):
        fuuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_VLAN_SET_FLOW_XML % (switch_id,
                                                         of_port_id, fuuid,
                                                         priority,
                                                         segmentation_id)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, fuuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, fuuid, port_id, 'setVlan')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _port_inbound_strip_vlan_flow(self, context, switch_id, port_id,
                                      of_port_id, segmentation_id,
                                      priority, container):
        ruuid = uuid.uuid4()
        xml = odl_xml_snippets.INT_PORT_POP_VLAN_XML % (switch_id,
                                                        ruuid, priority,
                                                        segmentation_id,
                                                        of_port_id)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, ruuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, ruuid, port_id, 'popVlan')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _add_port_gateway_flow(self, context, switch_id, port_id, of_port_id,
                               gateway_ip, priority, container):
        guuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_GATEWAY_FLOW_XML % (switch_id,
                                                        of_port_id,
                                                        guuid,
                                                        gateway_ip,
                                                        priority)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, guuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, guuid, port_id, 'gateway')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _add_port_port_dual_flow(self, context, switch_id, ingress_id,
                                 egress_id, priority, container, label):

        duuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_DHCP_FLOW_XML % (switch_id,
                                                     ingress_id,
                                                     duuid,
                                                     priority,
                                                     egress_id)

        # Add forward flow
        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, duuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, duuid, ingress_id, label)
        else:
            LOG.error(_("Error creating flow: %s") % response)

        # Add reverse flow from dhcp port
        rduuid = uuid.uuid4()
        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, rduuid)
        xml = odl_xml_snippets.PORT_DHCP_FLOW_XML % (switch_id,
                                                     egress_id,
                                                     rduuid,
                                                     priority,
                                                     ingress_id)
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, rduuid, ingress_id, label)
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _create_port_add_flows(self, context, data,
                               container=DEFAULT_CONTAINER):
        LOG.debug(_("Creating port flows on controller"))
        port_id = data['port_id']
        # Get port info
        try:
            port = self.get_port(context, port_id)
        except Exception:
            return True

        # Get segmentation id
        segmentation_id = self.segmentation_manager.get_segmentation_id(
            context.session, port['network_id'])
        switch_id = '00:00:' + data['switch_id']
        port_name = data['vif_id'].split(',')[2].split('=')[1]
        of_port_id = data['vif_id'].split(',')[3].split('=')[1]

        # Store port data
        odl_db.add_ovs_port(context.session, port_id, of_port_id, port_name)

        # Get bridge port id
        #bport = self._get_phy_br_port_id(context, switch_id, container)

        # Add drop flow first
        """
        self._add_port_drop_flow(context, switch_id, port_id, of_port_id,
                                    DEFAULT_PRIORITY + 1, container)
        """

        # Add host and set vlan
        node_ip = port['fixed_ips'][0]['ip_address']
        self._add_static_host(context, port['mac_address'], switch_id,
                              of_port_id, node_ip, segmentation_id,
                              container)

        # Add setVlan flow now
        """
        self._port_outbound_setvlan_flow(context, switch_id, port_id,
                                            of_port_id, segmentation_id,
                                            DEFAULT_PRIORITY + 2, container)
        """

        # Add inbound flow
        """
        self._port_inbound_strip_vlan_flow(context, switch_id, port_id,
                                            of_port_id, segmentation_id,
                                            DEFAULT_PRIORITY + 2, container)
        """

        # Add port gateway flow
        # Get subnets for this network
        subnets = self.get_subnets(
            context, filters={'network_id': [port['network_id']]})
        for subnet in subnets:
            self._add_port_gateway_flow(context, switch_id, port_id,
                                        of_port_id, subnet['gateway_ip'],
                                        DEFAULT_PRIORITY + 2, container)

        # Add flow to dhcp port
        """
        if (port['device_owner'] != 'network:dhcp'):
            # Add a high priority path to the dhcp/bootp port
            # Get dhcp port for this network
            filters = {'device_owner': ['network:dhcp'],
                        'network_id': [port['network_id']]}
            ports = self.get_ports(
                        context,
                        filters=filters)
            for dport in ports:
                # Get of id for this port
                of_dport_id = odl_db.get_ovs_port(context.session,
                                                    dport['id']).of_port_id
                self._add_port_port_dual_flow(context, switch_id, of_port_id,
                                                of_dport_id,
                                                DEFAULT_PRIORITY + 3,
                                                container, 'dhcp')
        """

    def _delete_port_del_flow(self, context, data,
                              container=DEFAULT_CONTAINER):
        LOG.debug(_("Deleting port flows on controller"))
        port_id = data['port_id']
        switch_id = '00:00:' + data['switch_id']
        flows = odl_db.get_port_flows(context.session, port_id)

        for flow in flows:
            self._delete_flow(context, switch_id, flow['flow_id'])

    def _delete_flow(self, context, switch_id, flow_name,
                     container=DEFAULT_CONTAINER):
        LOG.debug(_("Deleting port flow on controller"))
        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, flow_name)
        headers = {"Accept": "application/json"}

        (status, response) = self._rest_call('DELETE', uri, headers,
                                             json.dumps({}))
        if status == 200:
            odl_db.del_port_flow(context.session, flow_name)
        else:
            LOG.error(_("Error deleting flow on controller: %s") % response)

    def _create_subnet(self, context, subnet, container=DEFAULT_CONTAINER):
        LOG.debug(_("Creating subnet gateway on controller"))
        name = False
        if subnet['name']:
            name = subnet['name']
        else:
            name = subnet['id']

        if subnet['gateway_ip']:
            uri = SUBNET_CREATE_PATH % (container, name)
            mask = subnet['cidr'].split('/')[1]
            headers = {"Accept": "application/json"}
            uri = uri + '?' + 'subnet=' + str(
                subnet['gateway_ip'] + '/' + mask)

            self._rest_call('POST', uri, headers, json.dumps({}))

    def _delete_subnet(self, context, id, container=DEFAULT_CONTAINER):
        LOG.debug(_("Deleting subnet gateway on controller"))
        uri = SUBNET_CREATE_PATH % (container, id)
        headers = {"Accept": "application/json"}
        self._rest_call('DELETE', uri, headers, json.dumps({}))

    def create_network(self, context, network):
        LOG.debug(_("Creating network"))
        # Assign segment id
        session = context.session
        with session.begin(subtransactions=True):
            net = super(ODLQuantumPlugin, self).create_network(context,
                                                               network)
            self.segmentation_manager.allocate_network_segment(
                session, net['id'])
            return net

    def delete_network(self, context, id):
        LOG.debug(_("Deleting network"))
        # Delete segment id
        session = context.session
        with session.begin(subtransactions=True):
            # Check subnets associated with network
            network = self.get_network(context, id)
            # Delete all subnets
            for subnet in network['subnets']:
                self.delete_subnet(context, subnet)
            super(ODLQuantumPlugin, self).delete_network(context, id)
            #self.segmentation_manager.delete_segment_binding(session, id)

    def create_port(self, context, port):
        LOG.debug(_("Creating port"))
        port['port']['status'] = q_const.PORT_STATUS_DOWN
        port = super(ODLQuantumPlugin, self).create_port(context, port)
        return port

    def create_subnet(self, context, subnet):
        LOG.debug(_("Creating subnet"))
        subnet = super(ODLQuantumPlugin, self).create_subnet(context, subnet)
        self._create_subnet(context, subnet)
        return subnet

    def delete_subnet(self, context, id):
        LOG.debug(_("Deleting subnet"))
        subnet = self.get_subnet(context, id)
        super(ODLQuantumPlugin, self).delete_subnet(context, id)
        # Delete gateway with this subnet id in the controller
        if (subnet['name']):
            self._delete_subnet(context, subnet['name'])
        else:
            self._delete_subnet(context, id)
