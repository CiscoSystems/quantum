import base64
import httplib
import json
import urllib

from oslo.config import cfg

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.db import dhcp_rpc_base
from quantum.db import l3_rpc_base
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.db.db_base_plugin_v2 import QuantumDbPluginV2
from quantum.db.securitygroups_db import SecurityGroupDbMixin
from quantum.plugins.opendaylight import config
from quantum.openstack.common import log as logging
from quantum.plugins.opendaylight import odl_db

LOG = logging.getLogger(__name__)


DEFAULT_CONTAINER = 'default'
SWITCH_LIST_PATH = '/controller/nb/v2/switch/%s/nodes/'
HOST_LIST_PATH = '/controller/nb/v2/host/%s/'
FLOW_LIST_PATH = '/controller/nb/v2//flow/%s/'
SUBNET_LIST_PATH = '/controller/nb/v2/subnet/%s'
SUBNET_CREATE_PATH = '/controller/nb/v2/subnet/%s/%s'

class SegmentationManager(object):
    def get_segmentation_id(self, session, network_id):
        segment = odl_db.get_network_binding(session, network_id)
        return segment['segmentation_id']

    def allocate_network_segment(self, session, network_id):
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

    def delete_segment_binding(self, session, network_id):
        odl_db.del_network_binding(None, network_id)

class ODLRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                      l3_rpc_base.L3RpcCallbackMixin,
                      sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC

    RPC_API_VERSION = '1.1'

    def __init__(self, notifier):
        self.notifier = notifier

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    def port_create(self, rpc_context, **kwargs):
        pass

class ODLQuantumPlugin(QuantumDbPluginV2, SecurityGroupDbMixin):

    _supported_extension_aliases = ["provider", "router",
                                    "binding", "quotas", "security-group"]

    def __init__(self):
        odl_db.initialize()
        self.controllers = []
        controllers = cfg.CONF.ODL.controllers.split(',')
        self.controllers.extend(controllers)
        self.conn = False

        self.segmentation_manager = SegmentationManager()

    def _rest_call(self, action, uri, headers, data=None):
        data = json.dumps(data) or json.dumps({})
        (ip,port,username,password) = self.controllers[0].split(':')
        conn = httplib.HTTPConnection(ip, port)
        # Add auth
        auth = 'Basic %s' % base64.encodestring('%s:%s' % (username, password)).strip()
        headers['Authorization'] = auth
        conn.request(action, uri, data, headers)
        response = conn.getresponse()
        respstr = response.read()

    def _create_flow(self, context, ingress, egress):
        pass

    def _get_flows(self, context):
        pass

    def _delete_flow(self, context, name):
        pass

    def _create_gateway(self, context, gateway_ip):
        pass

    def _push_switch_config(self, switch_id, switch_type, config):
        pass

    def _create_subnet(self, context, subnet, container=DEFAULT_CONTAINER):
        name = False
        if subnet['name']:
            name = subnet['name']
        else:
            name = subnet['id']

        if subnet['gateway_ip']:
            uri = SUBNET_CREATE_PATH % (container, name)
            mask = subnet['cidr'].split('/')[1]
            headers = {"Accept": "application/json"}
            uri = uri + '?' +  'subnet=' + str(subnet['gateway_ip'] + '/' + mask)

            self._rest_call('POST', uri, headers, {})

    def _delete_subnet(self, context, id, container=DEFAULT_CONTAINER):
        uri = SUBNET_CREATE_PATH % (container, id)
        headers = {"Accept": "application/json"}
        self._rest_call('DELETE', uri, headers, {})

    def create_network(self, context, network):
        # Assign segment id
        session = context.session
        with session.begin(subtransactions=True):
            net = super(ODLQuantumPlugin, self).create_network(context,
                                                               network)
            self.segmentation_manager.allocate_network_segment(session, net['id'])
            return net

    def delete_network(self, context, id):
        # Delete segment id
        session = context.session
        with session.begin(subtransactions=True):
            # Check subnets associated with network
            network = self.get_network(context, id)
            # Delete all subnets
            for subnet in network['subnets']:
                self.delete_subnet(context, subnet)
            super(ODLQuantumPlugin, self).delete_network(context, id)
            self.segmentation_manager.delete_segment_binding(session, id)

    def create_port(self, context, port_dict):
        port = super(ODLQuantumPlugin, self).create_port(context, port_dict)
        return port

    def update_port(self, context, id, port):
        pass

    def delete_port(self, context, id):
        pass

    def create_subnet(self, context, subnet):
        subnet = super(ODLQuantumPlugin, self).create_subnet(context, subnet)
        self._create_subnet(context, subnet)
        return subnet

    def delete_subnet(self, context, id):
        subnet = self.get_subnet(context, id)
        super(ODLQuantumPlugin, self).delete_subnet(context, id)
        # Delete gateway with this subnet id in the controller
        if (subnet['name']):
            self._delete_subnet(context, subnet['name'])
        else:
            self._delete_subnet(context, id)
        
    def create_security_group_rule(self, context, security_group_rule):
        pass

    def delete_security_group_rule(self, context, id):
        pass
