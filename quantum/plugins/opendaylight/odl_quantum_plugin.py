import httplib
import json

from oslo.config import cfg

from quantum.db.db_base_plugin_v2 import QuantumDbPluginV2
from quantum.db.securitygroups_db import SecurityGroupDbMixin
from quantum.plugins.opendaylight import config
from quantum.openstack.common import log as logging
from quantum.plugins.opendaylight import odl_db

LOG = logging.getLogger(__name__)


DEFAULT_CONTAINER = 'default'
SWITCH_LIST_PATH = '/switch/%s/nodes/'
HOST_LIST_PATH = '/host/%s/'
FLOW_LIST_PATH = '/flow/%s/'
SUBNET_LIST_PATH = '/subnet/%s'


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

    def _rest_call(self, resource, data, headers):
        controller = self.controllers[0]
        if not self.conn:
            try:
                self.conn = httplib.HTTPConnection(controller)
            except:
                raise

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

    def _create_subnet(self, context, cidr, container=DEFAULT_CONTAINER):
        pass

    def _delete_subnet(self, context, id):
        pass

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
            super(ODLQuantumPlugin, self).delete_network(context, id)
            self.segmentation_manager.delete_segment_binding(session, id)

    def create_port(self, context, port):
        pass

    def get_port(self, context, id, fields=None):
        pass

    def update_port(self, context, id, port):
        pass

    def delete_port(self, context, id):
        pass

    def create_subnet(self, context, subnet):
        pass

    def get_subnet(self, context, id, fields=None):
        pass

    def update_subnet(self, context, id ,subnet):
        pass

    def delete_subnet(self, context, id):
        pass

    def create_security_group_rule(self, context, security_group_rule):
        pass

    def delete_security_group_rule(self, context, id):
        pass

