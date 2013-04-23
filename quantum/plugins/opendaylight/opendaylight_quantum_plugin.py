import httplib
import json

from oslo.config import cfg

from quantum.db.db_base_plugin_v2 import QuantumDbPluginV2
from quantum.db.securitygroups_db import SecurityGroupDbMixin

DEFAULT_CONTAINER = 'default'
SWITCH_LIST_PATH = '/switch/%s/nodes/'
HOST_LIST_PATH = '/host/%s/'
FLOW_LIST_PATH = '/flow/%s/'
SUBNET_LIST_PATH = '/subnet/%s'

class ODLQuantumPlugin(QuantumDbPluginV2, SecurityGroupDbMixin):

    _supported_extension_aliases = ["provider", "router",
                                    "binding", "quotas", "security-group"]

    def __init__(self):
        self.controllers = []
        controllers = cfg.CONF.OPENDAYLIGHT.controllers.split(',')
        self.controllers.extend(controllers)
        self.conn = False

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
        pass

    def get_network(self, context, id, fields=None):
        pass

    def update_network(self, context, id, network):
        pass

    def delete_network(self, context, id):
        pass

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

