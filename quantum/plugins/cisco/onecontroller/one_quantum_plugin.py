import json

from quantum.openstack.common import log as logging

from quantum.plugins.opendaylight.odl_quantum_plugin import ODLQuantumPlugin
from quantum.plugins.cisco.onecontroller import one_xml_snippets


LOG = logging.getLogger(__name__)


DEFAULT_CONTAINER = 'default'
SLICE_CREATE_PATH = '/controller/nb/v2/slices/%s'
SLICE_PORT_PATH = '/controller/nb/v2/slices/%s/nodeconnector'

class OneQuantumPlugin(ODLQuantumPlugin):
    def __init__(self):
        super(OneQuantumPlugin, self).__init__()

    def _get_segmentation_id(self, args):
        return self.segmentation_manager.get_segmentation_id(None, args)

    def _create_port_add_flows(self, context, data,
                                container=DEFAULT_CONTAINER):
        segmentation_id = self.segmentation_manager.get_segmentation_id(
            context.session, port['network_id'])
        switch_id = '00:00:' + data['switch_id']
        port_name = data['vif_id'].split(',')[2].split('=')[1]
        of_port_id = data['vif_id'].split(',')[3].split('=')[1]
        container = port['network_id'].replace('-','')
        super(OneQuantumPlugin, self).\
            _create_port_add_flows(context, data, container)
        # Add port to slice
        self._add_slice_port(context, of_port_id, switch_id, container)

    def _create_network_slice(self, context, network):
        LOG.debug(_("Creating a network slice"))
        net_id = network['id']
        # Remove hyphens from net_id
        net_id = net_id.replace('-','')
        uri = SLICE_CREATE_PATH % net_id
        # Grab segmentation id
        segmentation_id = self.segmentation_manager.get_segmentation_id(
            context.session, network['id'])
        xml = one_xml_snippets.SLICE_CREATE_XML % (net_id, segmentation_id)
        headers = {"Content-type": "application/xml"}

        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            LOG.info(_("Created network slice on controller"))
        else:
            LOG.error(_("Error creating network slice: %s" % response))

    def _delete_network_slice(self, context, network):
        LOG.debug(_("Deleting network slice"))
        network = network.replace('-','')
        uri = SLICE_CREATE_PATH % network
        (status, response) = self._rest_call('DELETE', uri, {}, json.dumps({}))
        if status == 200:
            LOG.info(_("Deleted network slice on controller"))
        else:
            LOG.error(_("Error deleting network slice: %s" % response))

    def _add_slice_port(self, context, of_port, switch_id,
                        container=DEFAULT_CONTAINER):
        LOG.debug(_("\n\n\n\n\nAdding port to slice\n\n\n\n\n"))
        uri = SLICE_PORT_PATH % container
        xml = one_xml_snippets.ADD_SLICE_PORT_XML % \
                (container, switch_id, of_port)
        headers = {"Content-type": "application/xml"}
        LOG.debug("\n\n\n\n%s\n\n\n" % xml)
        (status, response) = self._rest_call('PUT', uri, headers, xml)
        LOG.debug("\n\n\n\n\n%s\n\n\n\n" % response)

    def create_network(self, context, network):
        LOG.debug(_("Creating network"))
        # Assign segment id
        session = context.session
        with session.begin(subtransactions=True):
            net = super(OneQuantumPlugin, self).create_network(context,
                                                               network)
            # Create a slice on the controller
            self._create_network_slice(context, net)
            return net

    def delete_network(self, context, id):
        LOG.debug(_("Deleting network"))
        super(ODLQuantumPlugin, self).delete_network(context, id)
        self._delete_network_slice(context, id)
