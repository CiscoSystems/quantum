# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from quantum.extensions import portbindings
from quantum.tests.unit import _test_extension_portbindings as test_bindings
from quantum.tests.unit import test_db_plugin as test_plugin
from quantum.tests.unit import test_security_groups_rpc as test_sg_rpc


class OpenvswitchPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('quantum.plugins.openvswitch.'
                    'ovs_quantum_plugin.OVSQuantumPluginV2')

    def setUp(self):
        super(OpenvswitchPluginV2TestCase, self).setUp(self._plugin_name)
        self.port_create_status = 'DOWN'


class TestOpenvswitchBasicGet(test_plugin.TestBasicGet,
                              OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                    OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchPortsV2(test_plugin.TestPortsV2,
                             OpenvswitchPluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')


class TestOpenvswitchNetworksV2(test_plugin.TestNetworksV2,
                                OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchPortBinding(OpenvswitchPluginV2TestCase,
                                 test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self, firewall_driver=None):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        super(TestOpenvswitchPortBinding, self).setUp()


class TestOpenvswitchPortBindingNoSG(TestOpenvswitchPortBinding):
    HAS_PORT_FILTER = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestOpenvswitchPortBindingHost(
    OpenvswitchPluginV2TestCase,
    test_bindings.PortBindingsHostTestCaseMixin):
    pass
