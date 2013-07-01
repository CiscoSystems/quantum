# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Big Switch Networks, Inc.
# All Rights Reserved.
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

import os

from mock import patch
from oslo.config import cfg
import webob.exc

import quantum.common.test_lib as test_lib
from quantum.extensions import portbindings
from quantum.manager import QuantumManager
from quantum.tests.unit import _test_extension_portbindings as test_bindings
import quantum.tests.unit.test_db_plugin as test_plugin


RESTPROXY_PKG_PATH = 'quantum.plugins.bigswitch.plugin'


class HTTPResponseMock():
    status = 200
    reason = 'OK'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False):
        pass

    def read(self):
        return "{'status': '200 OK'}"


class HTTPConnectionMock():

    def __init__(self, server, port, timeout):
        pass

    def request(self, action, uri, body, headers):
        return

    def getresponse(self):
        return HTTPResponseMock(None)

    def close(self):
        pass


class BigSwitchProxyPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.QuantumRestProxyV2' % RESTPROXY_PKG_PATH)

    def setUp(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                'restproxy.ini.test')]

        self.httpPatch = patch('httplib.HTTPConnection', create=True,
                               new=HTTPConnectionMock)
        self.addCleanup(self.httpPatch.stop)
        self.httpPatch.start()
        super(BigSwitchProxyPluginV2TestCase,
              self).setUp(self._plugin_name)


class TestBigSwitchProxyBasicGet(test_plugin.TestBasicGet,
                                 BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxyV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                       BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxyPortsV2(test_plugin.TestPortsV2,
                                BigSwitchProxyPluginV2TestCase,
                                test_bindings.PortBindingsTestCase):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False


class TestBigSwitchProxyPortsV2IVS(test_plugin.TestPortsV2,
                                   BigSwitchProxyPluginV2TestCase,
                                   test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_IVS
    HAS_PORT_FILTER = False

    def setUp(self):
        super(TestBigSwitchProxyPortsV2IVS,
              self).setUp()
        cfg.CONF.set_override('vif_type', 'ivs', 'NOVA')


class TestNoHostIDVIFOverride(test_plugin.TestPortsV2,
                              BigSwitchProxyPluginV2TestCase,
                              test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False

    def setUp(self):
        super(TestNoHostIDVIFOverride, self).setUp()
        cfg.CONF.set_override('vif_type', 'ovs', 'NOVA')

    def test_port_vif_details(self):
        kwargs = {'name': 'name', 'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_OVS)


class TestBigSwitchVIFOverride(test_plugin.TestPortsV2,
                               BigSwitchProxyPluginV2TestCase,
                               test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False

    def setUp(self):
        super(TestBigSwitchVIFOverride,
              self).setUp()
        cfg.CONF.set_override('vif_type', 'ovs', 'NOVA')

    def test_port_vif_details(self):
        kwargs = {'name': 'name', 'binding:host_id': 'ivshost',
                  'device_id': 'override_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'],
                             portbindings.VIF_TYPE_IVS)
        kwargs = {'name': 'name2', 'binding:host_id': 'someotherhost',
                  'device_id': 'other_dev'}
        with self.port(**kwargs) as port:
            self.assertEqual(port['port']['binding:vif_type'], self.VIF_TYPE)

    def _make_port(self, fmt, net_id, expected_res_status=None, **kwargs):
        res = self._create_port(fmt, net_id, expected_res_status,
                                ('binding:host_id', ), **kwargs)
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)


class TestBigSwitchProxyNetworksV2(test_plugin.TestNetworksV2,
                                   BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxySubnetsV2(test_plugin.TestSubnetsV2,
                                  BigSwitchProxyPluginV2TestCase):

    pass


class TestBigSwitchProxySync(BigSwitchProxyPluginV2TestCase):

    def test_send_data(self):
        plugin_obj = QuantumManager.get_plugin()
        result = plugin_obj._send_all_data()
        self.assertEqual(result[0], 200)
