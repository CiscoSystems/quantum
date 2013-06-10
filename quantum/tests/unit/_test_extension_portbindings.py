# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NEC Corporation
# All rights reserved.
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
# @author: Akihiro Motoki, NEC Corporation
#

import contextlib

from oslo.config import cfg
from webob import exc

from quantum import context
from quantum.extensions import portbindings
from quantum.manager import QuantumManager
from quantum.tests.unit import test_db_plugin


class PortBindingsTestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    # VIF_TYPE must be overridden according to plugin vif_type
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    # The plugin supports the port security feature such as
    # security groups and anti spoofing.
    HAS_PORT_FILTER = False

    def _check_response_portbindings(self, port):
        self.assertEqual(port['binding:vif_type'], self.VIF_TYPE)
        port_cap = port[portbindings.CAPABILITIES]
        self.assertEqual(port_cap[portbindings.CAP_PORT_FILTER],
                         self.HAS_PORT_FILTER)

    def _check_response_no_portbindings(self, port):
        self.assertTrue('status' in port)
        self.assertFalse(portbindings.VIF_TYPE in port)
        self.assertFalse(portbindings.CAPABILITIES in port)

    def test_port_vif_details(self):
        with self.port(name='name') as port:
            port_id = port['port']['id']
            # Check a response of create_port
            self._check_response_portbindings(port['port'])
            # Check a response of get_port
            ctx = context.get_admin_context()
            port = self._show('ports', port_id, quantum_context=ctx)['port']
            self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            non_admin_port = self._show(
                'ports', port_id, quantum_context=ctx)['port']
            self._check_response_no_portbindings(non_admin_port)

    def test_ports_vif_details(self):
        plugin = QuantumManager.get_plugin()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(), self.port()):
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for port in ports:
                self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            ports = self._list('ports', quantum_context=ctx)['ports']
            self.assertEqual(len(ports), 2)
            for non_admin_port in ports:
                self._check_response_no_portbindings(non_admin_port)


class PortBindingsHostTestCaseMixin(object):
    fmt = 'json'
    hostname = 'testhost'

    def _check_response_portbindings_host(self, port):
        self.assertEqual(port[portbindings.HOST_ID], self.hostname)

    def _check_response_no_portbindings_host(self, port):
        self.assertIn('status', port)
        self.assertNotIn(portbindings.HOST_ID, port)

    def test_port_vif_non_admin(self):
        with self.network(set_context=True,
                          tenant_id='test') as net1:
            with self.subnet(network=net1) as subnet1:
                host_arg = {portbindings.HOST_ID: self.hostname}
                try:
                    with self.port(subnet=subnet1,
                                   expected_res_status=403,
                                   arg_list=(portbindings.HOST_ID,),
                                   set_context=True,
                                   tenant_id='test',
                                   **host_arg):
                        pass
                except exc.HTTPClientError:
                    pass

    def test_port_vif_host(self):
        host_arg = {portbindings.HOST_ID: self.hostname}
        with self.port(name='name', arg_list=(portbindings.HOST_ID,),
                       **host_arg) as port:
            port_id = port['port']['id']
            # Check a response of create_port
            self._check_response_portbindings_host(port['port'])
            # Check a response of get_port
            ctx = context.get_admin_context()
            port = self._show('ports', port_id, quantum_context=ctx)['port']
            self._check_response_portbindings_host(port)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            non_admin_port = self._show(
                'ports', port_id, quantum_context=ctx)['port']
            self._check_response_no_portbindings_host(non_admin_port)

    def test_ports_vif_host(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with contextlib.nested(
            self.port(name='name1',
                      arg_list=(portbindings.HOST_ID,),
                      **host_arg),
            self.port(name='name2')):
            ctx = context.get_admin_context()
            ports = self._list('ports', quantum_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for port in ports:
                if port['name'] == 'name1':
                    self._check_response_portbindings_host(port)
                else:
                    self.assertFalse(port[portbindings.HOST_ID])
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            ports = self._list('ports', quantum_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for non_admin_port in ports:
                self._check_response_no_portbindings_host(non_admin_port)

    def test_ports_vif_host_update(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with contextlib.nested(
            self.port(name='name1',
                      arg_list=(portbindings.HOST_ID,),
                      **host_arg),
            self.port(name='name2')) as (port1, port2):
            data = {'port': {portbindings.HOST_ID: 'testhosttemp'}}
            req = self.new_update_request('ports', data, port1['port']['id'])
            req.get_response(self.api)
            req = self.new_update_request('ports', data, port2['port']['id'])
            ctx = context.get_admin_context()
            req.get_response(self.api)
            ports = self._list('ports', quantum_context=ctx)['ports']
        self.assertEqual(2, len(ports))
        for port in ports:
            self.assertEqual('testhosttemp', port[portbindings.HOST_ID])

    def test_ports_vif_host_list(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with contextlib.nested(
            self.port(name='name1',
                      arg_list=(portbindings.HOST_ID,),
                      **host_arg),
            self.port(name='name2'),
            self.port(name='name3',
                      arg_list=(portbindings.HOST_ID,),
                      **host_arg),) as (port1, _port2, port3):
            self._test_list_resources(
                'port', (port1, port3),
                query_params='%s=%s' % (portbindings.HOST_ID, self.hostname))
