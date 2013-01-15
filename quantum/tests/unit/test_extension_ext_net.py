# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack, LLC.
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

import itertools

import mock
from webob import exc
import webtest

from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import db_base_plugin_v2
from quantum.db import ext_net_db
from quantum.db import models_v2
from quantum.extensions import ext_net
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class ExtNetTestExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# This plugin class is just for testing
class TestExtNetPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                       ext_net_db.Ext_net_db_mixin):
    supported_extension_aliases = ["externalnet"]

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestExtNetPlugin, self).create_network(context,
                                                               network)
            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_l3(context, net)
        return net

    def update_network(self, context, id, network):

        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestExtNetPlugin, self).update_network(context, id,
                                                               network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_l3(context, net)
        return net

    def delete_network(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(TestExtNetPlugin, self).delete_network(context, id)

    def get_network(self, context, id, fields=None):
        net = super(TestExtNetPlugin, self).get_network(context, id, None)
        self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(TestExtNetPlugin, self).get_networks(context, filters,
                                                          None)
        for net in nets:
            self._extend_network_dict_l3(context, net)
        nets = self._filter_nets_l3(context, nets, filters)

        return [self._fields(net, fields) for net in nets]


class ExtNetDBTestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    def _create_network(self, fmt, name, admin_status_up, **kwargs):
        """ Override the routine for allowing the router:external attribute """
        # attributes containing a colon should be passed with
        # a double underscore
        new_args = dict(itertools.izip(map(lambda x: x.replace('__', ':'),
                                           kwargs),
                                       kwargs.values()))
        arg_list = (ext_net.EXTERNAL,)
        return super(ExtNetDBTestCase, self)._create_network(fmt,
                                                             name,
                                                             admin_status_up,
                                                             arg_list=arg_list,
                                                             **new_args)

    def setUp(self):
        test_config['plugin_name_v2'] = (
            'quantum.tests.unit.test_extension_ext_net.TestExtNetPlugin')
        ext_mgr = ExtNetTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        super(ExtNetDBTestCase, self).setUp()

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {ext_net.EXTERNAL: True}})

    def test_list_nets_external(self):
        with self.network() as n1:
            self._set_net_external(n1['network']['id'])
            with self.network() as n2:
                body = self._list('networks')
                self.assertEqual(len(body['networks']), 2)

                body = self._list('networks',
                                  query_params="%s=True" % ext_net.EXTERNAL)
                self.assertEqual(len(body['networks']), 1)

                body = self._list('networks',
                                  query_params="%s=False" % ext_net.EXTERNAL)
                self.assertEqual(len(body['networks']), 1)

    def test_get_network_succeeds_without_filter(self):
        plugin = manager.QuantumManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        result = plugin.get_networks(ctx, filters=None)
        self.assertEqual(result, [])

    def test_network_filter_hook_admin_context(self):
        plugin = manager.QuantumManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        model = models_v2.Network
        conditions = plugin._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions, [])

    def test_network_filter_hook_nonadmin_context(self):
        plugin = manager.QuantumManager.get_plugin()
        ctx = context.Context('edinson', 'cavani')
        model = models_v2.Network
        txt = "externalnetworks.network_id IS NOT NULL"
        conditions = plugin._network_filter_hook(ctx, model, [])
        self.assertEqual(conditions.__str__(), txt)
        # Try to concatenate conditions
        conditions = plugin._network_filter_hook(ctx, model, conditions)
        self.assertEqual(conditions.__str__(), "%s OR %s" % (txt, txt))

    def test_create_port_external_network_non_admin_fails(self):
        with self.network(externalnet__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                with self.assertRaises(exc.HTTPClientError) as ctx_manager:
                    with self.port(subnet=ext_subnet,
                                   set_context='True',
                                   tenant_id='noadmin'):
                        pass
                    self.assertEqual(ctx_manager.exception.code, 403)

    def test_create_port_external_network_admin_suceeds(self):
        with self.network(externalnet__external=True) as ext_net:
            with self.subnet(network=ext_net) as ext_subnet:
                    with self.port(subnet=ext_subnet) as port:
                        self.assertEqual(port['port']['network_id'],
                                         ext_net['network']['id'])

    def test_create_external_network_non_admin_fails(self):
        with self.assertRaises(exc.HTTPClientError) as ctx_manager:
            with self.network(externalnet__external=True,
                              set_context='True',
                              tenant_id='noadmin'):
                pass
            print ctx_manager
            self.assertEqual(ctx_manager.exception.code, 403)

    def test_create_external_network_admin_suceeds(self):
        with self.network(externalnet__external=True) as external_net:
            self.assertEqual(external_net['network'][ext_net.EXTERNAL],
                             True)


class ExtNetDBTestCaseXML(ExtNetDBTestCase):
    fmt = 'xml'
