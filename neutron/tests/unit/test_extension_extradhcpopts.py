# Copyright (c) 2013 OpenStack Foundation.
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
#
# @author: D.E. Kehn, dekehn@gmail.com
#

import copy

from neutron.db import db_base_plugin_v2
from neutron.db import extradhcpopt_db as edo_db
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.openstack.common import log as logging
from neutron.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)

DB_PLUGIN_KLASS = (
    'neutron.tests.unit.test_extension_extradhcpopts.ExtraDhcpOptTestPlugin')


class ExtraDhcpOptTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             edo_db.ExtraDhcpOptMixin):
    """Test plugin that implements necessary calls on create/delete port for
    associating ports with extra dhcp options.
    """

    supported_extension_aliases = ["extra_dhcp_opt"]

    def create_port(self, context, port):
        with context.session.begin(subtransactions=True):
            edos = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            new_port = super(ExtraDhcpOptTestPlugin, self).create_port(
                context, port)
            self._process_port_create_extra_dhcp_opts(context, new_port, edos)
        return new_port

    def update_port(self, context, id, port):
        with context.session.begin(subtransactions=True):
            rtn_port = super(ExtraDhcpOptTestPlugin, self).update_port(
                context, id, port)
            self._update_extra_dhcp_opts_on_port(context, id, port, rtn_port)
        return rtn_port


class ExtraDhcpOptDBTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None):
        super(ExtraDhcpOptDBTestCase, self).setUp(plugin=DB_PLUGIN_KLASS)


class TestExtraDhcpOpt(ExtraDhcpOptDBTestCase):
    def _check_opts(self, expected, returned):
        self.assertEqual(len(expected), len(returned))
        for opt in returned:
            name = opt['opt_name']
            for exp in expected:
                if name == exp['opt_name']:
                    val = exp['opt_value']
                    break
            self.assertEqual(opt['opt_value'], val)

    def test_create_port_with_extradhcpopts(self):
        opt_dict = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_dict,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_dict,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_with_extradhcpopts_with_same(self):
        opt_dict = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        new_opts = opt_dict[:]
        for i in new_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break

        params = {edo_ext.EXTRADHCPOPTS: opt_dict,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize('json', req.get_response(self.api))
            self._check_opts(new_opts,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_with_extradhcpopts(self):
        opt_dict = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        new_opts = copy.deepcopy(opt_dict)
        for i in new_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break

        params = {edo_ext.EXTRADHCPOPTS: opt_dict,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize('json', req.get_response(self.api))
            self._check_opts(new_opts,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_with_extradhcpopt1(self):
        opt_dict = [{'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        new_opts = copy.deepcopy(opt_dict)
        new_opts.append(upd_opts[0])

        params = {edo_ext.EXTRADHCPOPTS: opt_dict,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize('json', req.get_response(self.api))
            self._check_opts(new_opts,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_adding_extradhcpopts(self):
        opt_dict = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        with self.port() as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: opt_dict}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize('json', req.get_response(self.api))
            self._check_opts(opt_dict,
                             port['port'][edo_ext.EXTRADHCPOPTS])
