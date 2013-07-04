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
# @author: Bob Melander, Cisco Systems, Inc.

import mock
from oslo.config import cfg
import webtest

from quantum.api.v2 import attributes
from quantum import context
from quantum.common.test_lib import test_config
from quantum.extensions import l3
from quantum.manager import QuantumManager
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common.notifier import api as notifier_api
from quantum.openstack.common.notifier import test_notifier
from quantum.openstack.common import uuidutils
from quantum.plugins.cisco.l3.db import composite_agentschedulers_db as agt_sch_db
from quantum.plugins.cisco.l3.db import l3_router_appliance_db
from quantum.tests.unit import test_extension_extraroute
from quantum.tests.unit import test_l3_plugin

LOG = logging.getLogger(__name__)


# This plugin class is just for testing
class TestL3RouterAppliancePlugin(
    test_extension_extraroute.TestExtraRoutePlugin,
    l3_router_appliance_db.L3_router_appliance_db_mixin,
    agt_sch_db.CompositeAgentSchedulerDbMixin,):

    def __init__(self):
        self.hosting_scheduler = importutils.import_object(
            cfg.CONF.hosting_scheduler_driver)
        super(TestL3RouterAppliancePlugin, self).__init__()

    @classmethod
    def resetPlugin(cls):
        cls._mgmt_nw_uuid = None
        cls._l3_tenant_uuid = None
        cls._svc_vm_mgr = None
        cls.hosting_scheduler = None


# Functions to mock service VM creation.
def dispatch_service_vm(self, vm_image, vm_flavor, mgmt_port, ports):
    vm_id=uuidutils.generate_uuid()

    if mgmt_port is not None:
        p_dict = {'port': {'device_id': vm_id,
                           'device_owner': 'nova'}}
        self._core_plugin.update_port(self._context, mgmt_port['id'],
                                      p_dict)

    for port in ports:
        p_dict = {'port': {'device_id': vm_id,
                           'device_owner': 'nova'}}
        self._core_plugin.update_port(self._context, port['id'], p_dict)

    myserver = {'server': {'adminPass': "MVk5HPrazHcG",
                'id': vm_id,
                'links': [{'href': "http://openstack.example.com/v2/"
                                   "openstack/servers/" + vm_id,
                           'rel': "self"},
                          {'href': "http://openstack.example.com/"
                                   "openstack/servers/" + vm_id,
                           'rel': "bookmark"}]}}

    return myserver['server']


def delete_service_vm(self, id, mgmt_nw_id, delete_networks=False):
    ports = self._core_plugin.get_ports(self._context,
                                        filters={'device_id': [id]})

    nets_to_delete = []
    for port in ports:
        if delete_networks and port['network_id'] != mgmt_nw_id:
            nets_to_delete.append(port['network_id'])
        self._core_plugin.delete_port(self._context, port['id'])
    for net_id in nets_to_delete:
        self._core_plugin.delete_network(self._context, net_id)
    return True


class L3RouterApplianceTestCase(test_extension_extraroute.ExtraRouteDBTestCase):

    def setUp(self):
        test_config['plugin_name_v2'] = (
            'quantum.plugins.cisco.l3.tests.unit.'
            'test_l3_router_appliance_plugin.TestL3RouterAppliancePlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = test_extension_extraroute.ExtraRouteTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        #L3NatDBTestCase will overwrite plugin_name_v2,
        #so we don't need to setUp on the class here
        super(test_l3_plugin.L3NatTestCaseBase, self).setUp()

        # Set to None to reload the drivers
        notifier_api._drivers = None
        cfg.CONF.set_override("notification_driver", [test_notifier.__name__])

        cfg.CONF.set_override('allow_sorting', True)

        # Mock l3 admin tenant
        self.tenant_id_fcn_p = mock.patch('quantum.plugins.cisco.l3.db.'
                                          'l3_router_appliance_db.'
                                          'L3_router_appliance_db_mixin.'
                                          'l3_tenant_id')
        self.tenant_id_fcn = self.tenant_id_fcn_p.start()
        self.tenant_id_fcn.return_value = "L3AdminTenantId"

        # A management network/subnet is needed
        self.mgmt_nw = self._make_network(
            self.fmt, cfg.CONF.management_network, True,
            tenant_id="L3AdminTenantId", shared=False)
        self.mgmt_subnet = self._make_subnet(self.fmt, self.mgmt_nw,
                                             "10.0.100.1", "10.0.100.0/24",
                                             ip_version=4)

    def tearDown(self):
        plugin = QuantumManager.get_plugin()
        plugin.delete_all_service_vm_hosting_entities(
            context.get_admin_context())
        self._delete('subnets', self.mgmt_subnet['subnet']['id'])
        self._delete('networks', self.mgmt_nw['network']['id'])
        plugin.resetPlugin()
        self.tenant_id_fcn_p.stop()
        super(test_l3_plugin.L3NatDBTestCase, self).tearDown()

    def test_get_network_succeeds_without_filter(self):
        plugin = QuantumManager.get_plugin()
        ctx = context.Context(None, None, is_admin=True)
        result = plugin.get_networks(ctx, filters=None)
        # Remove mgmt network from list
        to_del = -1
        for i in xrange(0, len(result)):
            if result[i].get('id') == plugin.mgmt_nw_id():
                to_del = i
        if to_del != -1:
            del result[to_del]
        self.assertEqual(result, [])

    def test_list_nets_external(self):
        with self.network() as n1:
            self._set_net_external(n1['network']['id'])
            with self.network():
                body = self._list('networks')
                # 3 networks since there is also the mgmt network
                self.assertEqual(len(body['networks']), 3)

                body = self._list('networks',
                                  query_params="%s=True" % l3.EXTERNAL)
                self.assertEqual(len(body['networks']), 1)

                body = self._list('networks',
                                  query_params="%s=False" % l3.EXTERNAL)
                # 2 networks since there is also the mgmt network
                self.assertEqual(len(body['networks']), 2)


class L3RouterApplianceTestCaseXML(L3RouterApplianceTestCase):
    fmt = 'xml'

    def setUp(self):
        super(L3RouterApplianceTestCaseXML, self).setUp()
        # TODO(bob-melander): Temporary fix to make unit tests pass.
        # The proper way is modify the get_extended_resources() method
        # in extraroute.py so that it extends the attributes.PLURALS
        # dict, i.e., add this line attr.PLURALS.update({'routes': 'route'})
        # Should be reported as a bug and solution upstreamed.
        attributes.PLURALS.update({'routes': 'route'})

    def tearDown(self):
        super(L3RouterApplianceTestCaseXML, self).tearDown()
