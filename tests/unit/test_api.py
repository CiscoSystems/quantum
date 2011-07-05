# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 ????
# All Rights Reserved.
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
#    @author: Brad Hall, Nicira Networks
#    @author: Salvatore Orlando, Citrix Systems

import logging
import unittest


import tests.unit.testlib as testlib

from quantum import api as server
from quantum.db import api as db
from quantum.common.wsgi import Serializer


#    Fault names copied here for reference
#
#    _fault_names = {
#            400: "malformedRequest",
#            401: "unauthorized",
#            420: "networkNotFound",
#            421: "networkInUse",
#            430: "portNotFound",
#            431: "requestedStateInvalid",
#            432: "portInUse",
#            440: "alreadyAttached",
#            470: "serviceUnavailable",
#            471: "pluginFault"}


LOG = logging.getLogger('quantum.tests.test_api')


class APITest(unittest.TestCase):

    def _create_network(self, format):
        LOG.debug("Creating network")
        content_type = "application/" + format
        network_req = testlib.new_network_request(self.tenant_id,
                                                  self.network_name,
                                                  format)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 200)
        network_data = Serializer().deserialize(network_res.body,
                                                content_type)
        return network_data['networks']['network']['id']

    def _create_port(self, network_id, port_state, format):
        LOG.debug("Creating port for network %s", network_id)
        content_type = "application/%s" % format
        port_req = testlib.new_port_request(self.tenant_id, network_id,
                                            port_state, format)
        port_res = port_req.get_response(self.api)
        self.assertEqual(port_res.status_int, 200)
        port_data = Serializer().deserialize(port_res.body, content_type)
        return port_data['ports']['port']['id']

    def _test_create_network(self, format):
        LOG.debug("_test_create_network - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = Serializer().deserialize(show_network_res.body,
                                                content_type)
        self.assertEqual(network_id,
                         network_data['networks']['network']['id'])
        LOG.debug("_test_create_network - format:%s - END", format)

    def _test_show_network(self, format):
        LOG.debug("_test_show_network - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = Serializer().deserialize(show_network_res.body,
                                                content_type)
        self.assertEqual({'id': network_id, 'name': self.network_name},
                         network_data['networks']['network'])
        LOG.debug("_test_show_network - format:%s - END", format)

    def _test_delete_network(self, format):
        LOG.debug("_test_delete_network - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        LOG.debug("Deleting network %(network_id)s"\
                  " of tenant %(tenant_id)s", locals())
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            format)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 202)
        list_network_req = testlib.network_list_request(self.tenant_id, format)
        list_network_res = list_network_req.get_response(self.api)
        network_list_data = Serializer().deserialize(list_network_res.body,
                                                     content_type)
        network_count = len(network_list_data['networks'])
        self.assertEqual(network_count, 0)
        LOG.debug("_test_delete_network - format:%s - END", format)

    def _test_delete_network_in_use(self, format):
        LOG.debug("_test_delete_network_in_use - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        attachment_id = "test_attachment"
        network_id = self._create_network(format)
        LOG.debug("Deleting network %(network_id)s"\
                  " of tenant %(tenant_id)s", locals())
        port_id = self._create_port(network_id, port_state, format)
        #plug an attachment into the port
        LOG.debug("Putting attachment into port %s", port_id)
        attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                        network_id,
                                                        port_id,
                                                        attachment_id)
        attachment_res = attachment_req.get_response(self.api)
        self.assertEquals(attachment_res.status_int, 202)

        LOG.debug("Deleting network %(network_id)s"\
                  " of tenant %(tenant_id)s", locals())
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            format)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 421)
        LOG.debug("_test_delete_network_in_use - format:%s - END", format)

    def _test_create_port(self, format):
        LOG.debug("_test_create_port - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        show_port_req = testlib.show_port_request(self.tenant_id, network_id,
                                                  port_id, format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = Serializer().deserialize(show_port_res.body, content_type)
        self.assertEqual(port_id, port_data['ports']['port']['id'])
        LOG.debug("_test_create_port - format:%s - END", format)

    def _test_delete_port(self, format):
        LOG.debug("_test_delete_port - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        LOG.debug("Deleting port %(port_id)s for network %(network_id)s"\
                  " of tenant %(tenant_id)s", locals())
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, port_id,
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 202)
        list_port_req = testlib.port_list_request(self.tenant_id, network_id,
                                                  format)
        list_port_res = list_port_req.get_response(self.api)
        port_list_data = Serializer().deserialize(list_port_res.body,
                                                  content_type)
        port_count = len(port_list_data['ports'])
        self.assertEqual(port_count, 0)
        LOG.debug("_test_delete_port - format:%s - END", format)

    def _test_delete_port_in_use(self, format):
        LOG.debug("_test_delete_port_in_use - format:%s - START", format)
        content_type = "application/" + format
        port_state = "ACTIVE"
        attachment_id = "test_attachment"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        #plug an attachment into the port
        LOG.debug("Putting attachment into port %s", port_id)
        attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                        network_id,
                                                        port_id,
                                                        attachment_id)
        attachment_res = attachment_req.get_response(self.api)
        self.assertEquals(attachment_res.status_int, 202)
        LOG.debug("Deleting port %(port_id)s for network %(network_id)s"\
                  " of tenant %(tenant_id)s", locals())
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, port_id,
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 432)
        LOG.debug("_test_delete_port_in_use - format:%s - END", format)
        pass

    def _test_delete_port_with_bad_id(self, format):
        LOG.debug("_test_delete_port_with_bad_id - format:%s - START", format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        # Test for portnotfound
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, "A_BAD_ID",
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 430)
        LOG.debug("_test_delete_port_with_bad_id - format:%s - END", format)

    def setUp(self):
        self.db_file = ':memory:'
        options = {}
        options['plugin_provider'] = 'quantum.plugins.SamplePlugin.FakePlugin'
        options['sql_connection'] = 'sqlite:///%s' % self.db_file
        self.api = server.APIRouterV01(options)
        self.tenant_id = "test_tenant"
        self.network_name = "test_network"

    def tearDown(self):
        """Clear the test environment"""
        # Remove database contents
        db.clear_db()

    def test_create_network_json(self):
        self._test_create_network('json')

    #def test_create_network_xml(self):
    #    self._test_create_network('xml')

    def test_show_network_json(self):
        self._test_show_network('json')

    def test_show_network_xml(self):
        self._test_show_network('xml')

    def test_delete_network_json(self):
        self._test_delete_network('json')

    def test_delete_network_xml(self):
        self._test_delete_network('xml')

    def test_delete_network_in_use_json(self):
        self._test_delete_network_in_use('json')

    def test_delete_network_in_use_xml(self):
        self._test_delete_network_in_use('xml')

    def test_create_port_json(self):
        self._test_create_port('json')

    def test_create_port_xml(self):
        self._test_create_port('xml')

    def test_delete_port_xml(self):
        self._test_delete_port('xml')

    def test_delete_port_json(self):
        self._test_delete_port('json')

    def test_delete_port_in_use_xml(self):
        self._test_delete_port_in_use('xml')

    def test_delete_port_in_use_json(self):
        self._test_delete_port_in_use('json')

    def test_delete_port_with_bad_id_xml(self):
        self._test_delete_port_with_bad_id('xml')

    def test_delete_port_with_bad_id_json(self):
        self._test_delete_port_with_bad_id('json')
