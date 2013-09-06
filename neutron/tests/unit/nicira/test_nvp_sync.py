# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira Networks, Inc.
# All Rights Reserved
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

import contextlib
import time

import mock
from oslo.config import cfg

from neutron.api.v2 import attributes as attr
from neutron.common import config
from neutron.common import constants
from neutron import context
from neutron.openstack.common import jsonutils as json
from neutron.plugins.nicira.common import sync
from neutron.plugins.nicira import NeutronPlugin
from neutron.plugins.nicira import nvp_cluster
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib
from neutron.tests import base
from neutron.tests.unit.nicira import fake_nvpapiclient
from neutron.tests.unit.nicira import get_fake_conf
from neutron.tests.unit.nicira import NVPAPI_NAME
from neutron.tests.unit.nicira import STUBS_PATH
from neutron.tests.unit import test_api_v2

from neutron.openstack.common import log

LOG = log.getLogger(__name__)

_uuid = test_api_v2._uuid
LSWITCHES = [{'uuid': _uuid(), 'name': 'ls-1'},
             {'uuid': _uuid(), 'name': 'ls-2'}]
LSWITCHPORTS = [{'uuid': _uuid(), 'name': 'lp-1'},
                {'uuid': _uuid(), 'name': 'lp-2'}]
LROUTERS = [{'uuid': _uuid(), 'name': 'lr-1'},
            {'uuid': _uuid(), 'name': 'lr-2'}]


class NvpCacheTestCase(base.BaseTestCase):
    """Test suite providing coverage for the NvpCache class."""

    def setUp(self):
        self.nvp_cache = sync.NvpCache()
        for lswitch in LSWITCHES:
            self.nvp_cache._uuid_dict_mappings[lswitch['uuid']] = (
                self.nvp_cache._lswitches)
            self.nvp_cache._lswitches[lswitch['uuid']] = (
                {'data': lswitch,
                 'hash': hash(json.dumps(lswitch))})
        for lswitchport in LSWITCHPORTS:
            self.nvp_cache._uuid_dict_mappings[lswitchport['uuid']] = (
                self.nvp_cache._lswitchports)
            self.nvp_cache._lswitchports[lswitchport['uuid']] = (
                {'data': lswitchport,
                 'hash': hash(json.dumps(lswitchport))})
        for lrouter in LROUTERS:
            self.nvp_cache._uuid_dict_mappings[lrouter['uuid']] = (
                self.nvp_cache._lrouters)
            self.nvp_cache._lrouters[lrouter['uuid']] = (
                {'data': lrouter,
                 'hash': hash(json.dumps(lrouter))})
        super(NvpCacheTestCase, self).setUp()

    def test_get_lswitches(self):
        ls_uuids = self.nvp_cache.get_lswitches()
        self.assertEqual(set(ls_uuids),
                         set([ls['uuid'] for ls in LSWITCHES]))

    def test_get_lswitchports(self):
        lp_uuids = self.nvp_cache.get_lswitchports()
        self.assertEqual(set(lp_uuids),
                         set([lp['uuid'] for lp in LSWITCHPORTS]))

    def test_get_lrouters(self):
        lr_uuids = self.nvp_cache.get_lrouters()
        self.assertEqual(set(lr_uuids),
                         set([lr['uuid'] for lr in LROUTERS]))

    def test_get_lswitches_changed_only(self):
        ls_uuids = self.nvp_cache.get_lswitches(changed_only=True)
        self.assertEqual(0, len(ls_uuids))

    def test_get_lswitchports_changed_only(self):
        lp_uuids = self.nvp_cache.get_lswitchports(changed_only=True)
        self.assertEqual(0, len(lp_uuids))

    def test_get_lrouters_changed_only(self):
        lr_uuids = self.nvp_cache.get_lrouters(changed_only=True)
        self.assertEqual(0, len(lr_uuids))

    def _verify_update(self, new_resource, changed=True, hit=True):
        cached_resource = self.nvp_cache[new_resource['uuid']]
        self.assertEqual(new_resource, cached_resource['data'])
        self.assertEqual(hit, cached_resource.get('hit', False))
        self.assertEqual(changed,
                         cached_resource.get('changed', False))

    def test_update_lswitch_new_item(self):
        new_switch_uuid = _uuid()
        new_switch = {'uuid': new_switch_uuid, 'name': 'new_switch'}
        self.nvp_cache.update_lswitch(new_switch)
        self.assertIn(new_switch_uuid, self.nvp_cache._lswitches.keys())
        self._verify_update(new_switch)

    def test_update_lswitch_existing_item(self):
        switch = LSWITCHES[0]
        switch['name'] = 'new_name'
        self.nvp_cache.update_lswitch(switch)
        self.assertIn(switch['uuid'], self.nvp_cache._lswitches.keys())
        self._verify_update(switch)

    def test_update_lswitchport_new_item(self):
        new_switchport_uuid = _uuid()
        new_switchport = {'uuid': new_switchport_uuid,
                          'name': 'new_switchport'}
        self.nvp_cache.update_lswitchport(new_switchport)
        self.assertIn(new_switchport_uuid,
                      self.nvp_cache._lswitchports.keys())
        self._verify_update(new_switchport)

    def test_update_lswitchport_existing_item(self):
        switchport = LSWITCHPORTS[0]
        switchport['name'] = 'new_name'
        self.nvp_cache.update_lswitchport(switchport)
        self.assertIn(switchport['uuid'],
                      self.nvp_cache._lswitchports.keys())
        self._verify_update(switchport)

    def test_update_lrouter_new_item(self):
        new_router_uuid = _uuid()
        new_router = {'uuid': new_router_uuid,
                      'name': 'new_router'}
        self.nvp_cache.update_lrouter(new_router)
        self.assertIn(new_router_uuid,
                      self.nvp_cache._lrouters.keys())
        self._verify_update(new_router)

    def test_update_lrouter_existing_item(self):
        router = LROUTERS[0]
        router['name'] = 'new_name'
        self.nvp_cache.update_lrouter(router)
        self.assertIn(router['uuid'],
                      self.nvp_cache._lrouters.keys())
        self._verify_update(router)

    def test_process_updates_initial(self):
        # Clear cache content to simulate first-time filling
        self.nvp_cache._lswitches.clear()
        self.nvp_cache._lswitchports.clear()
        self.nvp_cache._lrouters.clear()
        self.nvp_cache.process_updates(LSWITCHES, LROUTERS, LSWITCHPORTS)
        for resource in LSWITCHES + LROUTERS + LSWITCHPORTS:
            self._verify_update(resource)

    def test_process_updates_no_change(self):
        self.nvp_cache.process_updates(LSWITCHES, LROUTERS, LSWITCHPORTS)
        for resource in LSWITCHES + LROUTERS + LSWITCHPORTS:
            self._verify_update(resource, changed=False)

    def test_process_updates_with_changes(self):
        LSWITCHES[0]['name'] = 'altered'
        self.nvp_cache.process_updates(LSWITCHES, LROUTERS, LSWITCHPORTS)
        for resource in LSWITCHES + LROUTERS + LSWITCHPORTS:
            changed = (True if resource['uuid'] == LSWITCHES[0]['uuid']
                       else False)
            self._verify_update(resource, changed=changed)

    def _test_process_updates_with_removals(self):
        lswitches = LSWITCHES[:]
        lswitch = lswitches.pop()
        self.nvp_cache.process_updates(lswitches, LROUTERS, LSWITCHPORTS)
        for resource in LSWITCHES + LROUTERS + LSWITCHPORTS:
            hit = (False if resource['uuid'] == lswitch['uuid']
                   else True)
            self._verify_update(resource, changed=False, hit=hit)
        return (lswitch, lswitches)

    def test_process_updates_with_removals(self):
        self._test_process_updates_with_removals()

    def test_process_updates_cleanup_after_delete(self):
        deleted_lswitch, lswitches = self._test_process_updates_with_removals()
        self.nvp_cache.process_deletes()
        self.nvp_cache.process_updates(lswitches, LROUTERS, LSWITCHPORTS)
        self.assertNotIn(deleted_lswitch['uuid'], self.nvp_cache._lswitches)

    def _verify_delete(self, resource, deleted=True, hit=True):
        cached_resource = self.nvp_cache[resource['uuid']]
        data_field = 'data_bk' if deleted else 'data'
        self.assertEqual(resource, cached_resource[data_field])
        self.assertEqual(hit, cached_resource.get('hit', False))
        self.assertEqual(deleted,
                         cached_resource.get('changed', False))

    def _set_hit(self, resources, uuid_to_delete=None):
        for resource in resources:
            if resource['data']['uuid'] != uuid_to_delete:
                resource['hit'] = True

    def test_process_deletes_no_change(self):
        # Mark all resources as hit
        self._set_hit(self.nvp_cache._lswitches.values())
        self._set_hit(self.nvp_cache._lswitchports.values())
        self._set_hit(self.nvp_cache._lrouters.values())
        self.nvp_cache.process_deletes()
        for resource in LSWITCHES + LROUTERS + LSWITCHPORTS:
            self._verify_delete(resource, hit=False, deleted=False)

    def test_process_deletes_with_removals(self):
        # Mark all resources but one as hit
        uuid_to_delete = LSWITCHPORTS[0]['uuid']
        self._set_hit(self.nvp_cache._lswitches.values(),
                      uuid_to_delete)
        self._set_hit(self.nvp_cache._lswitchports.values(),
                      uuid_to_delete)
        self._set_hit(self.nvp_cache._lrouters.values(),
                      uuid_to_delete)
        self.nvp_cache.process_deletes()
        for resource in LSWITCHES + LROUTERS + LSWITCHPORTS:
            deleted = resource['uuid'] == uuid_to_delete
            self._verify_delete(resource, hit=False, deleted=deleted)


class SyncLoopingCallTestCase(base.BaseTestCase):

    def test_looping_calls(self):
        # Avoid runs of the synchronization process - just start
        # the looping call
        with mock.patch.object(
            sync.NvpSynchronizer, '_synchronize_state',
            return_value=0.01):
            synchronizer = sync.NvpSynchronizer(None, None,
                                                100, 0, 0)
            time.sleep(0.04999)
            # stop looping call before asserting
            synchronizer._sync_looping_call.stop()
            self.assertEqual(
                5, synchronizer._synchronize_state.call_count)


class NvpSyncTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        # Avoid runs of the synchronizer looping call
        # These unit tests will excplicitly invoke synchronization
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        self.mock_nvpapi = mock_nvpapi.start()
        patch_sync.start()
        self.mock_nvpapi.return_value.login.return_value = "the_cookie"
        # Emulate tests against NVP 3.x
        self.mock_nvpapi.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion("3.1"))

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        self.mock_nvpapi.return_value.request.side_effect = _fake_request
        self.fake_cluster = nvp_cluster.NVPCluster(
            name='fake-cluster', nvp_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nvp_user='foo', nvp_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nvp_user, self.fake_cluster.nvp_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)
        # Instantiate Neutron plugin
        # and setup needed config variables
        args = ['--config-file', get_fake_conf('neutron.conf.test'),
                '--config-file', get_fake_conf('nvp.ini.test')]
        config.parse(args=args)
        self._plugin = NeutronPlugin.NvpPluginV2()
        super(NvpSyncTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(patch_sync.stop)
        self.addCleanup(mock_nvpapi.stop)

    def tearDown(self):
        cfg.CONF.reset()
        super(NvpSyncTestCase, self).tearDown()

    @contextlib.contextmanager
    def _populate_data(self, ctx, net_size=2, port_size=2, router_size=2):

        def network(idx):
            return {'network': {'name': 'net-%s' % idx,
                                'admin_state_up': True,
                                'shared': False,
                                'port_security_enabled': True,
                                'tenant_id': 'foo'}}

        def subnet(idx, net_id):
            return {'subnet':
                    {'cidr': '10.10.%s.0/24' % idx,
                     'name': 'sub-%s' % idx,
                     'gateway_ip': attr.ATTR_NOT_SPECIFIED,
                     'allocation_pools': attr.ATTR_NOT_SPECIFIED,
                     'ip_version': 4,
                     'dns_nameservers': attr.ATTR_NOT_SPECIFIED,
                     'host_routes': attr.ATTR_NOT_SPECIFIED,
                     'enable_dhcp': True,
                     'network_id': net_id,
                     'tenant_id': 'foo'}}

        def port(idx, net_id):
            return {'port': {'network_id': net_id,
                             'name': 'port-%s' % idx,
                             'admin_state_up': True,
                             'device_id': 'miao',
                             'device_owner': 'bau',
                             'fixed_ips': attr.ATTR_NOT_SPECIFIED,
                             'mac_address': attr.ATTR_NOT_SPECIFIED,
                             'tenant_id': 'foo'}}

        def router(idx):
            # Use random uuids as names
            return {'router': {'name': 'rtr-%s' % idx,
                               'admin_state_up': True,
                               'tenant_id': 'foo'}}

        networks = []
        ports = []
        routers = []
        for i in range(0, net_size):
            net = self._plugin.create_network(ctx, network(i))
            networks.append(net)
            self._plugin.create_subnet(ctx, subnet(i, net['id']))
            for j in range(0, port_size):
                ports.append(self._plugin.create_port(
                    ctx, port("%s-%s" % (i, j), net['id'])))
        for i in range(0, router_size):
            routers.append(self._plugin.create_router(ctx, router(i)))
        # Do not return anything as the user does need the actual
        # data created
        try:
            yield
        finally:
            # Remove everything
            for router in routers:
                self._plugin.delete_router(ctx, router['id'])
            for port in ports:
                self._plugin.delete_port(ctx, port['id'])
            # This will remove networks and subnets
            for network in networks:
                self._plugin.delete_network(ctx, network['id'])

    def _get_tag_dict(self, tags):
        return dict((tag['scope'], tag['tag']) for tag in tags)

    def _test_sync(self, exp_net_status,
                   exp_port_status, exp_router_status,
                   action_callback=None, sp=None):
        neutron_net_id = ls_uuid = self.fc._fake_lswitch_dict.keys()[0]
        lp_uuid = self.fc._fake_lswitch_lport_dict.keys()[0]
        neutron_port_id = self._get_tag_dict(
            self.fc._fake_lswitch_lport_dict[lp_uuid]['tags'])['q_port_id']
        neutron_rtr_id = lr_uuid = self.fc._fake_lrouter_dict.keys()[0]
        if action_callback:
            action_callback(ls_uuid, lp_uuid, lr_uuid)
        # Make chunk big enough to read everything
        if not sp:
            sp = sync.SyncParameters(100)
        self._plugin._synchronizer._synchronize_state(sp)
        # Verify element is in expected status
        # TODO(salv-orlando): Verify status for all elements
        ctx = context.get_admin_context()
        neutron_net = self._plugin.get_network(ctx, neutron_net_id)
        neutron_port = self._plugin.get_port(ctx, neutron_port_id)
        neutron_rtr = self._plugin.get_router(ctx, neutron_rtr_id)
        self.assertEqual(exp_net_status, neutron_net['status'])
        self.assertEqual(exp_port_status, neutron_port['status'])
        self.assertEqual(exp_router_status, neutron_rtr['status'])

    def _action_callback_status_down(self, ls_uuid, lp_uuid, lr_uuid):
        self.fc._fake_lswitch_dict[ls_uuid]['status'] = 'false'
        self.fc._fake_lswitch_lport_dict[lp_uuid]['status'] = 'false'
        self.fc._fake_lrouter_dict[lr_uuid]['status'] = 'false'

    def test_initial_sync(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            self._test_sync(
                constants.NET_STATUS_ACTIVE,
                constants.PORT_STATUS_ACTIVE,
                constants.NET_STATUS_ACTIVE)

    def test_initial_sync_with_resources_down(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            self._test_sync(
                constants.NET_STATUS_DOWN, constants.PORT_STATUS_DOWN,
                constants.NET_STATUS_DOWN, self._action_callback_status_down)

    def test_resync_with_resources_down(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            sp = sync.SyncParameters(100)
            self._plugin._synchronizer._synchronize_state(sp)
            self._test_sync(
                constants.NET_STATUS_DOWN, constants.PORT_STATUS_DOWN,
                constants.NET_STATUS_DOWN, self._action_callback_status_down)

    def _action_callback_del_resource(self, ls_uuid, lp_uuid, lr_uuid):
        del self.fc._fake_lswitch_dict[ls_uuid]
        del self.fc._fake_lswitch_lport_dict[lp_uuid]
        del self.fc._fake_lrouter_dict[lr_uuid]

    def test_initial_sync_with_resources_removed(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            self._test_sync(
                constants.NET_STATUS_ERROR, constants.PORT_STATUS_ERROR,
                constants.NET_STATUS_ERROR, self._action_callback_del_resource)

    def test_resync_with_resources_removed(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            sp = sync.SyncParameters(100)
            self._plugin._synchronizer._synchronize_state(sp)
            self._test_sync(
                constants.NET_STATUS_ERROR, constants.PORT_STATUS_ERROR,
                constants.NET_STATUS_ERROR, self._action_callback_del_resource)

    def _test_sync_with_chunk_larger_maxpagesize(
        self, net_size, port_size, router_size, chunk_size, exp_calls):
        ctx = context.get_admin_context()
        real_func = nvplib.get_single_query_page
        sp = sync.SyncParameters(chunk_size)
        with self._populate_data(ctx, net_size=net_size,
                                 port_size=port_size,
                                 router_size=router_size):
            with mock.patch.object(nvplib, 'MAX_PAGE_SIZE', 15):
                # The following mock is just for counting calls,
                # but we will still run the actual function
                with mock.patch.object(
                    nvplib, 'get_single_query_page',
                    side_effect=real_func) as mock_get_page:
                    self._test_sync(
                        constants.NET_STATUS_ACTIVE,
                        constants.PORT_STATUS_ACTIVE,
                        constants.NET_STATUS_ACTIVE,
                        sp=sp)
            # As each resource type does not exceed the maximum page size,
            # the method should be called once for each resource type
            self.assertEqual(exp_calls, mock_get_page.call_count)

    def test_sync_chunk_larger_maxpagesize_no_multiple_requests(self):
        # total resource size = 20
        # total size for each resource does not exceed max page size (15)
        self._test_sync_with_chunk_larger_maxpagesize(
            net_size=5, port_size=2, router_size=5,
            chunk_size=20, exp_calls=3)

    def test_sync_chunk_larger_maxpagesize_triggers_multiple_requests(self):
        # total resource size = 48
        # total size for each resource does exceed max page size (15)
        self._test_sync_with_chunk_larger_maxpagesize(
            net_size=16, port_size=1, router_size=16,
            chunk_size=48, exp_calls=6)

    def test_sync_multi_chunk(self):
        # The fake NVP API client cannot be used for this test
        ctx = context.get_admin_context()
        # Generate 4 networks, 1 port per network, and 4 routers
        with self._populate_data(ctx, net_size=4, port_size=1, router_size=4):
            fake_lswitches = json.loads(
                self.fc.handle_get('/ws.v1/lswitch'))['results']
            fake_lrouters = json.loads(
                self.fc.handle_get('/ws.v1/lrouter'))['results']
            fake_lswitchports = json.loads(
                self.fc.handle_get('/ws.v1/lswitch/*/lport'))['results']
            return_values = [
                # Chunk 0 - lswitches
                (fake_lswitches, None, 4),
                # Chunk 0 - lrouters
                (fake_lrouters[:2], 'xxx', 4),
                # Chunk 0 - lports (size only)
                ([], 'start', 4),
                # Chunk 1 - lrouters (2 more) (lswitches are skipped)
                (fake_lrouters[2:], None, None),
                # Chunk 1 - lports
                (fake_lswitchports, None, 4)]

            def fake_fetch_data(*args, **kwargs):
                return return_values.pop(0)

            # 2 Chunks, with 6 resources each.
            # 1st chunk lswitches and lrouters
            # 2nd chunk lrouters and lports
            # Mock _fetch_data
            with mock.patch.object(
                self._plugin._synchronizer, '_fetch_data',
                side_effect=fake_fetch_data):
                sp = sync.SyncParameters(6)

                def do_chunk(chunk_idx, ls_cursor, lr_cursor, lp_cursor):
                    self._plugin._synchronizer._synchronize_state(sp)
                    self.assertEqual(chunk_idx, sp.current_chunk)
                    self.assertEqual(ls_cursor, sp.ls_cursor)
                    self.assertEqual(lr_cursor, sp.lr_cursor)
                    self.assertEqual(lp_cursor, sp.lp_cursor)

                # check 1st chunk
                do_chunk(1, None, 'xxx', 'start')
                # check 2nd chunk
                do_chunk(0, None, None, None)
                # Chunk size should have stayed the same
                self.assertEqual(sp.chunk_size, 6)

    def test_synchronize_network(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            # Put a network down to verify synchronization
            q_net_id = ls_uuid = self.fc._fake_lswitch_dict.keys()[0]
            self.fc._fake_lswitch_dict[ls_uuid]['status'] = 'false'
            q_net_data = self._plugin._get_network(ctx, q_net_id)
            self._plugin._synchronizer.synchronize_network(ctx, q_net_data)
            # Reload from db
            q_nets = self._plugin.get_networks(ctx)
            for q_net in q_nets:
                if q_net['id'] == q_net_id:
                    exp_status = constants.NET_STATUS_DOWN
                else:
                    exp_status = constants.NET_STATUS_ACTIVE
                self.assertEqual(exp_status, q_net['status'])

    def test_synchronize_port(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            # Put a network down to verify synchronization
            lp_uuid = self.fc._fake_lswitch_lport_dict.keys()[0]
            lport = self.fc._fake_lswitch_lport_dict[lp_uuid]
            q_port_id = self._get_tag_dict(lport['tags'])['q_port_id']
            lport['status'] = 'false'
            q_port_data = self._plugin._get_port(ctx, q_port_id)
            self._plugin._synchronizer.synchronize_port(ctx, q_port_data)
            # Reload from db
            q_ports = self._plugin.get_ports(ctx)
            for q_port in q_ports:
                if q_port['id'] == q_port_id:
                    exp_status = constants.PORT_STATUS_DOWN
                else:
                    exp_status = constants.PORT_STATUS_ACTIVE
                self.assertEqual(exp_status, q_port['status'])

    def test_synchronize_router(self):
        ctx = context.get_admin_context()
        with self._populate_data(ctx):
            # Put a network down to verify synchronization
            q_rtr_id = lr_uuid = self.fc._fake_lrouter_dict.keys()[0]
            self.fc._fake_lrouter_dict[lr_uuid]['status'] = 'false'
            q_rtr_data = self._plugin._get_router(ctx, q_rtr_id)
            self._plugin._synchronizer.synchronize_router(ctx, q_rtr_data)
            # Reload from db
            q_routers = self._plugin.get_routers(ctx)
            for q_rtr in q_routers:
                if q_rtr['id'] == q_rtr_id:
                    exp_status = constants.NET_STATUS_DOWN
                else:
                    exp_status = constants.NET_STATUS_ACTIVE
                self.assertEqual(exp_status, q_rtr['status'])

    def test_sync_nvp_failure_backoff(self):
        self.mock_nvpapi.return_value.request.side_effect = (
            NvpApiClient.RequestTimeout)
        # chunk size won't matter here
        sp = sync.SyncParameters(999)
        for i in range(0, 10):
            self.assertEqual(
                min(64, 2 ** i),
                self._plugin._synchronizer._synchronize_state(sp))
