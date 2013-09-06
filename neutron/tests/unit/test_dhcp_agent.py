# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

import copy
import os
import sys
import uuid

import eventlet
import mock
from oslo.config import cfg
import testtools

from neutron.agent.common import config
from neutron.agent import dhcp_agent
from neutron.agent.dhcp_agent import DhcpAgentWithStateReport
from neutron.agent.linux import dhcp
from neutron.agent.linux import interface
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.tests import base


ROOTDIR = os.path.dirname(os.path.dirname(__file__))
ETCDIR = os.path.join(ROOTDIR, 'etc')
HOSTNAME = 'hostname'
dev_man = dhcp.DeviceManager
rpc_api = dhcp_agent.DhcpPluginApi
DEVICE_MANAGER = '%s.%s' % (dev_man.__module__, dev_man.__name__)
DHCP_PLUGIN = '%s.%s' % (rpc_api.__module__, rpc_api.__name__)


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


fake_tenant_id = 'aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'
fake_subnet1_allocation_pools = dhcp.DictModel(dict(id='', start='172.9.9.2',
                                               end='172.9.9.254'))
fake_subnet1 = dhcp.DictModel(dict(id='bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='172.9.9.0/24', enable_dhcp=True, name='',
                              tenant_id=fake_tenant_id,
                              gateway_ip='172.9.9.1', host_routes=[],
                              dns_nameservers=[], ip_version=4,
                              allocation_pools=fake_subnet1_allocation_pools))

fake_subnet2_allocation_pools = dhcp.DictModel(dict(id='', start='172.9.8.2',
                                               end='172.9.8.254'))
fake_subnet2 = dhcp.DictModel(dict(id='dddddddd-dddd-dddd-dddddddddddd',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='172.9.8.0/24', enable_dhcp=False, name='',
                              tenant_id=fake_tenant_id, gateway_ip='172.9.8.1',
                              host_routes=[], dns_nameservers=[], ip_version=4,
                              allocation_pools=fake_subnet2_allocation_pools))

fake_subnet3 = dhcp.DictModel(dict(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                              network_id='12345678-1234-5678-1234567890ab',
                              cidr='192.168.1.1/24', enable_dhcp=True))

fake_meta_subnet = dhcp.DictModel(dict(id='bbbbbbbb-1111-2222-bbbbbbbbbbbb',
                                  network_id='12345678-1234-5678-1234567890ab',
                                  cidr='169.254.169.252/30',
                                  gateway_ip='169.254.169.253',
                                  enable_dhcp=True))

fake_fixed_ip1 = dhcp.DictModel(dict(id='', subnet_id=fake_subnet1.id,
                                ip_address='172.9.9.9'))
fake_meta_fixed_ip = dhcp.DictModel(dict(id='', subnet=fake_meta_subnet,
                                    ip_address='169.254.169.254'))
fake_allocation_pool_subnet1 = dhcp.DictModel(dict(id='', start='172.9.9.2',
                                              end='172.9.9.254'))

fake_port1 = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                            device_id='dhcp-12345678-1234-aaaa-1234567890ab',
                            allocation_pools=fake_subnet1_allocation_pools,
                            mac_address='aa:bb:cc:dd:ee:ff',
                            network_id='12345678-1234-5678-1234567890ab',
                            fixed_ips=[fake_fixed_ip1]))

fake_port2 = dhcp.DictModel(dict(id='12345678-1234-aaaa-123456789000',
                            mac_address='aa:bb:cc:dd:ee:99',
                            network_id='12345678-1234-5678-1234567890ab',
                            fixed_ips=[]))

fake_meta_port = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                                mac_address='aa:bb:cc:dd:ee:ff',
                                network_id='12345678-1234-5678-1234567890ab',
                                device_owner=const.DEVICE_OWNER_ROUTER_INTF,
                                device_id='forzanapoli',
                                fixed_ips=[fake_meta_fixed_ip]))

fake_network = dhcp.NetModel(True, dict(id='12345678-1234-5678-1234567890ab',
                             tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                             admin_state_up=True,
                             subnets=[fake_subnet1, fake_subnet2],
                             ports=[fake_port1]))

fake_meta_network = dhcp.NetModel(True,
                                  dict(id='12345678-1234-5678-1234567890ab',
                                  tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                  admin_state_up=True,
                                  subnets=[fake_meta_subnet],
                                  ports=[fake_meta_port]))

fake_down_network = dhcp.NetModel(True,
                                  dict(id='12345678-dddd-dddd-1234567890ab',
                                  tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                  admin_state_up=False,
                                  subnets=[],
                                  ports=[]))


class TestDhcpAgent(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpAgent, self).setUp()
        dhcp_agent.register_options()
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        self.driver_cls_p = mock.patch(
            'neutron.agent.dhcp_agent.importutils.import_class')
        self.driver = mock.Mock(name='driver')
        self.driver.existing_dhcp_networks.return_value = []
        self.driver_cls = self.driver_cls_p.start()
        self.driver_cls.return_value = self.driver
        self.mock_makedirs_p = mock.patch("os.makedirs")
        self.mock_makedirs = self.mock_makedirs_p.start()

    def tearDown(self):
        self.driver_cls_p.stop()
        self.mock_makedirs_p.stop()
        cfg.CONF.reset()
        super(TestDhcpAgent, self).tearDown()

    def test_dhcp_agent_manager(self):
        state_rpc_str = 'neutron.agent.rpc.PluginReportStateAPI'
        with mock.patch.object(DhcpAgentWithStateReport,
                               'sync_state',
                               autospec=True) as mock_sync_state:
            with mock.patch.object(DhcpAgentWithStateReport,
                                   'periodic_resync',
                                   autospec=True) as mock_periodic_resync:
                with mock.patch(state_rpc_str) as state_rpc:
                    with mock.patch.object(sys, 'argv') as sys_argv:
                        sys_argv.return_value = [
                            'dhcp', '--config-file',
                            etcdir('neutron.conf.test')]
                        cfg.CONF.register_opts(dhcp_agent.DhcpAgent.OPTS)
                        config.register_agent_state_opts_helper(cfg.CONF)
                        config.register_root_helper(cfg.CONF)
                        cfg.CONF.register_opts(dhcp.OPTS)
                        cfg.CONF.register_opts(interface.OPTS)
                        cfg.CONF(project='neutron')
                        agent_mgr = DhcpAgentWithStateReport('testhost')
                        eventlet.greenthread.sleep(1)
                        agent_mgr.after_start()
                        mock_sync_state.assert_called_once_with(agent_mgr)
                        mock_periodic_resync.assert_called_once_with(agent_mgr)
                        state_rpc.assert_has_calls(
                            [mock.call(mock.ANY),
                             mock.call().report_state(mock.ANY, mock.ANY,
                                                      mock.ANY)])

    def test_dhcp_agent_main_agent_manager(self):
        logging_str = 'neutron.agent.common.config.setup_logging'
        launcher_str = 'neutron.openstack.common.service.ServiceLauncher'
        with mock.patch(logging_str):
            with mock.patch.object(sys, 'argv') as sys_argv:
                with mock.patch(launcher_str) as launcher:
                    sys_argv.return_value = ['dhcp', '--config-file',
                                             etcdir('neutron.conf.test')]
                    dhcp_agent.main()
                    launcher.assert_has_calls(
                        [mock.call(), mock.call().launch_service(mock.ANY),
                         mock.call().wait()])

    def test_run_completes_single_pass(self):
        with mock.patch(DEVICE_MANAGER):
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            attrs_to_mock = dict(
                [(a, mock.DEFAULT) for a in
                 ['sync_state', 'periodic_resync']])
            with mock.patch.multiple(dhcp, **attrs_to_mock) as mocks:
                dhcp.run()
                mocks['sync_state'].assert_called_once_with()
                mocks['periodic_resync'].assert_called_once_with()

    def test_call_driver(self):
        network = mock.Mock()
        network.id = '1'
        dhcp = dhcp_agent.DhcpAgent(cfg.CONF)
        self.assertTrue(dhcp.call_driver('foo', network))
        self.driver.assert_called_once_with(cfg.CONF,
                                            mock.ANY,
                                            'sudo',
                                            mock.ANY,
                                            mock.ANY)

    def test_call_driver_failure(self):
        network = mock.Mock()
        network.id = '1'
        self.driver.return_value.foo.side_effect = Exception
        with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            self.assertIsNone(dhcp.call_driver('foo', network))
            self.driver.assert_called_once_with(cfg.CONF,
                                                mock.ANY,
                                                'sudo',
                                                mock.ANY,
                                                mock.ANY)
            self.assertEqual(log.call_count, 1)
            self.assertTrue(dhcp.needs_resync)

    def _test_sync_state_helper(self, known_networks, active_networks):
        with mock.patch(DHCP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            mock_plugin.get_active_networks_info.return_value = active_networks
            plug.return_value = mock_plugin

            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

            attrs_to_mock = dict(
                [(a, mock.DEFAULT) for a in
                 ['refresh_dhcp_helper', 'disable_dhcp_helper', 'cache']])

            with mock.patch.multiple(dhcp, **attrs_to_mock) as mocks:
                mocks['cache'].get_network_ids.return_value = known_networks
                dhcp.sync_state()

                exp_refresh = [
                    mock.call(net_id) for net_id in active_networks]

                diff = set(known_networks) - set(active_networks)
                exp_disable = [mock.call(net_id) for net_id in diff]

                mocks['cache'].assert_has_calls([mock.call.get_network_ids()])
                mocks['refresh_dhcp_helper'].assert_has_called(exp_refresh)
                mocks['disable_dhcp_helper'].assert_has_called(exp_disable)

    def test_sync_state_initial(self):
        self._test_sync_state_helper([], ['a'])

    def test_sync_state_same(self):
        self._test_sync_state_helper(['a'], ['a'])

    def test_sync_state_disabled_net(self):
        self._test_sync_state_helper(['b'], ['a'])

    def test_sync_state_plugin_error(self):
        with mock.patch(DHCP_PLUGIN) as plug:
            mock_plugin = mock.Mock()
            mock_plugin.get_active_networks_info.side_effect = Exception
            plug.return_value = mock_plugin

            with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
                dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
                dhcp.sync_state()

                self.assertTrue(log.called)
                self.assertTrue(dhcp.needs_resync)

    def test_periodic_resync(self):
        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        with mock.patch.object(dhcp_agent.eventlet, 'spawn') as spawn:
            dhcp.periodic_resync()
            spawn.assert_called_once_with(dhcp._periodic_resync_helper)

    def test_periodoc_resync_helper(self):
        with mock.patch.object(dhcp_agent.eventlet, 'sleep') as sleep:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
            dhcp.needs_resync = True
            with mock.patch.object(dhcp, 'sync_state') as sync_state:
                sync_state.side_effect = RuntimeError
                with testtools.ExpectedException(RuntimeError):
                    dhcp._periodic_resync_helper()
                sync_state.assert_called_once_with()
                sleep.assert_called_once_with(dhcp.conf.resync_interval)
                self.assertFalse(dhcp.needs_resync)

    def test_populate_cache_on_start_without_active_networks_support(self):
        # emul dhcp driver that doesn't support retrieving of active networks
        self.driver.existing_dhcp_networks.side_effect = NotImplementedError

        with mock.patch.object(dhcp_agent.LOG, 'debug') as log:
            dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

            self.driver.existing_dhcp_networks.assert_called_once_with(
                dhcp.conf,
                cfg.CONF.root_helper
            )

            self.assertFalse(dhcp.cache.get_network_ids())
            self.assertTrue(log.called)

    def test_populate_cache_on_start(self):
        networks = ['aaa', 'bbb']
        self.driver.existing_dhcp_networks.return_value = networks

        dhcp = dhcp_agent.DhcpAgent(HOSTNAME)

        self.driver.existing_dhcp_networks.assert_called_once_with(
            dhcp.conf,
            cfg.CONF.root_helper
        )

        self.assertEqual(set(networks), set(dhcp.cache.get_network_ids()))


class TestLogArgs(base.BaseTestCase):

    def test_log_args_without_log_dir_and_file(self):
        conf_dict = {'debug': True,
                     'verbose': False,
                     'log_dir': None,
                     'log_file': None,
                     'use_syslog': True,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--use-syslog',
                         '--syslog-log-facility=LOG_USER']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_without_log_file(self):
        conf_dict = {'debug': True,
                     'verbose': True,
                     'log_dir': '/etc/tests',
                     'log_file': None,
                     'use_syslog': False,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--verbose',
                         '--log-file=log_file_name',
                         '--log-dir=/etc/tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_with_log_dir_and_file(self):
        conf_dict = {'debug': True,
                     'verbose': False,
                     'log_dir': '/etc/tests',
                     'log_file': 'tests/filelog',
                     'use_syslog': False,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--log-file=log_file_name',
                         '--log-dir=/etc/tests/tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_without_log_dir(self):
        conf_dict = {'debug': True,
                     'verbose': False,
                     'log_file': 'tests/filelog',
                     'log_dir': None,
                     'use_syslog': False,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--log-file=log_file_name',
                         '--log-dir=tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)

    def test_log_args_with_filelog_and_syslog(self):
        conf_dict = {'debug': True,
                     'verbose': True,
                     'log_file': 'tests/filelog',
                     'log_dir': '/etc/tests',
                     'use_syslog': True,
                     'syslog_log_facility': 'LOG_USER'}
        conf = dhcp.DictModel(conf_dict)
        expected_args = ['--debug',
                         '--verbose',
                         '--log-file=log_file_name',
                         '--log-dir=/etc/tests/tests']
        args = config.get_log_args(conf, 'log_file_name')
        self.assertEqual(expected_args, args)


class TestDhcpAgentEventHandler(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpAgentEventHandler, self).setUp()
        cfg.CONF.register_opts(dhcp.OPTS)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        config.register_root_helper(cfg.CONF)
        cfg.CONF.register_opts(dhcp_agent.DhcpAgent.OPTS)

        self.plugin_p = mock.patch(DHCP_PLUGIN)
        plugin_cls = self.plugin_p.start()
        self.plugin = mock.Mock()
        plugin_cls.return_value = self.plugin

        self.cache_p = mock.patch('neutron.agent.dhcp_agent.NetworkCache')
        cache_cls = self.cache_p.start()
        self.cache = mock.Mock()
        cache_cls.return_value = self.cache
        self.mock_makedirs_p = mock.patch("os.makedirs")
        self.mock_makedirs = self.mock_makedirs_p.start()
        self.mock_init_p = mock.patch('neutron.agent.dhcp_agent.'
                                      'DhcpAgent._populate_networks_cache')
        self.mock_init = self.mock_init_p.start()

        with mock.patch.object(dhcp.Dnsmasq,
                               'check_version') as check_v:
            check_v.return_value = dhcp.Dnsmasq.MINIMUM_VERSION
            self.dhcp = dhcp_agent.DhcpAgent(HOSTNAME)
        self.call_driver_p = mock.patch.object(self.dhcp, 'call_driver')

        self.call_driver = self.call_driver_p.start()
        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager'
        )
        self.external_process = self.external_process_p.start()

    def tearDown(self):
        self.external_process_p.stop()
        self.call_driver_p.stop()
        self.cache_p.stop()
        self.plugin_p.stop()
        self.mock_makedirs_p.stop()
        self.mock_init_p.stop()
        cfg.CONF.reset()
        super(TestDhcpAgentEventHandler, self).tearDown()

    def _enable_dhcp_helper(self, isolated_metadata=False):
        if isolated_metadata:
            cfg.CONF.set_override('enable_isolated_metadata', True)
        self.plugin.get_network_info.return_value = fake_network
        self.dhcp.enable_dhcp_helper(fake_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_network.id)])
        self.call_driver.assert_called_once_with('enable', fake_network)
        self.cache.assert_has_calls([mock.call.put(fake_network)])
        if isolated_metadata:
            self.external_process.assert_has_calls([
                mock.call(
                    cfg.CONF,
                    '12345678-1234-5678-1234567890ab',
                    'sudo',
                    'qdhcp-12345678-1234-5678-1234567890ab'),
                mock.call().enable(mock.ANY)
            ])
        else:
            self.assertFalse(self.external_process.call_count)

    def test_enable_dhcp_helper_enable_isolated_metadata(self):
        self._enable_dhcp_helper(isolated_metadata=True)

    def test_enable_dhcp_helper(self):
        self._enable_dhcp_helper()

    def test_enable_dhcp_helper_down_network(self):
        self.plugin.get_network_info.return_value = fake_down_network
        self.dhcp.enable_dhcp_helper(fake_down_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_down_network.id)])
        self.assertFalse(self.call_driver.called)
        self.assertFalse(self.cache.called)
        self.assertFalse(self.external_process.called)

    def test_enable_dhcp_helper_exception_during_rpc(self):
        self.plugin.get_network_info.side_effect = Exception
        with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
            self.dhcp.enable_dhcp_helper(fake_network.id)
            self.plugin.assert_has_calls(
                [mock.call.get_network_info(fake_network.id)])
            self.assertFalse(self.call_driver.called)
            self.assertTrue(log.called)
            self.assertTrue(self.dhcp.needs_resync)
            self.assertFalse(self.cache.called)
            self.assertFalse(self.external_process.called)

    def test_enable_dhcp_helper_driver_failure(self):
        self.plugin.get_network_info.return_value = fake_network
        self.call_driver.return_value = False
        self.dhcp.enable_dhcp_helper(fake_network.id)
        self.plugin.assert_has_calls(
            [mock.call.get_network_info(fake_network.id)])
        self.call_driver.assert_called_once_with('enable', fake_network)
        self.assertFalse(self.cache.called)
        self.assertFalse(self.external_process.called)

    def _disable_dhcp_helper_known_network(self, isolated_metadata=False):
        if isolated_metadata:
            cfg.CONF.set_override('enable_isolated_metadata', True)
        self.cache.get_network_by_id.return_value = fake_network
        self.dhcp.disable_dhcp_helper(fake_network.id)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        self.call_driver.assert_called_once_with('disable', fake_network)
        if isolated_metadata:
            self.external_process.assert_has_calls([
                mock.call(
                    cfg.CONF,
                    '12345678-1234-5678-1234567890ab',
                    'sudo',
                    'qdhcp-12345678-1234-5678-1234567890ab'),
                mock.call().disable()
            ])
        else:
            self.assertFalse(self.external_process.call_count)

    def test_disable_dhcp_helper_known_network_isolated_metadata(self):
        self._disable_dhcp_helper_known_network(isolated_metadata=True)

    def test_disable_dhcp_helper_known_network(self):
        self._disable_dhcp_helper_known_network()

    def test_disable_dhcp_helper_unknown_network(self):
        self.cache.get_network_by_id.return_value = None
        self.dhcp.disable_dhcp_helper('abcdef')
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id('abcdef')])
        self.assertEqual(0, self.call_driver.call_count)
        self.assertFalse(self.external_process.called)

    def _disable_dhcp_helper_driver_failure(self, isolated_metadata=False):
        if isolated_metadata:
            cfg.CONF.set_override('enable_isolated_metadata', True)
        self.cache.get_network_by_id.return_value = fake_network
        self.call_driver.return_value = False
        self.dhcp.disable_dhcp_helper(fake_network.id)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        self.call_driver.assert_called_once_with('disable', fake_network)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_network.id)])
        if isolated_metadata:
            self.external_process.assert_has_calls([
                mock.call(
                    cfg.CONF,
                    '12345678-1234-5678-1234567890ab',
                    'sudo',
                    'qdhcp-12345678-1234-5678-1234567890ab'),
                mock.call().disable()
            ])
        else:
            self.assertFalse(self.external_process.call_count)

    def test_disable_dhcp_helper_driver_failure_isolated_metadata(self):
        self._disable_dhcp_helper_driver_failure(isolated_metadata=True)

    def test_disable_dhcp_helper_driver_failure(self):
        self._disable_dhcp_helper_driver_failure()

    def test_enable_isolated_metadata_proxy(self):
        class_path = 'neutron.agent.linux.external_process.ProcessManager'
        with mock.patch(class_path) as ext_process:
            self.dhcp.enable_isolated_metadata_proxy(fake_network)
            ext_process.assert_has_calls([
                mock.call(
                    cfg.CONF,
                    '12345678-1234-5678-1234567890ab',
                    'sudo',
                    'qdhcp-12345678-1234-5678-1234567890ab'),
                mock.call().enable(mock.ANY)
            ])

    def test_disable_isolated_metadata_proxy(self):
        class_path = 'neutron.agent.linux.external_process.ProcessManager'
        with mock.patch(class_path) as ext_process:
            self.dhcp.disable_isolated_metadata_proxy(fake_network)
            ext_process.assert_has_calls([
                mock.call(
                    cfg.CONF,
                    '12345678-1234-5678-1234567890ab',
                    'sudo',
                    'qdhcp-12345678-1234-5678-1234567890ab'),
                mock.call().disable()
            ])

    def test_enable_isolated_metadata_proxy_with_metadata_network(self):
        cfg.CONF.set_override('enable_metadata_network', True)
        cfg.CONF.set_override('debug', True)
        cfg.CONF.set_override('log_file', 'test.log')
        class_path = 'neutron.agent.linux.ip_lib.IPWrapper'
        self.external_process_p.stop()
        # Ensure the mock is restored if this test fail
        try:
            with mock.patch(class_path) as ip_wrapper:
                self.dhcp.enable_isolated_metadata_proxy(fake_meta_network)
                ip_wrapper.assert_has_calls([mock.call(
                    'sudo',
                    'qdhcp-12345678-1234-5678-1234567890ab'),
                    mock.call().netns.execute([
                        'neutron-ns-metadata-proxy',
                        mock.ANY,
                        mock.ANY,
                        '--router_id=forzanapoli',
                        mock.ANY,
                        mock.ANY,
                        '--debug',
                        ('--log-file=neutron-ns-metadata-proxy-%s.log' %
                         fake_meta_network.id)])
                ])
        finally:
            self.external_process_p.start()

    def test_network_create_end(self):
        payload = dict(network=dict(id=fake_network.id))

        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_create_end(None, payload)
            enable.assertCalledOnceWith(fake_network.id)

    def test_network_update_end_admin_state_up(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=True))
        with mock.patch.object(self.dhcp, 'enable_dhcp_helper') as enable:
            self.dhcp.network_update_end(None, payload)
            enable.assertCalledOnceWith(fake_network.id)

    def test_network_update_end_admin_state_down(self):
        payload = dict(network=dict(id=fake_network.id, admin_state_up=False))
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_update_end(None, payload)
            disable.assertCalledOnceWith(fake_network.id)

    def test_network_delete_end(self):
        payload = dict(network_id=fake_network.id)

        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.network_delete_end(None, payload)
            disable.assertCalledOnceWith(fake_network.id)

    def test_refresh_dhcp_helper_no_dhcp_enabled_networks(self):
        network = dhcp.NetModel(True, dict(id='net-id',
                                tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                admin_state_up=True,
                                subnets=[],
                                ports=[]))

        self.cache.get_network_by_id.return_value = network
        self.plugin.get_network_info.return_value = network
        with mock.patch.object(self.dhcp, 'disable_dhcp_helper') as disable:
            self.dhcp.refresh_dhcp_helper(network.id)
            disable.called_once_with_args(network.id)
            self.assertFalse(self.cache.called)
            self.assertFalse(self.call_driver.called)
            self.cache.assert_has_calls(
                [mock.call.get_network_by_id('net-id')])

    def test_refresh_dhcp_helper_exception_during_rpc(self):
        network = dhcp.NetModel(True, dict(id='net-id',
                                tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                admin_state_up=True,
                                subnets=[],
                                ports=[]))

        self.cache.get_network_by_id.return_value = network
        self.plugin.get_network_info.side_effect = Exception
        with mock.patch.object(dhcp_agent.LOG, 'exception') as log:
            self.dhcp.refresh_dhcp_helper(network.id)
            self.assertFalse(self.call_driver.called)
            self.cache.assert_has_calls(
                [mock.call.get_network_by_id('net-id')])
            self.assertTrue(log.called)
            self.assertTrue(self.dhcp.needs_resync)

    def test_subnet_update_end(self):
        payload = dict(subnet=dict(network_id=fake_network.id))
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_update_end(None, payload)

        self.cache.assert_has_calls([mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)

    def test_subnet_update_end_restart(self):
        new_state = dhcp.NetModel(True, dict(id=fake_network.id,
                                  tenant_id=fake_network.tenant_id,
                                  admin_state_up=True,
                                  subnets=[fake_subnet1, fake_subnet3],
                                  ports=[fake_port1]))

        payload = dict(subnet=dict(network_id=fake_network.id))
        self.cache.get_network_by_id.return_value = fake_network
        self.plugin.get_network_info.return_value = new_state

        self.dhcp.subnet_update_end(None, payload)

        self.cache.assert_has_calls([mock.call.put(new_state)])
        self.call_driver.assert_called_once_with('restart',
                                                 new_state)

    def test_subnet_update_end_delete_payload(self):
        prev_state = dhcp.NetModel(True, dict(id=fake_network.id,
                                   tenant_id=fake_network.tenant_id,
                                   admin_state_up=True,
                                   subnets=[fake_subnet1, fake_subnet3],
                                   ports=[fake_port1]))

        payload = dict(subnet_id=fake_subnet1.id)
        self.cache.get_network_by_subnet_id.return_value = prev_state
        self.cache.get_network_by_id.return_value = prev_state
        self.plugin.get_network_info.return_value = fake_network

        self.dhcp.subnet_delete_end(None, payload)

        self.cache.assert_has_calls([
            mock.call.get_network_by_subnet_id(
                'bbbbbbbb-bbbb-bbbb-bbbbbbbbbbbb'),
            mock.call.get_network_by_id('12345678-1234-5678-1234567890ab'),
            mock.call.put(fake_network)])
        self.call_driver.assert_called_once_with('restart',
                                                 fake_network)

    def test_port_update_end(self):
        payload = dict(port=vars(fake_port2))
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2
        self.dhcp.port_update_end(None, payload)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_port2.network_id),
             mock.call.get_port_by_id(fake_port2.id),
             mock.call.put_port(mock.ANY)])
        self.call_driver.assert_called_once_with('reload_allocations',
                                                 fake_network)

    def test_port_update_change_ip_on_port(self):
        payload = dict(port=vars(fake_port1))
        self.cache.get_network_by_id.return_value = fake_network
        updated_fake_port1 = copy.deepcopy(fake_port1)
        updated_fake_port1.fixed_ips[0].ip_address = '172.9.9.99'
        self.cache.get_port_by_id.return_value = updated_fake_port1
        self.dhcp.port_update_end(None, payload)
        self.cache.assert_has_calls(
            [mock.call.get_network_by_id(fake_port1.network_id),
             mock.call.get_port_by_id(fake_port1.id),
             mock.call.put_port(mock.ANY)])
        self.call_driver.assert_has_calls(
            [mock.call.call_driver(
                'release_lease',
                fake_network,
                mac_address=fake_port1.mac_address,
                removed_ips=set([updated_fake_port1.fixed_ips[0].ip_address])),
             mock.call.call_driver('reload_allocations', fake_network)])

    def test_port_delete_end(self):
        payload = dict(port_id=fake_port2.id)
        self.cache.get_network_by_id.return_value = fake_network
        self.cache.get_port_by_id.return_value = fake_port2

        self.dhcp.port_delete_end(None, payload)
        removed_ips = [fixed_ip.ip_address
                       for fixed_ip in fake_port2.fixed_ips]
        self.cache.assert_has_calls(
            [mock.call.get_port_by_id(fake_port2.id),
             mock.call.get_network_by_id(fake_network.id),
             mock.call.remove_port(fake_port2)])
        self.call_driver.assert_has_calls(
            [mock.call.call_driver('release_lease',
                                   fake_network,
                                   mac_address=fake_port2.mac_address,
                                   removed_ips=removed_ips),
             mock.call.call_driver('reload_allocations', fake_network)])

    def test_port_delete_end_unknown_port(self):
        payload = dict(port_id='unknown')
        self.cache.get_port_by_id.return_value = None

        self.dhcp.port_delete_end(None, payload)

        self.cache.assert_has_calls([mock.call.get_port_by_id('unknown')])
        self.assertEqual(self.call_driver.call_count, 0)


class TestDhcpPluginApiProxy(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpPluginApiProxy, self).setUp()
        self.proxy = dhcp_agent.DhcpPluginApi('foo', {}, None)
        self.proxy.host = 'foo'

        self.call_p = mock.patch.object(self.proxy, 'call')
        self.call = self.call_p.start()
        self.make_msg_p = mock.patch.object(self.proxy, 'make_msg')
        self.make_msg = self.make_msg_p.start()

    def tearDown(self):
        self.make_msg_p.stop()
        self.call_p.stop()
        super(TestDhcpPluginApiProxy, self).tearDown()

    def test_get_network_info(self):
        self.call.return_value = dict(a=1)
        retval = self.proxy.get_network_info('netid')
        self.assertEqual(retval.a, 1)
        self.assertTrue(self.call.called)
        self.make_msg.assert_called_once_with('get_network_info',
                                              network_id='netid',
                                              host='foo')

    def test_get_dhcp_port(self):
        self.call.return_value = dict(a=1)
        retval = self.proxy.get_dhcp_port('netid', 'devid')
        self.assertEqual(retval.a, 1)
        self.assertTrue(self.call.called)
        self.make_msg.assert_called_once_with('get_dhcp_port',
                                              network_id='netid',
                                              device_id='devid',
                                              host='foo')

    def test_get_active_networks_info(self):
        self.proxy.get_active_networks_info()
        self.make_msg.assert_called_once_with('get_active_networks_info',
                                              host='foo')

    def test_create_dhcp_port(self):
        port_body = (
            {'port':
                {'name': '', 'admin_state_up': True,
                 'network_id': fake_network.id,
                 'tenant_id': fake_network.tenant_id,
                 'fixed_ips': [{'subnet_id': fake_fixed_ip1.subnet_id}],
                 'device_id': mock.ANY}})

        self.proxy.create_dhcp_port(port_body)
        self.make_msg.assert_called_once_with('create_dhcp_port',
                                              port=port_body,
                                              host='foo')

    def test_update_dhcp_port(self):
        port_body = {'port': {'fixed_ips':
                              [{'subnet_id': fake_fixed_ip1.subnet_id}]}}
        self.proxy.update_dhcp_port(fake_port1.id, port_body)
        self.make_msg.assert_called_once_with('update_dhcp_port',
                                              port_id=fake_port1.id,
                                              port=port_body,
                                              host='foo')

    def test_release_dhcp_port(self):
        self.proxy.release_dhcp_port('netid', 'devid')
        self.assertTrue(self.call.called)
        self.make_msg.assert_called_once_with('release_dhcp_port',
                                              network_id='netid',
                                              device_id='devid',
                                              host='foo')

    def test_release_port_fixed_ip(self):
        self.proxy.release_port_fixed_ip('netid', 'devid', 'subid')
        self.assertTrue(self.call.called)
        self.make_msg.assert_called_once_with('release_port_fixed_ip',
                                              network_id='netid',
                                              subnet_id='subid',
                                              device_id='devid',
                                              host='foo')


class TestNetworkCache(base.BaseTestCase):
    def test_put_network(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        self.assertEqual(nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_put_network_existing(self):
        prev_network_info = mock.Mock()
        nc = dhcp_agent.NetworkCache()
        with mock.patch.object(nc, 'remove') as remove:
            nc.cache[fake_network.id] = prev_network_info

            nc.put(fake_network)
            remove.assert_called_once_with(prev_network_info)
        self.assertEqual(nc.cache,
                         {fake_network.id: fake_network})
        self.assertEqual(nc.subnet_lookup,
                         {fake_subnet1.id: fake_network.id,
                          fake_subnet2.id: fake_network.id})
        self.assertEqual(nc.port_lookup,
                         {fake_port1.id: fake_network.id})

    def test_remove_network(self):
        nc = dhcp_agent.NetworkCache()
        nc.cache = {fake_network.id: fake_network}
        nc.subnet_lookup = {fake_subnet1.id: fake_network.id,
                            fake_subnet2.id: fake_network.id}
        nc.port_lookup = {fake_port1.id: fake_network.id}
        nc.remove(fake_network)

        self.assertEqual(len(nc.cache), 0)
        self.assertEqual(len(nc.subnet_lookup), 0)
        self.assertEqual(len(nc.port_lookup), 0)

    def test_get_network_by_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_id(fake_network.id), fake_network)

    def test_get_network_ids(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_ids(), [fake_network.id])

    def test_get_network_by_subnet_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_subnet_id(fake_subnet1.id),
                         fake_network)

    def test_get_network_by_port_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)

        self.assertEqual(nc.get_network_by_port_id(fake_port1.id),
                         fake_network)

    def test_put_port(self):
        fake_net = dhcp.NetModel(True,
                                 dict(id='12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1]))
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_net)
        nc.put_port(fake_port2)
        self.assertEqual(len(nc.port_lookup), 2)
        self.assertIn(fake_port2, fake_net.ports)

    def test_put_port_existing(self):
        fake_net = dhcp.NetModel(True,
                                 dict(id='12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1, fake_port2]))
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_net)
        nc.put_port(fake_port2)

        self.assertEqual(len(nc.port_lookup), 2)
        self.assertIn(fake_port2, fake_net.ports)

    def test_remove_port_existing(self):
        fake_net = dhcp.NetModel(True,
                                 dict(id='12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=[fake_subnet1],
                                 ports=[fake_port1, fake_port2]))
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_net)
        nc.remove_port(fake_port2)

        self.assertEqual(len(nc.port_lookup), 1)
        self.assertNotIn(fake_port2, fake_net.ports)

    def test_get_port_by_id(self):
        nc = dhcp_agent.NetworkCache()
        nc.put(fake_network)
        self.assertEqual(nc.get_port_by_id(fake_port1.id), fake_port1)


class FakePort1:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'


class FakeV4Subnet:
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True


class FakeV4SubnetNoGateway:
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = None
    enable_dhcp = True


class FakeV4Network:
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1()]


class FakeV4NetworkNoSubnet:
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = []
    ports = []


class FakeV4NetworkNoGateway:
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoGateway()]
    ports = [FakePort1()]


class TestDeviceManager(base.BaseTestCase):
    def setUp(self):
        super(TestDeviceManager, self).setUp()
        cfg.CONF.register_opts(dhcp_agent.DhcpAgent.OPTS)
        cfg.CONF.register_opts(dhcp.OPTS)
        cfg.CONF.set_override('interface_driver',
                              'neutron.agent.linux.interface.NullDriver')
        config.register_root_helper(cfg.CONF)
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_isolated_metadata', True)

        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.dvr_cls_p = mock.patch('neutron.agent.linux.interface.NullDriver')
        self.iproute_cls_p = mock.patch('neutron.agent.linux.'
                                        'ip_lib.IpRouteCommand')
        driver_cls = self.dvr_cls_p.start()
        iproute_cls = self.iproute_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        self.mock_iproute = mock.MagicMock()
        driver_cls.return_value = self.mock_driver
        iproute_cls.return_value = self.mock_iproute

    def tearDown(self):
        self.dvr_cls_p.stop()
        self.device_exists_p.stop()
        self.iproute_cls_p.stop()
        cfg.CONF.reset()
        super(TestDeviceManager, self).tearDown()

    def _test_setup_helper(self, device_exists, reuse_existing=False,
                           net=None, port=None):
        net = net or fake_network
        port = port or fake_port1
        plugin = mock.Mock()
        plugin.create_dhcp_port.return_value = port or fake_port1
        plugin.get_dhcp_port.return_value = port or fake_port1
        self.device_exists.return_value = device_exists
        self.mock_driver.get_device_name.return_value = 'tap12345678-12'

        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, plugin)
        dh._set_default_route = mock.Mock()
        interface_name = dh.setup(net, reuse_existing)

        self.assertEqual(interface_name, 'tap12345678-12')

        plugin.assert_has_calls([
            mock.call.create_dhcp_port(
                {'port': {'name': '', 'admin_state_up': True,
                          'network_id': net.id, 'tenant_id': net.tenant_id,
                          'fixed_ips':
                          [{'subnet_id': fake_fixed_ip1.subnet_id}],
                          'device_id': mock.ANY}})])

        expected_ips = ['172.9.9.9/24', '169.254.169.254/16']
        expected = [
            mock.call.get_device_name(port),
            mock.call.init_l3(
                'tap12345678-12',
                expected_ips,
                namespace=net.namespace)]

        if not reuse_existing:
            expected.insert(1,
                            mock.call.plug(net.id,
                                           port.id,
                                           'tap12345678-12',
                                           'aa:bb:cc:dd:ee:ff',
                                           namespace=net.namespace))
        self.mock_driver.assert_has_calls(expected)

        dh._set_default_route.assert_called_once_with(net)

    def test_setup(self):
        cfg.CONF.set_override('enable_metadata_network', False)
        self._test_setup_helper(False)
        cfg.CONF.set_override('enable_metadata_network', True)
        self._test_setup_helper(False)

    def test_setup_device_exists(self):
        with testtools.ExpectedException(exceptions.PreexistingDeviceFailure):
            self._test_setup_helper(True)

    def test_setup_device_exists_reuse(self):
        self._test_setup_helper(True, True)

    def test_create_dhcp_port_create_new(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, plugin)
        plugin.create_dhcp_port.return_value = fake_network.ports[0]
        dh.setup_dhcp_port(fake_network)
        plugin.assert_has_calls([
            mock.call.create_dhcp_port(
                {'port': {'name': '', 'admin_state_up': True,
                          'network_id':
                          fake_network.id, 'tenant_id': fake_network.tenant_id,
                          'fixed_ips':
                          [{'subnet_id': fake_fixed_ip1.subnet_id}],
                          'device_id': mock.ANY}})])

    def test_create_dhcp_port_update_add_subnet(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        fake_network_copy.subnets[1].enable_dhcp = True
        plugin.update_dhcp_port.return_value = fake_network.ports[0]
        dh.setup_dhcp_port(fake_network_copy)
        port_body = {'port': {
                     'fixed_ips': [{'subnet_id': fake_fixed_ip1.subnet_id,
                                    'ip_address': fake_fixed_ip1.ip_address},
                                   {'subnet_id': fake_subnet2.id}]}}

        plugin.assert_has_calls([
            mock.call.update_dhcp_port(fake_network_copy.ports[0].id,
                                       port_body)])

    def test_create_dhcp_port_no_update_or_create(self):
        plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, plugin)
        fake_network_copy = copy.deepcopy(fake_network)
        fake_network_copy.ports[0].device_id = dh.get_device_id(fake_network)
        dh.setup_dhcp_port(fake_network_copy)
        self.assertFalse(plugin.setup_dhcp_port.called)
        self.assertFalse(plugin.update_dhcp_port.called)

    def test_destroy(self):
        fake_net = dhcp.NetModel(True,
                                 dict(id='12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'))

        fake_port = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                                   mac_address='aa:bb:cc:dd:ee:ff'))

        with mock.patch('neutron.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()
            plugin.get_dhcp_port.return_value = fake_port

            dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, plugin)
            dh.destroy(fake_net, 'tap12345678-12')

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.unplug('tap12345678-12',
                                  namespace='qdhcp-' + fake_net.id)])
            plugin.assert_has_calls(
                [mock.call.release_dhcp_port(fake_net.id, mock.ANY)])

    def test_get_interface_name(self):
        fake_net = dhcp.NetModel(True,
                                 dict(id='12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'))

        fake_port = dhcp.DictModel(dict(id='12345678-1234-aaaa-1234567890ab',
                                   mac_address='aa:bb:cc:dd:ee:ff'))

        with mock.patch('neutron.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            plugin = mock.Mock()
            plugin.get_dhcp_port.return_value = fake_port

            dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, plugin)
            dh.get_interface_name(fake_net, fake_port)

            dvr_cls.assert_called_once_with(cfg.CONF)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(fake_port)])

            self.assertEqual(len(plugin.mock_calls), 0)

    def test_get_device_id(self):
        fake_net = dhcp.NetModel(True,
                                 dict(id='12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa'))
        expected = ('dhcp1ae5f96c-c527-5079-82ea-371a01645457-12345678-1234-'
                    '5678-1234567890ab')

        with mock.patch('socket.gethostbyname') as get_host:
            with mock.patch('uuid.uuid5') as uuid5:
                uuid5.return_value = '1ae5f96c-c527-5079-82ea-371a01645457'
                get_host.return_value = 'localhost'

                dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, None)
                uuid5.called_once_with(uuid.NAMESPACE_DNS, 'localhost')
                self.assertEqual(dh.get_device_id(fake_net), expected)

    def _get_device_manager_with_mock_device(self, conf, device):
            dh = dhcp.DeviceManager(conf, cfg.CONF.root_helper, None)
            dh._get_device = mock.Mock(return_value=device)
            return dh

    def test_update(self):
        # Try with namespaces and no metadata network
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_metadata_network', False)
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, None)
        dh._set_default_route = mock.Mock()

        dh.update(True)

        dh._set_default_route.assert_called_once_with(True)

        # No namespaces, shouldn't set default route.
        cfg.CONF.set_override('use_namespaces', False)
        cfg.CONF.set_override('enable_metadata_network', False)
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, None)
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network())

        self.assertFalse(dh._set_default_route.called)

        # Meta data network enabled, don't interfere with its gateway.
        cfg.CONF.set_override('use_namespaces', True)
        cfg.CONF.set_override('enable_metadata_network', True)
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, None)
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network())

        self.assertTrue(dh._set_default_route.called)

        # For completeness
        cfg.CONF.set_override('use_namespaces', False)
        cfg.CONF.set_override('enable_metadata_network', True)
        dh = dhcp.DeviceManager(cfg.CONF, cfg.CONF.root_helper, None)
        dh._set_default_route = mock.Mock()

        dh.update(FakeV4Network())

        self.assertFalse(dh._set_default_route.called)

    def test_set_default_route(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = None

        # Basic one subnet with gateway.
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4Network()

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.0.1')

    def test_set_default_route_no_subnet(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = None

        # Try a namespace but no subnet.
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4NetworkNoSubnet()

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        self.assertFalse(device.route.delete_gateway.called)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_no_subnet_delete_gateway(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = dict(gateway='192.168.0.1')

        # Try a namespace but no subnet where a gateway needs to be deleted.
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4NetworkNoSubnet()

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        device.route.delete_gateway.assert_called_once_with('192.168.0.1')
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_no_gateway(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = dict(gateway='192.168.0.1')

        # Try a subnet with no gateway
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4NetworkNoGateway()

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        device.route.delete_gateway.assert_called_once_with('192.168.0.1')
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_do_nothing(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = dict(gateway='192.168.0.1')

        # Try a subnet where the gateway doesn't change.  Should do nothing.
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4Network()

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        self.assertFalse(device.route.delete_gateway.called)
        self.assertFalse(device.route.add_gateway.called)

    def test_set_default_route_change_gateway(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = dict(gateway='192.168.0.2')

        # Try a subnet with a gateway this is different than the current.
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4Network()

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.0.1')

    def test_set_default_route_two_subnets(self):
        device = mock.Mock()
        device.route.get_gateway.return_value = None

        # Try two subnets.  Should set gateway from the first.
        dh = self._get_device_manager_with_mock_device(cfg.CONF, device)
        network = FakeV4Network()
        subnet2 = FakeV4Subnet()
        subnet2.gateway_ip = '192.168.1.1'
        network.subnets = [subnet2, FakeV4Subnet()]

        dh._set_default_route(network)

        device.route.get_gateway.assert_called_once()
        self.assertFalse(device.route.delete_gateway.called)
        device.route.add_gateway.assert_called_once_with('192.168.1.1')


class TestDictModel(base.BaseTestCase):
    def test_basic_dict(self):
        d = dict(a=1, b=2)

        m = dhcp.DictModel(d)
        self.assertEqual(m.a, 1)
        self.assertEqual(m.b, 2)

    def test_dict_has_sub_dict(self):
        d = dict(a=dict(b=2))
        m = dhcp.DictModel(d)
        self.assertEqual(m.a.b, 2)

    def test_dict_contains_list(self):
        d = dict(a=[1, 2])

        m = dhcp.DictModel(d)
        self.assertEqual(m.a, [1, 2])

    def test_dict_contains_list_of_dicts(self):
        d = dict(a=[dict(b=2), dict(c=3)])

        m = dhcp.DictModel(d)
        self.assertEqual(m.a[0].b, 2)
        self.assertEqual(m.a[1].c, 3)


class TestNetModel(base.BaseTestCase):
    def test_ns_name(self):
        network = dhcp.NetModel(True, {'id': 'foo'})
        self.assertEqual(network.namespace, 'qdhcp-foo')

    def test_ns_name_false_namespace(self):
        network = dhcp.NetModel(False, {'id': 'foo'})
        self.assertIsNone(network.namespace)

    def test_ns_name_none_namespace(self):
        network = dhcp.NetModel(None, {'id': 'foo'})
        self.assertIsNone(network.namespace)
