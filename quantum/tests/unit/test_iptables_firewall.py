# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

import mock
from mock import call
from oslo.config import cfg

from quantum.agent.common import config as a_cfg
from quantum.agent.linux.iptables_firewall import IptablesFirewallDriver
from quantum.tests import base
from quantum.tests.unit import test_api_v2


_uuid = test_api_v2._uuid
FAKE_PREFIX = {'IPv4': '10.0.0.0/24',
               'IPv6': 'fe80::0/48'}
FAKE_IP = {'IPv4': '10.0.0.1',
           'IPv6': 'fe80::1'}


class IptablesFirewallTestCase(base.BaseTestCase):
    def setUp(self):
        super(IptablesFirewallTestCase, self).setUp()
        cfg.CONF.register_opts(a_cfg.ROOT_HELPER_OPTS, 'AGENT')
        self.utils_exec_p = mock.patch(
            'quantum.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()
        self.addCleanup(self.utils_exec_p.stop)
        self.iptables_cls_p = mock.patch(
            'quantum.agent.linux.iptables_manager.IptablesManager')
        iptables_cls = self.iptables_cls_p.start()
        self.addCleanup(self.iptables_cls_p.stop)
        self.iptables_inst = mock.Mock()
        self.v4filter_inst = mock.Mock()
        self.v6filter_inst = mock.Mock()
        self.iptables_inst.ipv4 = {'filter': self.v4filter_inst}
        self.iptables_inst.ipv6 = {'filter': self.v6filter_inst}
        iptables_cls.return_value = self.iptables_inst

        self.firewall = IptablesFirewallDriver()
        self.firewall.iptables = self.iptables_inst

    def _fake_port(self):
        return {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff',
                'fixed_ips': [FAKE_IP['IPv4'],
                              FAKE_IP['IPv6']]}

    def test_prepare_port_filter_with_no_sg(self):
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [call.add_chain('sg-fallback'),
                 call.add_rule('sg-fallback', '-j DROP'),
                 call.ensure_remove_chain('sg-chain'),
                 call.add_chain('sg-chain'),
                 call.add_chain('ifake_dev'),
                 call.add_rule('FORWARD',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-out tapfake_dev '
                               '-j $sg-chain'),
                 call.add_rule('sg-chain',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-out tapfake_dev '
                               '-j $ifake_dev'),
                 call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ifake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ifake_dev', '-j $sg-fallback'),
                 call.add_chain('ofake_dev'),
                 call.add_rule('FORWARD',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-in tapfake_dev '
                               '-j $sg-chain'),
                 call.add_rule('sg-chain',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-in tapfake_dev '
                               '-j $ofake_dev'),
                 call.add_rule('INPUT',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-in tapfake_dev '
                               '-j $ofake_dev'),
                 call.add_rule(
                     'ofake_dev', '-m mac ! --mac-source ff:ff:ff:ff -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-p udp --sport 68 --dport 67 -j RETURN'),
                 call.add_rule('ofake_dev', '! -s 10.0.0.1 -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-p udp --sport 67 --dport 68 -j DROP'),
                 call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ofake_dev', '-j $sg-fallback'),
                 call.add_rule('sg-chain', '-j ACCEPT')]

        self.v4filter_inst.assert_has_calls(calls)

    def test_filter_ipv4_ingress(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress'}
        ingress = call.add_rule('ifake_dev', '-j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'source_ip_prefix': prefix}
        ingress = call.add_rule('ifake_dev', '-j RETURN -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp'}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p tcp')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p tcp -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_icmp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'icmp'}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p icmp')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        ingress = call.add_rule(
            'ifake_dev', '-j RETURN -p icmp -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p tcp --dport 10')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p tcp -m multiport --dports 10:100')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p tcp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp'}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p udp')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p udp -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p udp --dport 10')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p udp -m multiport --dports 10:100')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p udp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress'}
        egress = call.add_rule('ofake_dev', '-j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'source_ip_prefix': prefix}
        egress = call.add_rule('ofake_dev', '-j RETURN -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp'}
        egress = call.add_rule('ofake_dev', '-j RETURN -p tcp')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        egress = call.add_rule('ofake_dev', '-j RETURN -p tcp -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp'}
        egress = call.add_rule('ofake_dev', '-j RETURN -p icmp')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        egress = call.add_rule(
            'ofake_dev', '-j RETURN -p icmp -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = call.add_rule('ofake_dev', '-j RETURN -p tcp --dport 10')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p tcp -m multiport --dports 10:100')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p tcp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp'}
        egress = call.add_rule('ofake_dev', '-j RETURN -p udp')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        egress = call.add_rule('ofake_dev', '-j RETURN -p udp -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = call.add_rule('ofake_dev', '-j RETURN -p udp --dport 10')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p udp -m multiport --dports 10:100')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p udp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress'}
        ingress = call.add_rule('ifake_dev', '-j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'source_ip_prefix': prefix}
        ingress = call.add_rule('ifake_dev', '-j RETURN -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp'}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p tcp')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p tcp -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p tcp --dport 10')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_icmp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'icmp'}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p icmpv6')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        ingress = call.add_rule(
            'ifake_dev', '-j RETURN -p icmpv6 -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p tcp -m multiport --dports 10:100')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p tcp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp'}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p udp')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p udp -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = call.add_rule('ifake_dev', '-j RETURN -p udp --dport 10')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p udp -m multiport --dports 10:100')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = call.add_rule(
            'ifake_dev',
            '-j RETURN -p udp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress'}
        egress = call.add_rule('ofake_dev', '-j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'source_ip_prefix': prefix}
        egress = call.add_rule('ofake_dev', '-j RETURN -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp'}
        egress = call.add_rule('ofake_dev', '-j RETURN -p tcp')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        egress = call.add_rule('ofake_dev', '-j RETURN -p tcp -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp'}
        egress = call.add_rule('ofake_dev', '-j RETURN -p icmpv6')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        egress = call.add_rule(
            'ofake_dev', '-j RETURN -p icmpv6 -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = call.add_rule('ofake_dev', '-j RETURN -p tcp --dport 10')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p tcp -m multiport --dports 10:100')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p tcp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp'}
        egress = call.add_rule('ofake_dev', '-j RETURN -p udp')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        egress = call.add_rule('ofake_dev', '-j RETURN -p udp -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = call.add_rule('ofake_dev', '-j RETURN -p udp --dport 10')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p udp -m multiport --dports 10:100')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = call.add_rule(
            'ofake_dev',
            '-j RETURN -p udp -m multiport '
            '--dports 10:100 -s %s' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def _test_prepare_port_filter(self,
                                  rule,
                                  ingress_expected_call=None,
                                  egress_expected_call=None):
        port = self._fake_port()
        ethertype = rule['ethertype']
        prefix = FAKE_IP[ethertype]
        filter_inst = self.v4filter_inst
        dhcp_rule = call.add_rule(
            'ofake_dev',
            '-p udp --sport 68 --dport 67 -j RETURN')

        if ethertype == 'IPv6':
            filter_inst = self.v6filter_inst
            dhcp_rule = call.add_rule('ofake_dev', '-p icmpv6 -j RETURN')

        sg = [rule]
        port['security_group_rules'] = sg
        self.firewall.prepare_port_filter(port)
        calls = [call.add_chain('sg-fallback'),
                 call.add_rule('sg-fallback', '-j DROP'),
                 call.ensure_remove_chain('sg-chain'),
                 call.add_chain('sg-chain'),
                 call.add_chain('ifake_dev'),
                 call.add_rule('FORWARD',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-out tapfake_dev '
                               '-j $sg-chain'),
                 call.add_rule('sg-chain',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-out tapfake_dev '
                               '-j $ifake_dev'),
                 call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ifake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN')]

        if ingress_expected_call:
            calls.append(ingress_expected_call)

        calls += [call.add_rule('ifake_dev', '-j $sg-fallback'),
                  call.add_chain('ofake_dev'),
                  call.add_rule('FORWARD',
                                '-m physdev --physdev-is-bridged '
                                '--physdev-in tapfake_dev '
                                '-j $sg-chain'),
                  call.add_rule('sg-chain',
                                '-m physdev --physdev-is-bridged '
                                '--physdev-in tapfake_dev '
                                '-j $ofake_dev'),
                  call.add_rule('INPUT',
                                '-m physdev --physdev-is-bridged '
                                '--physdev-in tapfake_dev '
                                '-j $ofake_dev'),
                  call.add_rule(
                      'ofake_dev',
                      '-m mac ! --mac-source ff:ff:ff:ff -j DROP'),
                  dhcp_rule,
                  call.add_rule('ofake_dev', '! -s %s -j DROP' % prefix)]

        if ethertype == 'IPv4':
            calls.append(call.add_rule(
                'ofake_dev',
                '-p udp --sport 67 --dport 68 -j DROP'))

        calls += [call.add_rule(
                  'ofake_dev', '-m state --state INVALID -j DROP'),
                  call.add_rule(
                  'ofake_dev',
                  '-m state --state ESTABLISHED,RELATED -j RETURN')]

        if egress_expected_call:
            calls.append(egress_expected_call)

        calls += [call.add_rule('ofake_dev', '-j $sg-fallback'),
                  call.add_rule('sg-chain', '-j ACCEPT')]

        filter_inst.assert_has_calls(calls)

    def test_update_delete_port_filter(self):
        port = self._fake_port()
        port['security_group_rules'] = [{'ethertype': 'IPv4',
                                         'direction': 'ingress'}]
        self.firewall.prepare_port_filter(port)
        port['security_group_rules'] = [{'ethertype': 'IPv4',
                                         'direction': 'egress'}]
        self.firewall.update_port_filter(port)
        self.firewall.update_port_filter({'device': 'no-exist-device'})
        self.firewall.remove_port_filter(port)
        self.firewall.remove_port_filter({'device': 'no-exist-device'})
        calls = [call.add_chain('sg-fallback'),
                 call.add_rule('sg-fallback', '-j DROP'),
                 call.ensure_remove_chain('sg-chain'),
                 call.add_chain('sg-chain'),
                 call.add_chain('ifake_dev'),
                 call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-out tapfake_dev -j $sg-chain'),
                 call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-out tapfake_dev -j $ifake_dev'),
                 call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ifake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ifake_dev', '-j RETURN'),
                 call.add_rule('ifake_dev', '-j $sg-fallback'),
                 call.add_chain('ofake_dev'),
                 call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-in tapfake_dev -j $sg-chain'),
                 call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-in tapfake_dev -j $ofake_dev'),
                 call.add_rule(
                     'INPUT',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-in tapfake_dev -j $ofake_dev'),
                 call.add_rule(
                     'ofake_dev',
                     '-m mac ! --mac-source ff:ff:ff:ff -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-p udp --sport 68 --dport 67 -j RETURN'),
                 call.add_rule(
                     'ofake_dev',
                     '! -s 10.0.0.1 -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-p udp --sport 67 --dport 68 -j DROP'),
                 call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ofake_dev', '-j $sg-fallback'),
                 call.add_rule('sg-chain', '-j ACCEPT'),
                 call.ensure_remove_chain('ifake_dev'),
                 call.ensure_remove_chain('ofake_dev'),
                 call.ensure_remove_chain('sfake_dev'),
                 call.ensure_remove_chain('sg-chain'),
                 call.add_chain('sg-chain'),
                 call.add_chain('ifake_dev'),
                 call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-out tapfake_dev -j $sg-chain'),
                 call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-out tapfake_dev -j $ifake_dev'),
                 call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ifake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ifake_dev', '-j $sg-fallback'),
                 call.add_chain('ofake_dev'),
                 call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-in tapfake_dev -j $sg-chain'),
                 call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-in tapfake_dev -j $ofake_dev'),
                 call.add_rule(
                     'INPUT',
                     '-m physdev --physdev-is-bridged '
                     '--physdev-in tapfake_dev -j $ofake_dev'),
                 call.add_rule(
                     'ofake_dev',
                     '-m mac ! --mac-source ff:ff:ff:ff -j DROP'),
                 call.add_rule(
                     'ofake_dev', '-p udp --sport 68 --dport 67 -j RETURN'),
                 call.add_rule(
                     'ofake_dev', '! -s 10.0.0.1 -j DROP'),
                 call.add_rule(
                     'ofake_dev', '-p udp --sport 67 --dport 68 -j DROP'),
                 call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ofake_dev', '-j RETURN'),
                 call.add_rule('ofake_dev', '-j $sg-fallback'),
                 call.add_rule('sg-chain', '-j ACCEPT'),
                 call.ensure_remove_chain('ifake_dev'),
                 call.ensure_remove_chain('ofake_dev'),
                 call.ensure_remove_chain('sfake_dev'),
                 call.ensure_remove_chain('sg-chain'),
                 call.add_chain('sg-chain')]

        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_unknown_port(self):
        port = self._fake_port()
        self.firewall.remove_port_filter(port)
        # checking no exception occures
        self.v4filter_inst.assert_has_calls([])

    def test_defer_apply(self):
        with self.firewall.defer_apply():
            pass
        self.iptables_inst.assert_has_calls([call.defer_apply_on(),
                                             call.defer_apply_off()])

    def test_filter_defer_with_exception(self):
        try:
            with self.firewall.defer_apply():
                raise Exception("same exception")
        except Exception:
            pass
        self.iptables_inst.assert_has_calls([call.defer_apply_on(),
                                             call.defer_apply_off()])

    def test_ip_spoofing_filter_with_multiple_ips(self):
        port = {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff',
                'fixed_ips': ['10.0.0.1', 'fe80::1', '10.0.0.2']}
        self.firewall.prepare_port_filter(port)
        calls = [call.add_chain('sg-fallback'),
                 call.add_rule('sg-fallback', '-j DROP'),
                 call.ensure_remove_chain('sg-chain'),
                 call.add_chain('sg-chain'),
                 call.add_chain('ifake_dev'),
                 call.add_rule('FORWARD',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-out tapfake_dev '
                               '-j $sg-chain'),
                 call.add_rule('sg-chain',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-out tapfake_dev '
                               '-j $ifake_dev'),
                 call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ifake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ifake_dev', '-j $sg-fallback'),
                 call.add_chain('ofake_dev'),
                 call.add_rule('FORWARD',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-in tapfake_dev '
                               '-j $sg-chain'),
                 call.add_rule('sg-chain',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-in tapfake_dev '
                               '-j $ofake_dev'),
                 call.add_rule('INPUT',
                               '-m physdev --physdev-is-bridged '
                               '--physdev-in tapfake_dev '
                               '-j $ofake_dev'),
                 call.add_chain('sfake_dev'),
                 call.add_rule('sfake_dev', '-s 10.0.0.1 -j RETURN'),
                 call.add_rule('sfake_dev', '-s 10.0.0.2 -j RETURN'),
                 call.add_rule('sfake_dev', '-j DROP'),
                 call.add_rule(
                     'ofake_dev', '-m mac ! --mac-source ff:ff:ff:ff -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-p udp --sport 68 --dport 67 -j RETURN'),
                 call.add_rule('ofake_dev', '-j $sfake_dev'),
                 call.add_rule(
                     'ofake_dev',
                     '-p udp --sport 67 --dport 68 -j DROP'),
                 call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 call.add_rule(
                     'ofake_dev',
                     '-m state --state ESTABLISHED,RELATED -j RETURN'),
                 call.add_rule('ofake_dev', '-j $sg-fallback'),
                 call.add_rule('sg-chain', '-j ACCEPT')]
        self.v4filter_inst.assert_has_calls(calls)
