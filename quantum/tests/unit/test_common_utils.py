# Copyright (c) 2012 OpenStack Foundation.
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

import testtools

from quantum.common import exceptions as q_exc
from quantum.common import utils
from quantum.plugins.common import utils as plugin_utils
from quantum.tests import base


class TestParseMappings(base.BaseTestCase):
    def parse(self, mapping_list, unique_values=True):
        return utils.parse_mappings(mapping_list, unique_values)

    def test_parse_mappings_fails_for_missing_separator(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key'])

    def test_parse_mappings_fails_for_missing_key(self):
        with testtools.ExpectedException(ValueError):
            self.parse([':val'])

    def test_parse_mappings_fails_for_missing_value(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key:'])

    def test_parse_mappings_fails_for_extra_separator(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key:val:junk'])

    def test_parse_mappings_fails_for_duplicate_key(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key:val1', 'key:val2'])

    def test_parse_mappings_fails_for_duplicate_value(self):
        with testtools.ExpectedException(ValueError):
            self.parse(['key1:val', 'key2:val'])

    def test_parse_mappings_succeeds_for_one_mapping(self):
        self.assertEqual(self.parse(['key:val']), {'key': 'val'})

    def test_parse_mappings_succeeds_for_n_mappings(self):
        self.assertEqual(self.parse(['key1:val1', 'key2:val2']),
                         {'key1': 'val1', 'key2': 'val2'})

    def test_parse_mappings_succeeds_for_duplicate_value(self):
        self.assertEqual(self.parse(['key1:val', 'key2:val'], False),
                         {'key1': 'val', 'key2': 'val'})

    def test_parse_mappings_succeeds_for_no_mappings(self):
        self.assertEqual(self.parse(['']), {})


class UtilTestParseVlanRanges(base.BaseTestCase):
    _err_prefix = "Invalid network VLAN range: '"
    _err_too_few = "' - 'need more than 2 values to unpack'"
    _err_too_many = "' - 'too many values to unpack'"
    _err_not_int = "' - 'invalid literal for int() with base 10: '%s''"
    _err_bad_vlan = "' - '%s is not a valid VLAN tag'"
    _err_range = "' - 'End of VLAN range is less than start of VLAN range'"

    def _range_too_few_err(self, nv_range):
        return self._err_prefix + nv_range + self._err_too_few

    def _range_too_many_err(self, nv_range):
        return self._err_prefix + nv_range + self._err_too_many

    def _vlan_not_int_err(self, nv_range, vlan):
        return self._err_prefix + nv_range + (self._err_not_int % vlan)

    def _nrange_invalid_vlan(self, nv_range, n):
        vlan = nv_range.split(':')[n]
        v_range = ':'.join(nv_range.split(':')[1:])
        return self._err_prefix + v_range + (self._err_bad_vlan % vlan)

    def _vrange_invalid_vlan(self, v_range_tuple, n):
        vlan = v_range_tuple[n - 1]
        v_range_str = '%d:%d' % v_range_tuple
        return self._err_prefix + v_range_str + (self._err_bad_vlan % vlan)

    def _vrange_invalid(self, v_range_tuple):
        v_range_str = '%d:%d' % v_range_tuple
        return self._err_prefix + v_range_str + self._err_range


class TestVlanRangeVerifyValid(UtilTestParseVlanRanges):
    def verify_range(self, vlan_range):
        return plugin_utils.verify_vlan_range(vlan_range)

    def test_range_valid_ranges(self):
        self.assertEqual(self.verify_range((1, 2)), None)
        self.assertEqual(self.verify_range((1, 1999)), None)
        self.assertEqual(self.verify_range((100, 100)), None)
        self.assertEqual(self.verify_range((100, 200)), None)
        self.assertEqual(self.verify_range((4001, 4094)), None)
        self.assertEqual(self.verify_range((1, 4094)), None)

    def check_one_vlan_invalid(self, bad_range, which):
        expected_msg = self._vrange_invalid_vlan(bad_range, which)
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.verify_range, bad_range)
        self.assertEqual(str(err), expected_msg)

    def test_range_first_vlan_invalid_negative(self):
        self.check_one_vlan_invalid((-1, 199), 1)

    def test_range_first_vlan_invalid_zero(self):
        self.check_one_vlan_invalid((0, 199), 1)

    def test_range_first_vlan_invalid_limit_plus_one(self):
        self.check_one_vlan_invalid((4095, 199), 1)

    def test_range_first_vlan_invalid_too_big(self):
        self.check_one_vlan_invalid((9999, 199), 1)

    def test_range_second_vlan_invalid_negative(self):
        self.check_one_vlan_invalid((299, -1), 2)

    def test_range_second_vlan_invalid_zero(self):
        self.check_one_vlan_invalid((299, 0), 2)

    def test_range_second_vlan_invalid_limit_plus_one(self):
        self.check_one_vlan_invalid((299, 4095), 2)

    def test_range_second_vlan_invalid_too_big(self):
        self.check_one_vlan_invalid((299, 9999), 2)

    def test_range_both_vlans_invalid_01(self):
        self.check_one_vlan_invalid((-1, 0), 1)

    def test_range_both_vlans_invalid_02(self):
        self.check_one_vlan_invalid((0, 4095), 1)

    def test_range_both_vlans_invalid_03(self):
        self.check_one_vlan_invalid((4095, 9999), 1)

    def test_range_both_vlans_invalid_04(self):
        self.check_one_vlan_invalid((9999, -1), 1)

    def test_range_reversed(self):
        bad_range = (95, 10)
        expected_msg = self._vrange_invalid(bad_range)
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.verify_range, bad_range)
        self.assertEqual(str(err), expected_msg)


class TestParseOneVlanRange(UtilTestParseVlanRanges):
    def parse_one(self, cfg_entry):
        return plugin_utils.parse_network_vlan_range(cfg_entry)

    def test_parse_one_net_no_vlan_range(self):
        config_str = "net1"
        expected_networks = ("net1", None)
        self.assertEqual(self.parse_one(config_str), expected_networks)

    def test_parse_one_net_and_vlan_range(self):
        config_str = "net1:100:199"
        expected_networks = ("net1", (100, 199))
        self.assertEqual(self.parse_one(config_str), expected_networks)

    def test_parse_one_net_incomplete_range(self):
        config_str = "net1:100"
        expected_msg = self._range_too_few_err(config_str)
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_range_too_many(self):
        config_str = "net1:100:150:200"
        expected_msg = self._range_too_many_err(config_str)
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_vlan1_not_int(self):
        config_str = "net1:foo:199"
        expected_msg = self._vlan_not_int_err(config_str, 'foo')
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_vlan2_not_int(self):
        config_str = "net1:100:bar"
        expected_msg = self._vlan_not_int_err(config_str, 'bar')
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_and_max_range(self):
        config_str = "net1:1:4094"
        expected_networks = ("net1", (1, 4094))
        self.assertEqual(self.parse_one(config_str), expected_networks)

    def test_parse_one_net_range_bad_vlan1(self):
        config_str = "net1:9000:150"
        expected_msg = self._nrange_invalid_vlan(config_str, 1)
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)

    def test_parse_one_net_range_bad_vlan2(self):
        config_str = "net1:4000:4999"
        expected_msg = self._nrange_invalid_vlan(config_str, 2)
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_one, config_str)
        self.assertEqual(str(err), expected_msg)


class TestParseVlanRangeList(UtilTestParseVlanRanges):
    def parse_list(self, cfg_entries):
        return plugin_utils.parse_network_vlan_ranges(cfg_entries)

    def test_parse_list_one_net_no_vlan_range(self):
        config_list = ["net1"]
        expected_networks = {"net1": []}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_list_one_net_vlan_range(self):
        config_list = ["net1:100:199"]
        expected_networks = {"net1": [(100, 199)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_no_vlan_range(self):
        config_list = ["net1",
                       "net2"]
        expected_networks = {"net1": [],
                             "net2": []}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_range_and_no_range(self):
        config_list = ["net1:100:199",
                       "net2"]
        expected_networks = {"net1": [(100, 199)],
                             "net2": []}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_no_range_and_range(self):
        config_list = ["net1",
                       "net2:200:299"]
        expected_networks = {"net1": [],
                             "net2": [(200, 299)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_bad_vlan_range1(self):
        config_list = ["net1:100",
                       "net2:200:299"]
        expected_msg = self._range_too_few_err(config_list[0])
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_list, config_list)
        self.assertEqual(str(err), expected_msg)

    def test_parse_two_nets_vlan_not_int2(self):
        config_list = ["net1:100:199",
                       "net2:200:0x200"]
        expected_msg = self._vlan_not_int_err(config_list[1], '0x200')
        err = self.assertRaises(q_exc.NetworkVlanRangeError,
                                self.parse_list, config_list)
        self.assertEqual(str(err), expected_msg)

    def test_parse_two_nets_and_append_1_2(self):
        config_list = ["net1:100:199",
                       "net1:1000:1099",
                       "net2:200:299"]
        expected_networks = {"net1": [(100, 199),
                                      (1000, 1099)],
                             "net2": [(200, 299)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)

    def test_parse_two_nets_and_append_1_3(self):
        config_list = ["net1:100:199",
                       "net2:200:299",
                       "net1:1000:1099"]
        expected_networks = {"net1": [(100, 199),
                                      (1000, 1099)],
                             "net2": [(200, 299)]}
        self.assertEqual(self.parse_list(config_list), expected_networks)
