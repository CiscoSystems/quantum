# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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
# @author: Abhishek Raut, Cisco Systems Inc.

from sqlalchemy.orm import exc as s_exc
import unittest2

from quantum.common import exceptions as q_exc
from quantum.db import api as db
from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import n1kv_db_v2
from quantum.plugins.cisco.db.n1kv_models_v2 import NetworkProfile
from quantum.plugins.cisco.db.n1kv_models_v2 import PolicyProfile
from quantum.plugins.cisco.db.n1kv_models_v2 import ProfileBinding
from quantum.tests.unit import test_db_plugin as test_plugin

PHYS_NET = 'physnet1'
PHYS_NET_2 = 'physnet2'
VLAN_MIN = 10
VLAN_MAX = 19
VLAN_RANGES = {PHYS_NET: [(VLAN_MIN, VLAN_MAX)]}
UPDATED_VLAN_RANGES = {PHYS_NET: [(VLAN_MIN + 20, VLAN_MAX + 20)],
                       PHYS_NET_2: [(VLAN_MIN + 40, VLAN_MAX + 40)]}
VXLAN_MIN = 100
VXLAN_MAX = 109
VXLAN_RANGES = [(VXLAN_MIN, VXLAN_MAX)]
UPDATED_VXLAN_RANGES = [(VXLAN_MIN + 20, VXLAN_MAX + 20)]
TEST_NETWORK_ID = 'abcdefghijklmnopqrstuvwxyz'
TEST_NETWORK_PROFILE = {'name': 'test_profile',
                        'segment_type': 'vlan',
                        'physical_network': 'physnet1',
                        'segment_range': '10-19'}
TEST_NETWORK_PROFILE_VXLAN = {'name': 'test_profile',
                              'segment_type': 'vxlan',
                              'segment_range': '100-109',
                              'multicast_ip_range': '239.0.0.70-239.0.0.80'}
TEST_POLICY_PROFILE = {'id': '4a417990-76fb-11e2-bcfd-0800200c9a66',
                       'name': 'test_policy_profile'}


def _create_test_network_profile_if_not_there(session,
                                              profile=TEST_NETWORK_PROFILE):
    try:
        _profile = session.query(NetworkProfile).filter_by(
            name=profile['name']).one()
    except s_exc.NoResultFound:
        _profile = n1kv_db_v2.create_network_profile(profile)
    return _profile


def _create_test_policy_profile_if_not_there(session,
                                             profile=TEST_POLICY_PROFILE):
    try:
        _profile = session.query(PolicyProfile).filter_by(
            name=profile['name']).one()
    except s_exc.NoResultFound:
        _profile = n1kv_db_v2.create_policy_profile(profile)
    return _profile


class VlanAllocationsTest(unittest2.TestCase):

    def setUp(self):
        n1kv_db_v2.initialize()
        n1kv_db_v2.sync_vlan_allocations(VLAN_RANGES)
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_sync_vlan_allocations(self):
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                         VLAN_MIN - 1))
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN).allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX).allocated)
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                         VLAN_MAX + 1))

        n1kv_db_v2.sync_vlan_allocations(UPDATED_VLAN_RANGES)

        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                         VLAN_MIN + 20 - 1))
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN + 20).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN + 20 + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX + 20 - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX + 20).
                         allocated)
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                         VLAN_MAX + 20 + 1))

        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                         VLAN_MIN + 40 - 1))
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MIN + 40).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MIN + 40 + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MAX + 40 - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MAX + 40).
                         allocated)
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                         VLAN_MAX + 40 + 1))

        n1kv_db_v2.sync_vlan_allocations(VLAN_RANGES)

        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                         VLAN_MIN - 1))
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN).allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX).allocated)
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                         VLAN_MAX + 1))

        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                         VLAN_MIN + 20))
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                         VLAN_MAX + 20))

    def test_vlan_pool(self):
        vlan_ids = set()
        p = _create_test_network_profile_if_not_there(self.session)
        for x in xrange(VLAN_MIN, VLAN_MAX + 1):
            physical_network, seg_type, vlan_id, m_ip = \
                n1kv_db_v2.reserve_vlan(
                    self.session, p)
            self.assertEqual(physical_network, PHYS_NET)
            self.assertGreaterEqual(vlan_id, VLAN_MIN)
            self.assertLessEqual(vlan_id, VLAN_MAX)
            vlan_ids.add(vlan_id)

        with self.assertRaises(q_exc.NoNetworkAvailable):
            physical_network, seg_type, vlan_id, m_ip = \
                n1kv_db_v2.reserve_vlan(
                    self.session, p)

        n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_ids.pop(),
                                VLAN_RANGES)
        physical_network, seg_type, vlan_id, m_ip = \
            n1kv_db_v2.reserve_vlan(
                self.session, p)
        self.assertEqual(physical_network, PHYS_NET)
        self.assertGreaterEqual(vlan_id, VLAN_MIN)
        self.assertLessEqual(vlan_id, VLAN_MAX)
        vlan_ids.add(vlan_id)

        for vlan_id in vlan_ids:
            n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_id,
                                    VLAN_RANGES)

    def test_specific_vlan_inside_pool(self):
        vlan_id = VLAN_MIN + 5
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        vlan_id).allocated)
        n1kv_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)
        self.assertTrue(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                       vlan_id).allocated)

        with self.assertRaises(q_exc.VlanIdInUse):
            n1kv_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)

        n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_id, VLAN_RANGES)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                        vlan_id).allocated)

    def test_specific_vlan_outside_pool(self):
        vlan_id = VLAN_MAX + 5
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET, vlan_id))
        n1kv_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)
        self.assertTrue(n1kv_db_v2.get_vlan_allocation(PHYS_NET,
                                                       vlan_id).allocated)

        with self.assertRaises(q_exc.VlanIdInUse):
            n1kv_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)

        n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_id, VLAN_RANGES)
        self.assertIsNone(n1kv_db_v2.get_vlan_allocation(PHYS_NET, vlan_id))


class VxlanAllocationsTest(unittest2.TestCase):

    def setUp(self):
        n1kv_db_v2.initialize()
        n1kv_db_v2.sync_vxlan_allocations(VXLAN_RANGES)
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_sync_vxlan_allocations(self):
        self.assertIsNone(n1kv_db_v2.get_vxlan_allocation(VXLAN_MIN - 1))
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MIN).allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MIN + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MAX - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MAX).allocated)
        self.assertIsNone(n1kv_db_v2.get_vxlan_allocation(VXLAN_MAX + 1))

        n1kv_db_v2.sync_vxlan_allocations(UPDATED_VXLAN_RANGES)

        self.assertIsNone(n1kv_db_v2.get_vxlan_allocation(VXLAN_MIN + 20 - 1))
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MIN + 20).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MIN + 20 + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MAX + 20 - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(VXLAN_MAX + 20).
                         allocated)
        self.assertIsNone(n1kv_db_v2.get_vxlan_allocation(VXLAN_MAX + 20 + 1))

    def test_vxlan_pool(self):
        vxlan_ids = set()
        profile = _create_test_network_profile_if_not_there(
            session=self.session,
            profile=TEST_NETWORK_PROFILE_VXLAN)
        for x in xrange(VXLAN_MIN, VXLAN_MAX + 1):
            vxlan = n1kv_db_v2.reserve_vxlan(self.session, profile)
            vxlan_id = vxlan[2]
            self.assertGreaterEqual(vxlan_id, VXLAN_MIN)
            self.assertLessEqual(vxlan_id, VXLAN_MAX)
            vxlan_ids.add(vxlan_id)

        with self.assertRaises(q_exc.NoNetworkAvailable):
            vxlan = n1kv_db_v2.reserve_vxlan(self.session, profile)
            vxlan_id = vxlan[2]
        n1kv_db_v2.release_vxlan(self.session, vxlan_ids.pop(), VXLAN_RANGES)
        vxlan = n1kv_db_v2.reserve_vxlan(self.session, profile)
        vxlan_id = vxlan[2]
        self.assertGreaterEqual(vxlan_id, VXLAN_MIN)
        self.assertLessEqual(vxlan_id, VXLAN_MAX)
        vxlan_ids.add(vxlan_id)

        for vxlan_id in vxlan_ids:
            n1kv_db_v2.release_vxlan(self.session, vxlan_id, VXLAN_RANGES)

    def test_specific_vxlan_inside_pool(self):
        vxlan_id = VXLAN_MIN + 5
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(vxlan_id).allocated)
        n1kv_db_v2.reserve_specific_vxlan(self.session, vxlan_id)
        self.assertTrue(n1kv_db_v2.get_vxlan_allocation(vxlan_id).allocated)

        with self.assertRaises(c_exc.VxlanIdInUse):
            n1kv_db_v2.reserve_specific_vxlan(self.session, vxlan_id)

        n1kv_db_v2.release_vxlan(self.session, vxlan_id, VXLAN_RANGES)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(vxlan_id).allocated)

    def test_specific_vxlan_outside_pool(self):
        vxlan_id = VXLAN_MAX + 5
        self.assertIsNone(n1kv_db_v2.get_vxlan_allocation(vxlan_id))
        n1kv_db_v2.reserve_specific_vxlan(self.session, vxlan_id)
        self.assertTrue(n1kv_db_v2.get_vxlan_allocation(vxlan_id).allocated)

        with self.assertRaises(c_exc.VxlanIdInUse):
            n1kv_db_v2.reserve_specific_vxlan(self.session, vxlan_id)

        n1kv_db_v2.release_vxlan(self.session, vxlan_id, VXLAN_RANGES)
        self.assertIsNone(n1kv_db_v2.get_vxlan_allocation(vxlan_id))


class NetworkBindingsTest(test_plugin.QuantumDbPluginV2TestCase):

    def setUp(self):
        super(NetworkBindingsTest, self).setUp()
        n1kv_db_v2.initialize()
        self.session = db.get_session()

    def tearDown(self):
        super(NetworkBindingsTest, self).tearDown()

    def test_add_network_binding(self):
        with self.network() as network:
            TEST_NETWORK_ID = network['network']['id']

            self.assertRaises(c_exc.N1kvNetworkBindingNotFound,
                              n1kv_db_v2.get_network_binding,
                              self.session,
                              TEST_NETWORK_ID)

            p = _create_test_network_profile_if_not_there(self.session)
            n1kv_db_v2.add_network_binding(
                self.session, TEST_NETWORK_ID, 'vlan',
                PHYS_NET, 1234, '0.0.0.0', p.id)
            binding = n1kv_db_v2.get_network_binding(
                self.session, TEST_NETWORK_ID)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.network_id, TEST_NETWORK_ID)
            self.assertEqual(binding.network_type, 'vlan')
            self.assertEqual(binding.physical_network, PHYS_NET)
            self.assertEqual(binding.segmentation_id, 1234)


class NetworkProfileTests(unittest2.TestCase):

    def setUp(self):
        n1kv_db_v2.initialize()
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_create_network_profile(self):
        _db_profile = n1kv_db_v2.create_network_profile(TEST_NETWORK_PROFILE)
        self.assertIsNotNone(_db_profile)
        db_profile = self.session.query(NetworkProfile).filter_by(
            name=TEST_NETWORK_PROFILE['name']).one()
        self.assertIsNotNone(db_profile)
        self.assertTrue(_db_profile.id == db_profile.id and
                        _db_profile.name == db_profile.name and
                        _db_profile.segment_type == db_profile.segment_type and
                        _db_profile.segment_range ==
                        db_profile.segment_range and
                        _db_profile.multicast_ip_index ==
                        db_profile.multicast_ip_index and
                        _db_profile.multicast_ip_range ==
                        db_profile.multicast_ip_range)

    def test_delete_network_profile(self):
        try:
            profile = self.session.query(NetworkProfile).filter_by(
                name=TEST_NETWORK_PROFILE['name']).one()
        except s_exc.NoResultFound:
            profile = n1kv_db_v2.create_network_profile(TEST_NETWORK_PROFILE)

        n1kv_db_v2.delete_network_profile(profile.id)
        try:
            self.session.query(NetworkProfile).filter_by(
                name=TEST_NETWORK_PROFILE['name']).one()
        except s_exc.NoResultFound:
            pass
        else:
            self.fail("Network Profile (%s) was not deleted" %
                      TEST_NETWORK_PROFILE['name'])

    def test_update_network_profile(self):
        TEST_PROFILE_1 = {'name': 'test_profile_1'}
        profile = _create_test_network_profile_if_not_there(self.session)
        updated_profile = n1kv_db_v2.update_network_profile(profile.id,
                                                            TEST_PROFILE_1)
        try:
            self.session.query(NetworkProfile).filter_by(name=profile.name).\
                one()
        except s_exc.NoResultFound:
            pass
        else:
            self.fail("Profile name was not updated")
        self.assertEqual(updated_profile.name, TEST_PROFILE_1['name'])

    def test_get_network_profile(self):
        profile = _create_test_network_profile_if_not_there(self.session)
        got_profile = n1kv_db_v2.get_network_profile(profile.id)
        self.assertEqual(profile.id, got_profile.id)
        self.assertEqual(profile.name, got_profile.name)

    def test_get_network_profiles(self):
        test_profiles = [{'name': 'test_profile1',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '200-210'},
                         {'name': 'test_profile2',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '211-220'},
                         {'name': 'test_profile3',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '221-230'},
                         {'name': 'test_profile4',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '231-240'},
                         {'name': 'test_profile5',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '241-250'},
                         {'name': 'test_profile6',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '251-260'},
                         {'name': 'test_profile7',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '261-270'}]
        [n1kv_db_v2.create_network_profile(p) for p in test_profiles]
        # TODO(abhraut): Fix this test to work with real tenant_td
        profiles = n1kv_db_v2._get_network_profiles()
        self.assertEqual(len(test_profiles), len(profiles))


class PolicyProfileTests(unittest2.TestCase):

    def setUp(self):
        n1kv_db_v2.initialize()
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_create_policy_profile(self):
        _db_profile = n1kv_db_v2.create_policy_profile(TEST_POLICY_PROFILE)
        self.assertIsNotNone(_db_profile)
        db_profile = self.session.query(PolicyProfile).filter_by(
            name=TEST_POLICY_PROFILE['name']).one()
        self.assertIsNotNone(db_profile)
        self.assertTrue(_db_profile.id == db_profile.id and
                        _db_profile.name == db_profile.name)

    def test_delete_policy_profile(self):
        profile = _create_test_policy_profile_if_not_there(self.session)
        n1kv_db_v2.delete_policy_profile(profile.id)
        try:
            self.session.query(PolicyProfile).filter_by(
                name=TEST_POLICY_PROFILE['name']).one()
        except s_exc.NoResultFound:
            pass
        else:
            self.fail("Policy Profile (%s) was not deleted" %
                      TEST_POLICY_PROFILE['name'])

    def test_update_policy_profile(self):
        TEST_PROFILE_1 = {'name': 'test_profile_1'}
        profile = _create_test_policy_profile_if_not_there(self.session)
        updated_profile = n1kv_db_v2.update_policy_profile(profile.id,
                                                           TEST_PROFILE_1)
        try:
            self.session.query(PolicyProfile).filter_by(name=profile.name).\
                one()
        except s_exc.NoResultFound:
            pass
        else:
            self.fail("Profile name was not updated")
        self.assertEqual(updated_profile.name, TEST_PROFILE_1['name'])

    def test_get_policy_profile(self):
        profile = _create_test_policy_profile_if_not_there(self.session)
        got_profile = n1kv_db_v2.get_policy_profile(profile.id)
        self.assertEqual(profile.id, got_profile.id)
        self.assertEqual(profile.name, got_profile.name)

    """
    def test_get_all_policy_profiles(self):
        test_profiles = [{'name': 'test_profile1',
                          'id':'e9dcbd10-76fc-11e2-bcfd-0800200c9a66'},
                         {'name': 'test_profile2',
                          'id':'efb30820-76fc-11e2-bcfd-0800200c9a66'},
                         {'name': 'test_profile3',
                          'id':'f7bef7e0-76fc-11e2-bcfd-0800200c9a66'},
                         {'name': 'test_profile4',
                          'id':'fc628f50-76fc-11e2-bcfd-0800200c9a66'},
                         {'name': 'test_profile5',
                          'id':'0139b9e0-76fd-11e2-bcfd-0800200c9a66'},
                         {'name': 'test_profile6',
                          'id':'07990b10-76fd-11e2-bcfd-0800200c9a66'},
                         {'name': 'test_profile7',
                          'id':'0ca8f8e0-76fd-11e2-bcfd-0800200c9a66'}]
        [n1kv_db_v2.create_policy_profile(p) for p in test_profiles]
        #TODO Fix this test to work with real tenant_td
        profiles = n1kv_db_v2.get_all_policy_profiles(None)
        self.assertEqual(len(test_profiles), len(profiles))
    """


class ProfileBindingTests(unittest2.TestCase):

    def setUp(self):
        n1kv_db_v2.initialize()
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def _create_test_binding_if_not_there(self, tenant_id, profile_id,
                                          profile_type):
        try:
            _binding = self.session.query(ProfileBinding).filter_by(
                profile_type=profile_type, tenant_id=tenant_id,
                profile_id=profile_id).one()
        except s_exc.NoResultFound:
            _binding = n1kv_db_v2.create_profile_binding(tenant_id,
                                                         profile_id,
                                                         profile_type)
        return _binding

    def test_create_profile_binding(self):
        test_tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "dd7b9741-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "network"
        n1kv_db_v2.create_profile_binding(test_tenant_id, test_profile_id,
                                          test_profile_type)
        try:
            self.session.query(ProfileBinding).filter_by(
                profile_type=test_profile_type,
                tenant_id=test_tenant_id,
                profile_id=test_profile_id).one()
        except s_exc.MultipleResultsFound:
            self.fail("Bindings must be unique")
        except s_exc.NoResultFound:
            self.fail("Could not create Profile Binding")

    def test_get_profile_binding(self):
        test_tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "dd7b9741-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "network"
        self._create_test_binding_if_not_there(test_tenant_id,
                                               test_profile_id,
                                               test_profile_type)
        binding = n1kv_db_v2.get_profile_binding(test_tenant_id,
                                                 test_profile_id)
        self.assertEqual(binding.tenant_id, test_tenant_id)
        self.assertEqual(binding.profile_id, test_profile_id)
        self.assertEqual(binding.profile_type, test_profile_type)

    def test_delete_profile_binding(self):
        test_tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "dd7b9741-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "network"
        self._create_test_binding_if_not_there(test_tenant_id,
                                               test_profile_id,
                                               test_profile_type)
        n1kv_db_v2.delete_profile_binding(test_tenant_id, test_profile_id)
        try:
            self.session.query(ProfileBinding).filter_by(
                profile_type=test_profile_type,
                tenant_id=test_tenant_id,
                profile_id=test_profile_id).one()
        except s_exc.NoResultFound:
            pass
        except s_exc.MultipleResultsFound:
            self.fail("This is very bad - multiple results and should be none")
        else:
            self.fail("Profile binding was not deleted")
