# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Aruna Kushwaha, Cisco Systems Inc.
# @author: Abhishek Raut, Cisco Systems Inc.
# @author: Rudrajit Tapadar, Cisco Systems Inc.
# @author: Sergey Sudakovich, Cisco Systems Inc.


import re
from sqlalchemy.orm import exc
from sqlalchemy.sql import and_

from quantum.common import exceptions as q_exc
import quantum.db.api as db
from quantum.db import models_v2
from quantum.openstack.common import log as logging
from quantum.plugins.cisco.common import cisco_constants as c_const
from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import n1kv_models_v2

LOG = logging.getLogger(__name__)


def initialize():
    """
    Initialize the database
    """
    db.configure_db()


def get_network_binding(db_session, network_id):
    """
    Retrieve network binding

    :param db_session: database session
    :param network_id: UUID representing the network whose binding is
                       to fetch
    :returns: binding object
    """
    db_session = db_session or db.get_session()
    try:
        binding = (db_session.query(n1kv_models_v2.N1kvNetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        raise c_exc.N1kvNetworkBindingNotFound(network_id=network_id)


def add_network_binding(db_session, network_id, network_type,
                        physical_network, segmentation_id,
                        multicast_ip, network_profile_id):
    """
    Create network binding.

    :param db_session: database session
    :param network_id: UUID representing the network
    :param network_type: string representing type of network (VLAN or VXLAN)
    :param physical_network: Only applicable for VLAN networks. It
                             represents a L2 Domain
    :param segmentation_id: integer representing VLAN or VXLAN ID
    :param multicast_ip: VXLAN technology needs a multicast IP to be associated
                         with every VXLAN ID to deal with broadcast packets. A
                         single multicast IP can be shared by multiple VXLAN
                         IDs.
    :param network_profile_id: network profile ID based on which this network
                               is created
    """
    with db_session.begin(subtransactions=True):
        binding = n1kv_models_v2.N1kvNetworkBinding(network_id,
                                                    network_type,
                                                    physical_network,
                                                    segmentation_id,
                                                    multicast_ip,
                                                    network_profile_id)
        db_session.add(binding)


def get_port_binding(db_session, port_id):
    """
    Retrieve port binding.

    :param db_session: database session
    :param port_id: UUID representing the port whose binding is to fetch
    :returns: port binding object
    """
    db_session = db_session or db.get_session()
    try:
        binding = (db_session.query(n1kv_models_v2.N1kvPortBinding).
                   filter_by(port_id=port_id).
                   one())
        return binding
    except exc.NoResultFound:
        raise c_exc.N1kvPortBindingNotFound(port_id=port_id)


def add_port_binding(db_session, port_id, policy_profile_id):
    """
    Create port binding.

    Bind the port with policy profile.
    :param db_session: database session
    :param port_id: UUID of the port
    :param policy_profile_id: UUID of the policy profile
    """
    with db_session.begin(subtransactions=True):
        binding = n1kv_models_v2.N1kvPortBinding(port_id, policy_profile_id)
        db_session.add(binding)


def sync_vlan_allocations(network_vlan_ranges):
    """
    Synchronize vlan_allocations table with configured VLAN ranges

    Sync the network profile range with the vlan_allocations table for each
    physical network.
    :param network_vlan_ranges: dictionary of network vlan ranges with the
                                physical network name as key.
    """

    db_session = db.get_session()
    with db_session.begin():
        # process vlan ranges for each physical network separately
        for physical_network, vlan_ranges in network_vlan_ranges.iteritems():

            # determine current configured allocatable vlans for this
            # physical network
            vlan_ids = set()
            for vlan_range in vlan_ranges:
                vlan_ids |= set(xrange(vlan_range[0], vlan_range[1] + 1))

            # add missing allocatable vlans to table
            for vlan_id in sorted(vlan_ids):
                try:
                    alloc = (db_session.query(n1kv_models_v2.
                                              N1kvVlanAllocation).
                             filter_by(physical_network=physical_network).
                             filter_by(vlan_id=vlan_id).one())
                except exc.NoResultFound:
                    alloc = n1kv_models_v2.N1kvVlanAllocation(physical_network,
                                                              vlan_id)
                    db_session.add(alloc)


def delete_vlan_allocations(network_vlan_ranges):
    """
    Delete vlan_allocations for deleted network profile range

    :param network_vlan_ranges: dictionary of network vlan ranges with the
                                physical network name as key.
    """

    db_session = db.get_session()
    with db_session.begin():
        # process vlan ranges for each physical network separately
        for physical_network, vlan_ranges in network_vlan_ranges.iteritems():
            # Determine the set of vlan ids which need to be deleted.
            vlan_ids = set()
            for vlan_range in vlan_ranges:
                vlan_ids |= set(xrange(vlan_range[0], vlan_range[1] + 1))

            allocs = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                      filter_by(physical_network=physical_network).
                      all())
            for alloc in allocs:
                if alloc.vlan_id in vlan_ids:
                    if not alloc.allocated:
                        LOG.debug(_("removing vlan %(vlan)s on physical "
                                    "network %(network)s from pool"),
                                  {'vlan': alloc.vlan_id,
                                   'network': physical_network})
                        db_session.delete(alloc)


def get_vlan_allocation(physical_network, vlan_id):
    """
    Retrieve vlan allocation.

    :param physical network: string name for the physical network
    :param vlan_id: integer representing the VLAN ID.
    :returns: allocation object for given physical network and VLAN ID
    """
    db_session = db.get_session()
    try:
        alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                 filter_by(physical_network=physical_network,
                           vlan_id=vlan_id).
                 one())
        return alloc
    except exc.NoResultFound:
        return


def reserve_vlan(db_session, network_profile):
    """
    Reserve a VLAN ID within the range of the network profile.

    :param db_session: database session
    :param network_profile: network profile object
    """
    seg_min, seg_max = network_profile.get_segment_range(db_session)
    segment_type = 'vlan'

    with db_session.begin(subtransactions=True):
        alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                 filter(and_(
                        n1kv_models_v2.N1kvVlanAllocation.vlan_id >= seg_min,
                        n1kv_models_v2.N1kvVlanAllocation.vlan_id <= seg_max,
                        n1kv_models_v2.N1kvVlanAllocation.allocated == False)
                        )).first()
        if alloc:
            segment_id = alloc.vlan_id
            physical_network = alloc.physical_network
            alloc.allocated = True
            return (physical_network, segment_type, segment_id, '0.0.0.0')
        raise q_exc.NoNetworkAvailable()


def reserve_vxlan(db_session, network_profile):
    """
    Reserve a VXLAN ID within the range of the network profile.

    :param db_session: database session
    :param network_profile: network profile object
    """
    seg_min, seg_max = network_profile.get_segment_range(db_session)
    segment_type = 'vxlan'
    physical_network = ""

    with db_session.begin(subtransactions=True):
        alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                 filter(and_(
                        n1kv_models_v2.N1kvVxlanAllocation.vxlan_id >=
                        seg_min,
                        n1kv_models_v2.N1kvVxlanAllocation.vxlan_id <=
                        seg_max,
                        n1kv_models_v2.N1kvVxlanAllocation.allocated == False)
                        ).first())
        if alloc:
            segment_id = alloc.vxlan_id
            alloc.allocated = True
            return (physical_network, segment_type,
                    segment_id, network_profile.get_multicast_ip(db_session))
        raise q_exc.NoNetworkAvailable()


def alloc_network(db_session, network_profile_id):
    """
    Allocate network using first available free segment ID in segment range

    :param db_session: database session
    :param network_profile_id: UUID representing the network profile
    """
    with db_session.begin(subtransactions=True):
        try:
            network_profile = get_network_profile(network_profile_id)
            if network_profile:
                if network_profile.segment_type == 'vlan':
                    return reserve_vlan(db_session, network_profile)
                else:
                    return reserve_vxlan(db_session, network_profile)
        except q_exc.NotFound:
            LOG.debug(_("NetworkProfile not found"))


def reserve_specific_vlan(db_session, physical_network, vlan_id):
    """
    Reserve a specific VLAN ID for the network.

    :param db_session: database session
    :param physical_network: string representing the name of physical network
    :param vlan_id: integer value of the segmentation ID to be reserved
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     one())
            if alloc.allocated:
                if vlan_id == c_const.FLAT_VLAN_ID:
                    raise q_exc.FlatNetworkInUse(
                        physical_network=physical_network)
                else:
                    raise q_exc.VlanIdInUse(vlan_id=vlan_id,
                                            physical_network=physical_network)
            LOG.debug(_("Reserving specific vlan %(vlan)s on physical "
                        "network %(network)s from pool"),
                      {'vlan': vlan_id, 'network': physical_network})
            alloc.allocated = True
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific vlan %(vlan)s on physical "
                        "network %(network)s outside pool"),
                      {'vlan': vlan_id, 'network': physical_network})
            alloc = n1kv_models_v2.N1kvVlanAllocation(physical_network,
                                                      vlan_id)
            alloc.allocated = True
            db_session.add(alloc)


def release_vlan(db_session, physical_network, vlan_id, network_vlan_ranges):
    """
    Release a given VLAN ID

    :param db_session: database session
    :param physical_network: string representing the name of physical network
    :param vlan_id: integer value of the segmentation ID to be released
    :param network_vlan_ranges: dictionary of network vlan ranges with the
                                physical network name as key.
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     one())
            alloc.allocated = False
            inside = False
            for vlan_range in network_vlan_ranges.get(physical_network, []):
                if vlan_range[0] <= vlan_id <= vlan_range[1]:
                    inside = True
                    break
            if inside:
                msg = _("Releasing vlan %(vlan)s on physical "
                        "network %(network)s to pool")
            else:
                db_session.delete(alloc)
                msg = _("Releasing vlan %(vlan)s on physical "
                        "network %(network)s outside pool")
            LOG.debug(msg, {'vlan': vlan_id, 'network': physical_network})
        except exc.NoResultFound:
            LOG.warning(_("vlan_id %(vlan)s on physical network %(network)s "
                          "not found"),
                        {'vlan': vlan_id, 'network': physical_network})


def sync_vxlan_allocations(vxlan_id_ranges):
    """
    Synchronize vxlan_allocations table with configured vxlan ranges

    :param vxlan_id_ranges: list of segment range tuples
    """

    vxlan_ids = set()
    for vxlan_id_range in vxlan_id_ranges:
        tun_min, tun_max = vxlan_id_range
        if tun_max + 1 - tun_min > 1000000:
            LOG.error(_("Skipping unreasonable vxlan ID range %s"),
                      vxlan_id_range)
        else:
            vxlan_ids |= set(xrange(tun_min, tun_max + 1))

    db_session = db.get_session()
    with db_session.begin():
        for vxlan_id in sorted(vxlan_ids):
            try:
                alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                         filter_by(vxlan_id=vxlan_id).one())
            except exc.NoResultFound:
                alloc = n1kv_models_v2.N1kvVxlanAllocation(vxlan_id)
                db_session.add(alloc)


def delete_vxlan_allocations(vxlan_id_ranges):
    """
    Delete vxlan_allocations for deleted network profile range

    :param vxlan_id_ranges: list of segment range tuples
    """
    vxlan_ids = set()
    for vxlan_id_range in vxlan_id_ranges:
        tun_min, tun_max = vxlan_id_range
        if tun_max + 1 - tun_min > 1000000:
            LOG.error(_("Skipping unreasonable vxlan ID range %s"),
                      vxlan_id_range)
        else:
            vxlan_ids |= set(xrange(tun_min, tun_max + 1))

    db_session = db.get_session()
    with db_session.begin():
        allocs = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).all())
        for alloc in allocs:
            if alloc.vxlan_id in vxlan_ids:
                if not alloc.allocated:
                    LOG.debug(_("removing vxlan %s from pool") %
                              alloc.vxlan_id)
                    db_session.delete(alloc)


def get_vxlan_allocation(vxlan_id):
    """
    Retrieve VXLAN allocation for the given VXLAN ID

    :param vxlan_id: integer value representing the segmentation ID
    :returns: allocation object
    """
    db_session = db.get_session()
    try:
        alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                 filter_by(vxlan_id=vxlan_id).
                 one())
        return alloc
    except exc.NoResultFound:
        return


def reserve_specific_vxlan(db_session, vxlan_id):
    """
    Reserve a specific VXLAN ID.

    :param db_session: databse session
    :param vxlan_id: integer value representing the segmentation ID
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                     filter_by(vxlan_id=vxlan_id).
                     one())
            if alloc.allocated:
                raise c_exc.VxlanIdInUse(vxlan_id=vxlan_id)
            LOG.debug(_("reserving specific vxlan %s from pool") % vxlan_id)
            alloc.allocated = True
        except exc.NoResultFound:
            LOG.debug(_("reserving specific vxlan %s outside pool") % vxlan_id)
            alloc = n1kv_models_v2.N1kvVxlanAllocation(vxlan_id)
            alloc.allocated = True
            db_session.add(alloc)


def release_vxlan(db_session, vxlan_id, vxlan_id_ranges):
    """
    Release a given VXLAN ID

    :param db_session: database session
    :param vxlan_id: integer value representing the segmentation ID
    :param vxlan_id_ranges: list of the segment range tuples.
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                     filter_by(vxlan_id=vxlan_id).
                     one())
            alloc.allocated = False
            inside = False
            for vxlan_id_range in vxlan_id_ranges:
                if vxlan_id_range[0] <= vxlan_id <= vxlan_id_range[1]:
                    inside = True
                    break
            if inside:
                msg = _("releasing vxlan %s to pool")
            else:
                db_session.delete(alloc)
                msg = _("releasing vxlan %s outside pool")
            LOG.debug(msg, vxlan_id)
        except exc.NoResultFound:
            LOG.warning(_("vxlan_id %s not found"), vxlan_id)


def set_port_status(port_id, status):
    db_session = db.get_session()
    try:
        port = db_session.query(models_v2.Port).filter_by(id=port_id).one()
        port['status'] = status
        db_session.merge(port)
        db_session.flush()
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)


def get_vm_network(policy_profile_id, network_id):
    """Retrieve a vm_network based on policy profile and network id."""
    db_session = db.get_session()
    try:
        vm_network = (db_session.query(n1kv_models_v2.N1kVmNetwork).
                      filter_by(profile_id=policy_profile_id).
                      filter_by(network_id=network_id).one())
        return vm_network
    except exc.NoResultFound:
        raise c_exc.VMNetworkNotFound(name=None)


def add_vm_network(name, policy_profile_id, network_id, port_count):
    """
    Add a vm_network for a unique combination of network and
    policy profile. All ports having the same policy profile
    on one network will be associated with one vm network.
    Port count represents the number ports on one vm network.
    """
    db_session = db.get_session()
    try:
        vm_network = (db_session.query(n1kv_models_v2.N1kVmNetwork).
                      filter_by(name=name).one())
    except exc.NoResultFound:
        with db_session.begin(subtransactions=True):
            vm_network = n1kv_models_v2.N1kVmNetwork(name,
                                                     policy_profile_id,
                                                     network_id,
                                                     port_count)
            db_session.add(vm_network)
            db_session.flush()


def update_vm_network(name, port_count):
    """Updates a vm network with new port count."""
    db_session = db.get_session()
    try:
        vm_network = (db_session.query(n1kv_models_v2.N1kVmNetwork).
                      filter_by(name=name).one())
        if port_count is not None:
            vm_network['port_count'] = port_count
        db_session.merge(vm_network)
        db_session.flush()
        return vm_network
    except exc.NoResultFound:
        raise c_exc.VMNetworkNotFound(name=name)


def delete_vm_network(policy_profile_id, network_id):
    """Deletes a vm network."""
    db_session = db.get_session()
    vm_network = get_vm_network(policy_profile_id, network_id)
    with db_session.begin(subtransactions=True):
        db_session.delete(vm_network)
        db_session.query(n1kv_models_v2.N1kVmNetwork).filter_by(
            name=vm_network['name']).delete()
    return vm_network


def create_network_profile(network_profile):
    """
    Create Network Profile
    """
    LOG.debug(_("create_network_profile()"))
    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        if network_profile['segment_type'] == 'vlan':
            net_profile = n1kv_models_v2.NetworkProfile(
                name=network_profile['name'],
                segment_type=network_profile['segment_type'],
                segment_range=network_profile['segment_range'],
                physical_network=network_profile['physical_network'])
        elif network_profile['segment_type'] == 'vxlan':
            net_profile = n1kv_models_v2.NetworkProfile(
                name=network_profile['name'],
                segment_type=network_profile['segment_type'],
                mcast_ip_index=0,
                segment_range=network_profile['segment_range'],
                mcast_ip_range=network_profile['multicast_ip_range'])
        db_session.add(net_profile)
        return net_profile


def delete_network_profile(id):
    """
    Delete Network Profile
    """
    LOG.debug(_("delete_network_profile()"))
    db_session = db.get_session()
    network_profile = get_network_profile(id)
    with db_session.begin(subtransactions=True):
        db_session.delete(network_profile)
        db_session.query(n1kv_models_v2.ProfileBinding).filter(
            n1kv_models_v2.ProfileBinding.profile_id == id).delete()
    return network_profile


def update_network_profile(id, network_profile):
    """
    Update Network Profile
    """
    LOG.debug(_("update_network_profile()"))
    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        _profile = get_network_profile(id)
        _profile.update(network_profile)
        db_session.merge(_profile)
        return _profile


def get_network_profile(id, fields=None):
    """
    Get Network Profile
    """
    LOG.debug(_("get_network_profile()"))
    db_session = db.get_session()
    try:
        net_profile = db_session.query(
            n1kv_models_v2.NetworkProfile).filter_by(id=id).one()
        return net_profile
    except exc.NoResultFound:
        raise c_exc.NetworkProfileIdNotFound(profile_id=id)


def get_network_profile_by_name(name):
    """
    Get Network Profile by name.
    """
    LOG.debug(_("get_network_profile_by_name"))
    db_session = db.get_session()
    try:
        network_profile = db_session.query(
            n1kv_models_v2.NetworkProfile).filter_by(name=name).one()
        return network_profile
    except exc.NoResultFound:
        return None


def _get_network_profiles(**kwargs):
    """
    Get Network Profiles on a particular physical network, if physical
    network is specified. If no physical network is specified, return
    all network profiles.
    """
    db_session = db.get_session()
    if "physical_network" in kwargs:
        try:
            net_profiles = db_session.query(n1kv_models_v2.NetworkProfile).\
                filter_by(physical_network=kwargs[
                          'physical_network']).all()
            return net_profiles
        except exc.NoResultFound:
            return None
    else:
        return db_session.query(n1kv_models_v2.NetworkProfile).all()


def create_policy_profile(policy_profile):
    """
    Create Policy Profile
    """
    LOG.debug(_("create_policy_profile()"))
    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        p_profile = n1kv_models_v2.PolicyProfile(id=policy_profile['id'],
                                                 name=policy_profile['name'])
        db_session.add(p_profile)
        return p_profile


def delete_policy_profile(id):
    """
    Delete Policy Profile
    """
    LOG.debug(_("delete_policy_profile()"))
    db_session = db.get_session()
    policy_profile = get_policy_profile(id)
    with db_session.begin(subtransactions=True):
        db_session.delete(policy_profile)


def update_policy_profile(id, policy_profile):
    """
    Update a policy profile.
    """
    LOG.debug(_("update_policy_profile()"))
    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        _profile = get_policy_profile(id)
        _profile.update(policy_profile)
        db_session.merge(_profile)
        return _profile


def get_policy_profile(id, fields=None):
    """
    Get Policy Profile
    """
    LOG.debug(_("get_policy_profile()"))
    db_session = db.get_session()
    try:
        policy_profile = db_session.query(
            n1kv_models_v2.PolicyProfile).filter_by(id=id).one()
        return policy_profile
    except exc.NoResultFound:
        raise c_exc.PolicyProfileIdNotFound(profile_id=id)


def create_profile_binding(tenant_id, profile_id, profile_type):
    """
    Create Network/Policy Profile association with a tenant.
    """
    if profile_type not in ['network', 'policy']:
        raise q_exc.QuantumException("Invalid profile type")

    if _profile_binding_exists(tenant_id, profile_id, profile_type):
        return get_profile_binding(tenant_id, profile_id)

    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        binding = n1kv_models_v2.ProfileBinding(profile_type=profile_type,
                                                profile_id=profile_id,
                                                tenant_id=tenant_id)
        db_session.add(binding)
        db_session.flush()
        return binding


def _profile_binding_exists(tenant_id, profile_id, profile_type):
    LOG.debug(_("_profile_binding_exists()"))
    try:
        binding = _get_profile_binding(tenant_id, profile_id)
        return binding.profile_type == profile_type
    except exc.NoResultFound:
        return False
    except Exception, e:
        LOG.debug(_("Error in get_profile_binding(): %s") % e)


def _get_profile_binding(tenant_id, profile_id):
    LOG.debug(_("_get_profile_binding"))
    db_session = db.get_session()
    binding = db_session.query(n1kv_models_v2.ProfileBinding).filter_by(
        tenant_id=tenant_id, profile_id=profile_id).one()
    return binding


def get_profile_binding(tenant_id, profile_id):
    """
    Get Network/Policy Profile - Tenant binding
    """
    LOG.debug(_("get_profile_binding()"))
    try:
        return _get_profile_binding(tenant_id, profile_id)
    except exc.NoResultFound:
        raise q_exc.QuantumException("Profile-Tenant binding not found")
    except exc.MultipleResultsFound:
        raise q_exc.QuantumException("Profile-Tenant binding must be unique")


def delete_profile_binding(tenant_id, profile_id):
    """
    Delete Policy Binding
    """
    LOG.debug(_("delete_profile_binding()"))
    db_session = db.get_session()
    binding = get_profile_binding(tenant_id, profile_id)
    with db_session.begin(subtransactions=True):
        db_session.delete(binding)


def _get_profile_bindings(profile_type=None):
    """
    Get all profile-tenant bindings based on profile type.
    If profile type is None, return profile-tenant binding for all
    profile types.
    """
    LOG.debug(_("_get_profile_bindings()"))
    db_session = db.get_session()
    if profile_type:
        profile_bindings = db_session.query(n1kv_models_v2.ProfileBinding).\
            filter_by(profile_type=profile_type).all()
        return profile_bindings
    else:
        return db_session.query(n1kv_models_v2.ProfileBinding).all()


class NetworkProfile_db_mixin(object):

    """
    Network Profile Mixin
    """

    def _get_network_collection_for_tenant(self, model, tenant_id):
        db_session = db.get_session()
        net_profile_ids = (db_session.query(n1kv_models_v2.ProfileBinding.
                                            profile_id).
                           filter_by(tenant_id=tenant_id).
                           filter_by(profile_type='network').all())
        network_profiles = []
        for pid in net_profile_ids:
            try:
                network_profiles.append(db_session.query(model).
                                        filter_by(id=pid[0]).one())
            except exc.NoResultFound:
                pass
        return [self._make_network_profile_dict(p) for p in network_profiles]

    def _make_profile_bindings_dict(self, profile_binding, fields=None):
        res = {'profile_id': profile_binding['profile_id'],
               'tenant_id': profile_binding['tenant_id']}
        return self._fields(res, fields)

    def _make_network_profile_dict(self, network_profile, fields=None):
        res = {'id': network_profile['id'],
               'name': network_profile['name'],
               'segment_type': network_profile['segment_type'],
               'segment_range': network_profile['segment_range'],
               'multicast_ip_index': network_profile['multicast_ip_index'],
               'multicast_ip_range': network_profile['multicast_ip_range'],
               'physical_network': network_profile['physical_network']}
        return self._fields(res, fields)

    def get_network_profile_bindings(self, context, filters=None, fields=None):
        if context.is_admin:
            profile_bindings = _get_profile_bindings(profile_type='network')
            return [self._make_profile_bindings_dict(pb)
                    for pb in profile_bindings]

    def create_network_profile(self, context, network_profile):
        p = network_profile['network_profile']
        self._validate_network_profile_args(context, p)
        tenant_id = self._get_tenant_id_for_create(context, p)
        net_profile = create_network_profile(p)
        create_profile_binding(tenant_id, net_profile.id, 'network')
        if p.get('add_tenant'):
            self.add_network_profile_tenant(net_profile.id, p['add_tenant'])
        return self._make_network_profile_dict(net_profile)

    def delete_network_profile(self, context, id):
        _profile = delete_network_profile(id)
        return self._make_network_profile_dict(_profile)

    def update_network_profile(self, context, id, network_profile):
        p = network_profile['network_profile']
        if context.is_admin and 'add_tenant' in p:
            self.add_network_profile_tenant(id, p['add_tenant'])
            return self._make_network_profile_dict(get_network_profile(id))
        elif context.is_admin and 'remove_tenant' in p:
            delete_profile_binding(p['remove_tenant'], id)
            return self._make_network_profile_dict(get_network_profile(id))
        else:
            return self._make_network_profile_dict(
                update_network_profile(id, p))

    def get_network_profile(self, context, id, fields=None):
        try:
            profile = self._get_by_id(context, n1kv_models_v2.NetworkProfile,
                                      id)
        except exc.NoResultFound:
            raise q_exc.NetworkProfileNotFound(profile_id=id)
        return self._make_network_profile_dict(profile, fields)

    def get_network_profiles(self, context, filters=None, fields=None):
        if context.is_admin:
            return self._get_collection(context, n1kv_models_v2.NetworkProfile,
                                        self._make_network_profile_dict,
                                        filters=filters, fields=fields)
        else:
            return self._get_network_collection_for_tenant(n1kv_models_v2.
                                                           NetworkProfile,
                                                           context.tenant_id)

    def add_network_profile_tenant(self, network_profile_id, tenant_id):
        """
        Add a tenant to a network profile
        """
        return create_profile_binding(tenant_id, network_profile_id, 'network')

    def network_profile_exists(self, context, id):
        try:
            get_network_profile(id)
            return True
        except exc.NoResultFound:
            raise c_exc.NetworkProfileIdNotFound(profile_id=id)

    def _get_segment_range(self, data):
        # Sort the range to ensure min, max is in order
        seg_min, seg_max = sorted(map(int, data.split('-')))
        return (seg_min, seg_max)

    def _validate_network_profile_args(self, context, p):
        """
        Validate completeness of Nexus1000V network profile arguments.
        """
        # TODO(abhraut): Cleanup validation logic
        self._validate_network_profile(p)
        self._validate_segment_range_uniqueness(context, p)

    def _validate_vlan(self, p):
        """Validate if vlan falls within segment boundaries."""
        '''
        seg_min, seg_max = self._get_segment_range(p['segment_range'])
        ranges = conf.CISCO_N1K.network_vlan_ranges
        ranges = ranges.split(',')
        for entry in ranges:
            entry = entry.strip()
            if ':' in entry:
                g_phy_nw, g_seg_min, g_seg_max = entry.split(':')
                if (seg_min < int(g_seg_min)) or (seg_max > int(g_seg_max)):
                    msg = _("Vlan out of range")
                    LOG.exception(msg)
                    raise q_exc.InvalidInput(error_message=msg)
        '''
        pass

    def _validate_vxlan(self, p):
        """
        Validate if vxlan falls within segment boundaries.
        :param p:
        :return:
        """
        '''
        seg_min, seg_max = self._get_segment_range(p['segment_range'])
        ranges = conf.CISCO_N1K.vxlan_id_ranges
        ranges = ranges.split(',')
        g_seg_min, g_seg_max = map(int, ranges[0].split(':'))
        LOG.debug("segmin %s segmax %s gsegmin %s gsegmax %s", seg_min,
                  seg_max, g_seg_min, g_seg_max)
        if (seg_min < g_seg_min) or (seg_max > g_seg_max):
            msg = _("Vxlan out of range")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        if p['multicast_ip_range'] == '0.0.0.0':
            msg = _("Multicast ip range is required")
            raise q_exc.InvalidInput(error_message=msg)
        if p['multicast_ip_range'].count('-') != 1:
            msg = _("invalid ip range. example range: 225.280.100.10-"
                    "225.280.100.20")
            raise q_exc.InvalidInput(error_message=msg)
        for ip in p['multicast_ip_range'].split('-'):
            if _validate_ip_address(ip) != None:
                msg = _("invalid ip address %s" % ip)
                raise q_exc.InvalidInput(error_message=msg)
        '''
        pass

    def _validate_segment_range(self, network_profile):
        """
        Validate segment range values.
        :param p:
        :return:
        """
        mo = re.match(r"(\d+)\-(\d+)", network_profile['segment_range'])
        if mo is None:
            msg = _("invalid segment range. example range: 500-550")
            raise q_exc.InvalidInput(error_message=msg)

    def _validate_network_profile(self, net_p):
        """
        Validate completeness of a network profile arguments.
        :param p:
        :return:
        """
        if any(net_p[arg] == '' for arg in ('segment_type', 'segment_range')):
            msg = _("arguments segment_type and segment_range missing"
                    " for network profile")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        _segment_type = net_p['segment_type'].lower()
        if _segment_type not in ['vlan', 'vxlan']:
            msg = _("segment_type should either be vlan or vxlan")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        self._validate_segment_range(net_p)
        if _segment_type == n1kv_models_v2.SEGMENT_TYPE_VLAN:
            self._validate_vlan(net_p)
            net_p['multicast_ip_range'] = '0.0.0.0'
        elif _segment_type == n1kv_models_v2.SEGMENT_TYPE_VXLAN:
            self._validate_vxlan(net_p)

    def _validate_segment_range_uniqueness(self, context, net_p):
        """
        Validate that segment range doesn't overlap.
        :param context:
        :param p:
        :return:
        """
        segment_type = net_p['segment_type'].lower()
        if segment_type == n1kv_models_v2.SEGMENT_TYPE_VLAN:
            profiles = _get_network_profiles(
                physical_network=net_p['physical_network'])
        elif segment_type == n1kv_models_v2.SEGMENT_TYPE_VXLAN:
            profiles = _get_network_profiles()
        if profiles:
            for prfl in profiles:
                name = prfl.name
                segment_range = prfl.segment_range
                if net_p['name'] == name:
                    msg = (_("NetworkProfile name %s already exists"),
                           net_p['name'])
                    LOG.exception(msg)
                    raise q_exc.InvalidInput(error_message=msg)
                seg_min, seg_max = self._get_segment_range(
                    net_p['segment_range'])
                prfl_seg_min, prfl_seg_max = self._get_segment_range(
                    segment_range)
                if (((seg_min >= prfl_seg_min) and
                     (seg_min <= prfl_seg_max)) or
                    ((seg_max >= prfl_seg_min) and
                     (seg_max <= prfl_seg_max)) or
                    ((seg_min <= prfl_seg_min) and
                     (seg_max >= prfl_seg_max))):
                    msg = _("segment range overlaps with another profile")
                    LOG.exception(msg)
                    raise q_exc.InvalidInput(error_message=msg)


class PolicyProfile_db_mixin(object):

    """
    Policy Profile Mixin
    """

    def _get_policy_collection_for_tenant(self, model, tenant_id):
        db_session = db.get_session()
        profile_ids = (db_session.query(n1kv_models_v2.
                       ProfileBinding.profile_id)
                       .filter_by(tenant_id=tenant_id).
                       filter_by(profile_type='policy').all())
        profiles = []
        for pid in profile_ids:
            try:
                profiles.append(db_session.query(model).
                                filter_by(id=pid[0]).one())
            except exc.NoResultFound:
                pass
        return [self._make_policy_profile_dict(p) for p in profiles]

    def _make_policy_profile_dict(self, policy_profile, fields=None):
        res = {'id': policy_profile['id'], 'name': policy_profile['name']}
        return self._fields(res, fields)

    def _make_profile_bindings_dict(self, profile_binding, fields=None):
        res = {'profile_id': profile_binding['profile_id'],
               'tenant_id': profile_binding['tenant_id']}
        return self._fields(res, fields)

    def _policy_profile_exists(self, id):
        db_session = db.get_session()
        return db_session.query(n1kv_models_v2.PolicyProfile).\
            filter_by(id=id).count() and True or False

    def get_policy_profile(self, context, id, fields=None):
        try:
            profile = self._get_by_id(context, n1kv_models_v2.PolicyProfile,
                                      id)
        except exc.NoResultFound:
            raise q_exc.PolicyProfileNotFound(profile_id=id)
        return self._make_policy_profile_dict(profile, fields)

    def get_policy_profiles(self, context, filters=None, fields=None):
        if context.is_admin:
            return self._get_collection(context, n1kv_models_v2.PolicyProfile,
                                        self._make_policy_profile_dict,
                                        filters=filters, fields=fields)
        else:
            return self._get_policy_collection_for_tenant(n1kv_models_v2.
                                                          PolicyProfile,
                                                          context.tenant_id)

    def get_policy_profile_bindings(self, context, filters=None, fields=None):
        if context.is_admin:
            profile_bindings = _get_profile_bindings(profile_type='policy')
            return [self._make_profile_bindings_dict(pb)
                    for pb in profile_bindings]

    def update_policy_profile(self, context, id, policy_profile):
        p = policy_profile['policy_profile']
        if context.is_admin and 'add_tenant' in p:
            self.add_policy_profile_tenant(id, p['add_tenant'])
            return self._make_policy_profile_dict(get_policy_profile(id))
        elif context.is_admin and 'remove_tenant' in p:
            delete_profile_binding(p['remove_tenant'], id)
            return self._make_policy_profile_dict(get_policy_profile(id))
        else:
            return self._make_policy_profile_dict(update_policy_profile(id,
                                                                        p))

    def policy_profile_exists(self, context, id):
        try:
            get_policy_profile(id)
            return True
        except exc.NoResultFound:
            raise c_exc.PolicyProfileIdNotFound(profile_id=id)

    def add_policy_profile_tenant(self, policy_profile_id, tenant_id):
        """
        Add tenant to a policy profile
        """
        return create_profile_binding(tenant_id, policy_profile_id, 'policy')

    def remove_policy_profile_tenant(self, policy_profile_id, tenant_id):
        delete_profile_binding(tenant_id, policy_profile_id)

    def _delete_policy_profile(self, policy_profile_id):
        """
        Delete policy profile and associated binding
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            db_session.query(n1kv_models_v2.PolicyProfile).\
                filter(n1kv_models_v2.PolicyProfile.id ==
                       policy_profile_id).delete()
            db_session.query(n1kv_models_v2.ProfileBinding).\
                filter(n1kv_models_v2.ProfileBinding.profile_id ==
                       policy_profile_id).delete()

    def _get_policy_profile_by_name(self, name):
        """
        Get policy profile based on name
        """
        db_session = db.get_session()
        try:
            with db_session.begin(subtransactions=True):
                profile = db_session.query(n1kv_models_v2.PolicyProfile).\
                    filter(n1kv_models_v2.PolicyProfile.name ==
                           name).one()
                return profile
        except exc.NoResultFound:
            return None

    def _remove_all_fake_policy_profiles(self):
        """
        Remove all policy profiles associated with fake tenant id

        This will find all Profile ID where tenant is not set yet - set A
        and profiles where tenant was already set - set B
        and remove what is in both and no tenant id set

        :return:
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            a_set_q = db_session.query(n1kv_models_v2.ProfileBinding).\
                filter_by(tenant_id=n1kv_models_v2.TENANT_ID_NOT_SET,
                          profile_type='policy').all()
            a_set = {i.profile_id for i in a_set_q}
            b_set_q = db_session.query(n1kv_models_v2.ProfileBinding).\
                filter(and_(n1kv_models_v2.ProfileBinding.tenant_id !=
                            n1kv_models_v2.TENANT_ID_NOT_SET,
                            n1kv_models_v2.ProfileBinding.profile_type ==
                            'policy')).all()
            b_set = {i.profile_id for i in b_set_q}
            db_session.query(n1kv_models_v2.ProfileBinding).\
                filter(and_(n1kv_models_v2.ProfileBinding.
                            profile_id.in_(a_set & b_set), n1kv_models_v2.
                            ProfileBinding.tenant_id == n1kv_models_v2.
                            TENANT_ID_NOT_SET)).\
                delete(synchronize_session='fetch')

    def _replace_fake_tenant_id_with_real(self, context):
        """
        Replace fake tenant id for all Policy Profile
        binding with real admin tenant ID
        """
        if context.is_admin and context.tenant_id:
            tenant_id = context.tenant_id
            db_session = db.get_session()
            with db_session.begin(subtransactions=True):
                db_session.query(n1kv_models_v2.ProfileBinding).\
                    filter_by(tenant_id=n1kv_models_v2.TENANT_ID_NOT_SET).\
                    update({'tenant_id': tenant_id})

    def _add_policy_profile(self,
                            policy_profile_name,
                            policy_profile_id,
                            tenant_id=None):
        """
        Add Policy profile and tenant binding
        """
        policy_profile = {'id': policy_profile_id, 'name': policy_profile_name}
        tenant_id = tenant_id or n1kv_models_v2.TENANT_ID_NOT_SET
        if not self._policy_profile_exists(policy_profile_id):
            create_policy_profile(policy_profile)
        create_profile_binding(tenant_id, policy_profile['id'], 'policy')
