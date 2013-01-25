# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Aaron Rosen, Nicira Networks, Inc.
# @author: Bob Kukura, Red Hat, Inc.

import logging

from sqlalchemy.orm import exc
from sqlalchemy.sql import and_

from quantum.common import exceptions as q_exc
from quantum.db import models_v2
import quantum.db.api as db
from quantum.openstack.common import cfg
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.db import n1kv_models_v2
from quantum.plugins.cisco.db import n1kv_profile_db
from quantum.plugins.cisco.common import cisco_exceptions as c_exc

LOG = logging.getLogger(__name__)


def initialize():
    db.configure_db()


def get_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(n1kv_models_v2.N1kNetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_network_binding(session, network_id, network_type,
                 physical_network, segmentation_id, multicast_ip, profile_id):
    with session.begin(subtransactions=True):
        binding = n1kv_models_v2.N1kNetworkBinding(network_id, network_type,
            physical_network,
            segmentation_id, multicast_ip, profile_id)
        session.add(binding)

def get_port_binding(session, port_id):
    session = session or db.get_session()
    try:
        binding = (session.query(n1kv_models_v2.N1kPortBinding).
                   filter_by(port_id=port_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_port_binding(session, port_id, profile_id):
    with session.begin(subtransactions=True):
        binding = n1kv_models_v2.N1kPortBinding(port_id, profile_id)
        session.add(binding)



def sync_vlan_allocations(network_vlan_ranges):
    """Synchronize vlan_allocations table with configured VLAN ranges"""

    session = db.get_session()
    with session.begin():
        # process vlan ranges for each physical network separately
        for physical_network, vlan_ranges in network_vlan_ranges.iteritems():

            # determine current configured allocatable vlans for this
            # physical network
            vlan_ids = set()
            for vlan_range in vlan_ranges:
                vlan_ids |= set(xrange(vlan_range[0], vlan_range[1] + 1))

            # remove from table unallocated vlans not currently allocatable
            try:
                allocs = (session.query(n1kv_models_v2.N1kVlanAllocation).
                          filter_by(physical_network=physical_network).
                          all())
                for alloc in allocs:
                    try:
                        # see if vlan is allocatable
                        vlan_ids.remove(alloc.vlan_id)
                    except KeyError:
                        # it's not allocatable, so check if its allocated
                        if not alloc.allocated:
                            # it's not, so remove it from table
                            LOG.debug("removing vlan %s on physical network "
                                      "%s from pool" %
                                      (alloc.vlan_id, physical_network))
                            session.delete(alloc)
            except exc.NoResultFound:
                pass

            # add missing allocatable vlans to table
            for vlan_id in sorted(vlan_ids):
                alloc = n1kv_models_v2.N1kVlanAllocation(physical_network, vlan_id)
                session.add(alloc)


def get_vlan_allocation(physical_network, vlan_id):
    session = db.get_session()
    try:
        alloc = (session.query(n1kv_models_v2.N1kVlanAllocation).
                 filter_by(physical_network=physical_network,
            vlan_id=vlan_id).
                 one())
        return alloc
    except exc.NoResultFound:
        return

def reserve_vlan(session, profile):
    seg_min, seg_max = profile.get_segment_range(session)
    segment_type = 'vlan'

    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(n1kv_models_v2.N1kVlanAllocation).
                    filter(and_(n1kv_models_v2.N1kVlanAllocation.vlan_id>=seg_min,
                        n1kv_models_v2.N1kVlanAllocation.vlan_id<=seg_max,
                        n1kv_models_v2.N1kVlanAllocation.allocated==False))).first()
            segment_id = alloc.vlan_id
            physical_network = alloc.physical_network
            alloc.allocated = True
            return (physical_network, segment_type, segment_id, '0.0.0.0')
        except exc.NoResultFound:
            raise q_exc.VlanIdInUse(vlan_id=segment_id,
                    physical_network=segment_type)

def reserve_tunnel(session, profile):
    seg_min, seg_max = profile.get_segment_range(session)
    segment_type = 'vxlan'
    physical_network = ""

    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(n1kv_models_v2.N1kTunnelAllocation).
                    filter(and_(n1kv_models_v2.N1kTunnelAllocation.tunnel_id>=seg_min,
                        n1kv_models_v2.N1kTunnelAllocation.tunnel_id<=seg_max,
                        n1kv_models_v2.N1kTunnelAllocation.allocated==False)).first())
            segment_id = alloc.tunnel_id
            alloc.allocated = True
            return (physical_network, segment_type, segment_id, profile.get_multicast_ip(session))
        except exc.NoResultFound:
            raise q_exc.TunnelIdInUse(tunnel_id=segment_id)


def alloc_network(session, profile_id):
    with session.begin(subtransactions=True):
        try:
            profile = (session.query(n1kv_profile_db.Profile).
                    filter_by(profile_id=profile_id).one())
            if profile:
                if profile.segment_type == 'vlan':
                    return reserve_vlan(session, profile)
                else:
                    return reserve_tunnel(session, profile)
        except q_exc.NotFound:
            LOG.debug("Profile not found")


def reserve_specific_vlan(session, physical_network, vlan_id):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(n1kv_models_v2.N1kVlanAllocation).
                     filter_by(physical_network=physical_network,
                vlan_id=vlan_id).
                     one())
            if alloc.allocated:
                if vlan_id == const.FLAT_VLAN_ID:
                    raise q_exc.FlatNetworkInUse(physical_network=
                    physical_network)
                else:
                    raise q_exc.VlanIdInUse(vlan_id=vlan_id,
                        physical_network=physical_network)
            LOG.debug("reserving specific vlan %s on physical network %s "
                      "from pool" % (vlan_id, physical_network))
            alloc.allocated = True
        except exc.NoResultFound:
            LOG.debug("reserving specific vlan %s on physical network %s "
                      "outside pool" % (vlan_id, physical_network))
            alloc = n1kv_models_v2.N1kVlanAllocation(physical_network, vlan_id)
            alloc.allocated = True
            session.add(alloc)


def release_vlan(session, physical_network, vlan_id, network_vlan_ranges):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(n1kv_models_v2.N1kVlanAllocation).
                     filter_by(physical_network=physical_network,
                vlan_id=vlan_id).
                     one())
            alloc.allocated = False
            inside = False
            for vlan_range in network_vlan_ranges.get(physical_network, []):
                if vlan_id >= vlan_range[0] and vlan_id <= vlan_range[1]:
                    inside = True
                    break
            if not inside:
                session.delete(alloc)
            LOG.debug("releasing vlan %s on physical network %s %s pool" %
                      (vlan_id, physical_network,
                       inside and "to" or "outside"))
        except exc.NoResultFound:
            LOG.warning("vlan_id %s on physical network %s not found" %
                        (vlan_id, physical_network))


def sync_tunnel_allocations(tunnel_id_ranges):
    """Synchronize tunnel_allocations table with configured tunnel ranges"""

    # determine current configured allocatable tunnels
    tunnel_ids = set()
    for tunnel_id_range in tunnel_id_ranges:
        tun_min, tun_max = tunnel_id_range
        if tun_max + 1 - tun_min > 1000000:
            LOG.error("Skipping unreasonable tunnel ID range %s:%s" %
                      tunnel_id_range)
        else:
            tunnel_ids |= set(xrange(tun_min, tun_max + 1))

    session = db.get_session()
    with session.begin():
        # remove from table unallocated tunnels not currently allocatable
        try:
            allocs = (session.query(n1kv_models_v2.N1kTunnelAllocation).
                      all())
            for alloc in allocs:
                try:
                    # see if tunnel is allocatable
                    tunnel_ids.remove(alloc.tunnel_id)
                except KeyError:
                    # it's not allocatable, so check if its allocated
                    if not alloc.allocated:
                        # it's not, so remove it from table
                        LOG.debug("removing tunnel %s from pool" %
                                  alloc.tunnel_id)
                        session.delete(alloc)
        except exc.NoResultFound:
            pass

        # add missing allocatable tunnels to table
        for tunnel_id in sorted(tunnel_ids):
            alloc = n1kv_models_v2.N1kTunnelAllocation(tunnel_id)
            session.add(alloc)


def get_tunnel_allocation(tunnel_id):
    session = db.get_session()
    try:
        alloc = (session.query(n1kv_models_v2.N1kTunnelAllocation).
                 filter_by(tunnel_id=tunnel_id).
                 one())
        return alloc
    except exc.NoResultFound:
        return


def reserve_specific_tunnel(session, tunnel_id):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(n1kv_models_v2.N1kTunnelAllocation).
                     filter_by(tunnel_id=tunnel_id).
                     one())
            if alloc.allocated:
                raise q_exc.TunnelIdInUse(tunnel_id=tunnel_id)
            LOG.debug("reserving specific tunnel %s from pool" % tunnel_id)
            alloc.allocated = True
        except exc.NoResultFound:
            LOG.debug("reserving specific tunnel %s outside pool" % tunnel_id)
            alloc = n1kv_models_v2.N1kTunnelAllocation(tunnel_id)
            alloc.allocated = True
            session.add(alloc)


def release_tunnel(session, tunnel_id, tunnel_id_ranges):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(n1kv_models_v2.N1kTunnelAllocation).
                     filter_by(tunnel_id=tunnel_id).
                     one())
            alloc.allocated = False
            inside = False
            for tunnel_id_range in tunnel_id_ranges:
                if (tunnel_id >= tunnel_id_range[0]
                    and tunnel_id <= tunnel_id_range[1]):
                    inside = True
                    break
            if not inside:
                session.delete(alloc)
            LOG.debug("releasing tunnel %s %s pool" %
                      (tunnel_id, inside and "to" or "outside"))
        except exc.NoResultFound:
            LOG.warning("tunnel_id %s not found" % tunnel_id)


def get_port(port_id):
    session = db.get_session()
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
    except exc.NoResultFound:
        port = None
    return port


def set_port_status(port_id, status):
    session = db.get_session()
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
        port['status'] = status
        session.merge(port)
        session.flush()
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)


def get_tunnel_endpoints():
    session = db.get_session()
    try:
        tunnels = session.query(n1kv_models_v2.N1kTunnelEndpoint).all()
    except exc.NoResultFound:
        return []
    return [{'id': tunnel.id,
             'ip_address': tunnel.ip_address} for tunnel in tunnels]


def _generate_tunnel_id(session):
    try:
        tunnels = session.query(n1kv_models_v2.N1kTunnelEndpoint).all()
    except exc.NoResultFound:
        return 0
    tunnel_ids = ([tunnel['id'] for tunnel in tunnels])
    if tunnel_ids:
        id = max(tunnel_ids)
    else:
        id = 0
    return id + 1


def add_tunnel_endpoint(ip):
    session = db.get_session()
    try:
        tunnel = (session.query(n1kv_models_v2.N1kTunnelEndpoint).
                  filter_by(ip_address=ip).one())
    except exc.NoResultFound:
        id = _generate_tunnel_id(session)
        tunnel = n1kv_models_v2.N1kTunnelEndpoint(ip, id)
        session.add(tunnel)
        session.flush()
    return tunnel

def get_vm_network(profile_id, network_id):
    """Retrieve a vm_network based on profile and network id"""
    session = db.get_session()
    try:
        vm_network = (session.query(n1kv_models_v2.N1kVmNetwork).
                      filter_by(profile_id=profile_id).
                      filter_by(network_id=network_id).one())
        return vm_network
    except exc.NoResultFound:
        return None

def add_vm_network(name, profile_id, network_id):
    session = db.get_session()
    with session.begin(subtransactions=True):
        vm_network = n1kv_models_v2.N1kVmNetwork(name, profile_id, network_id)
        session.add(vm_network)
