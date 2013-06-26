# Copyright (c) 2013 OpenStack Foundation
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
# @author: Kyle Mestery, Cisco Systems, Inc.

import sys

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy.orm import exc as sa_exc
from sqlalchemy.sql import func

from quantum.common import exceptions as exc
from quantum.db import api as db_api
from quantum.db import model_base
from quantum.openstack.common import log
from quantum.plugins.ml2 import driver_api as api
from quantum.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

VXLAN_UDP_PORT = 4789

vxlan_opts = [
    cfg.ListOpt('vni_ranges',
                default=[],
                help=_("Comma-separated list of <vni_min>:<vni_max> tuples "
                       "enumerating ranges of VXLAN VNI IDs that are "
                       "available for tenant network allocation")),
    cfg.StrOpt('vxlan_group', default=None,
               help=_("Multicast group for VXLAN. If unset, disables VXLAN "
                      "multicast mode.")),
]

cfg.CONF.register_opts(vxlan_opts, "ml2_type_vxlan")


class VXLANAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_vxlan_allocations'

    vxlan_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)

    def __init__(self, vxlan_vni):
        self.vxlan_vni = vxlan_vni
        self.allocated = False


class VXLANEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""
    __tablename__ = 'ml2_vxlan_endpoints'

    ip_address = sa.Column(sa.String(64), primary_key=True)
    id = sa.Column(sa.Integer, nullable=False)
    udp_port = sa.Column(sa.Integer, nullable=False)
    multicast_group = sa.Column(sa.String(64), nullable=False)

    def __init__(self, ip_address, id, multicast_group):
        self.ip_address = ip_address
        self.id = id
        self.udp_port = VXLAN_UDP_PORT
        self.multicast_group = multicast_group

    def __repr__(self):
        return "<TunnelEndpoint(%s,%s)>" % (self.ip_address, self.id)


class VXLANTypeDriver(api.TypeDriver,
                      type_tunnel.TunnelTypeDriver):

    def get_type(self):
        return type_tunnel.TYPE_VXLAN

    def initialize(self):
        self.vxlan_vni_ranges = []
        self._parse_vxlan_vni_ranges()
        self._sync_vxlan_allocations()

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network:
            msg = _("provider:physical_network specified for VXLAN "
                    "network")
            raise exc.InvalidInput(error_message=msg)

        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if segmentation_id is None:
            msg = _("segmentation_id required for VXLAN provider network")
            raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(VXLANAllocation).
                         filter_by(vxlan_vni=segmentation_id).
                         with_lockmode('update').
                         one())
                if alloc.allocated:
                    raise exc.TunnelIdInUse(tunnel_id=segmentation_id)
                LOG.debug(_("Reserving specific vxlan tunnel %s from pool"),
                          segmentation_id)
                alloc.allocated = True
            except sa_exc.NoResultFound:
                LOG.debug(_("Reserving specific vxlan tunnel %s outside pool"),
                          segmentation_id)
                alloc = VXLANAllocation(segmentation_id)
                alloc.allocated = True
                session.add(alloc)

    def allocate_tenant_segment(self, session):
        with session.begin(subtransactions=True):
            alloc = (session.query(VXLANAllocation).
                     filter_by(allocated=False).
                     with_lockmode('update').
                     first())
            if alloc:
                LOG.debug(_("Allocating vxlan tunnel vni %(vxlan_vni)s"),
                          {'vxlan_vni': alloc.vxlan_vni})
                alloc.allocated = True
                return {api.NETWORK_TYPE: type_tunnel.TYPE_VXLAN,
                        api.PHYSICAL_NETWORK: None,
                        api.SEGMENTATION_ID: alloc.vxlan_vni}
        raise exc.NoNetworkAvailable()

    def release_segment(self, session, segment):
        vxlan_vni = segment[api.SEGMENTATION_ID]
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(VXLANAllocation).
                         filter_by(vxlan_vni=vxlan_vni).
                         with_lockmode('update').
                         one())
                alloc.allocated = False
                inside = False
                for vxlan_vni_range in self.vxlan_vni_ranges:
                    if (vxlan_vni >= vxlan_vni_range[0]
                        and vxlan_vni <= vxlan_vni_range[1]):
                        inside = True
                        break
                if not inside:
                    session.delete(alloc)
                    LOG.debug(_("Releasing vxlan tunnel %s outside pool"),
                              vxlan_vni)
                else:
                    LOG.debug(_("Releasing vxln tunnel %s to pool"), vxlan_vni)
            except sa_exc.NoResultFound:
                LOG.warning(_("vxlan_vni %s not found"), vxlan_vni)

    def _parse_vxlan_vni_ranges(self):
        for entry in cfg.CONF.ml2_type_vxlan.vni_ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                self.vxlan_vni_ranges.append((int(tun_min), int(tun_max)))
            except ValueError as ex:
                LOG.error(_("Invalid VXLAN tunnel ID range: "
                            "'%(range)s' - %(e)s. Agent terminated!"),
                          {'range': entry, 'e': ex})
                sys.exit(1)
        LOG.info(_("VXLAN ID ranges: %s"), self.vxlan_vni_ranges)

    def _sync_vxlan_allocations(self):
        """
        Synchronize vxlan_allocations table with configured tunnel ranges.
        """

        # determine current configured allocatable vnis
        vxlan_vnis = set()
        for vxlan_vni_range in self.vxlan_vni_ranges:
            tun_min, tun_max = vxlan_vni_range
            if tun_max + 1 - tun_min > 1000000:
                LOG.error(_("Skipping unreasonable VXLAN VNI range "
                            "%(tun_min)s:%(tun_max)s"),
                          {'tun_min': tun_min, 'tun_max': tun_max})
            else:
                vxlan_vnis |= set(xrange(tun_min, tun_max + 1))

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            # remove from table unallocated tunnels not currently allocatable
            allocs = (session.query(VXLANAllocation).all())
            for alloc in allocs:
                try:
                    # see if tunnel is allocatable
                    vxlan_vnis.remove(alloc.vxlan_vni)
                except KeyError:
                    # it's not allocatable, so check if its allocated
                    if not alloc.allocated:
                        # it's not, so remove it from table
                        LOG.debug(_("Removing tunnel %s from pool"),
                                  alloc.vxlan_vni)
                        session.delete(alloc)

            # add missing allocatable tunnels to table
            for vxlan_vni in sorted(vxlan_vnis):
                alloc = VXLANAllocation(vxlan_vni)
                session.add(alloc)

    def get_vxlan_allocation(self, session, vxlan_vni):
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(VXLANAllocation).
                         filter_by(vxlan_vni=vxlan_vni).
                         with_lockmode('update').one())
                return alloc
            except sa_exc.NoResultFound:
                return

    def get_endpoints(self):
        """Get every vxlan endpoints from database."""

        LOG.debug(_("get_vxlan_endpoints() called"))
        session = db_api.get_session()

        with session.begin(subtransactions=True):
            vxlan_endpoints = session.query(VXLANEndpoints)
            return [{'id': vxlan_endpoint.id,
                     'ip_address': vxlan_endpoint.ip_address}
                    for vxlan_endpoint in vxlan_endpoints]

    def _generate_vxlan_endpoint_id(self, session):
        max_tunnel_id = session.query(
            func.max(VXLANEndpoints.id)).scalar() or 0
        return max_tunnel_id + 1

    def add_endpoint(self, ip):
        LOG.debug(_("add_vxlan_endpoint() called for ip %s"), ip)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            try:
                vxlan_endpoint = (session.query(VXLANEndpoints).
                                  filter_by(ip_address=ip).
                                  with_lockmode('update').one())
            except sa_exc.NoResultFound:
                vxlan_endpoint_id = self._generate_vxlan_endpoint_id(session)
                vxlan_endpoint = VXLANEndpoints(ip, vxlan_endpoint_id,
                                                (cfg.CONF.ml2_type_vxlan.
                                                 vxlan_group))
                session.add(vxlan_endpoint)
            return vxlan_endpoint
