# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Cisco Systems, Inc.
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
# @author: Abhishek Raut, Cisco Systems, Inc.
# @author: Rudrajit Tapadar, Cisco Systems, Inc.

import re
import uuid
import logging
import quantum.db.api as db

from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import exc

from quantum.api.v2.attributes import _validate_ip_address
from quantum.db import model_base
from quantum.db import models_v2
from quantum.db.models_v2 import model_base
from quantum.common import exceptions as q_exc
from quantum.plugins.cisco.extensions import profile
from quantum.plugins.cisco.common import cisco_exceptions
from quantum.plugins.cisco.common import config as conf


LOG = logging.getLogger(__name__)


class N1kvProfile_db(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents N1kv profiles"""
    __tablename__ = 'profiles'

    name = Column(String(255))
    profile_type = Column(String(255))
    profile_id = Column(String(255))
    segment_type = Column(String(255))
    segment_range = Column(String(255))
    multicast_ip_range = Column(String(255))
    multicast_ip_index = Column(Integer)

    def get_segment_range(self, session):
        """Get the segment range min and max for a network profile."""
        with session.begin(subtransactions=True):
            # Sort the range to ensure min, max is in order
            seg_min, seg_max = sorted(map(int, self.segment_range.split('-')))
            LOG.debug("N1kvProfile_db: seg_min %s seg_max %s",
                      seg_min, seg_max)
            return (int(seg_min), int(seg_max))

    def get_multicast_ip(self, session):
        "Returns a multicast ip from the defined pool."
        # Round robin multicast ip allocation
        with session.begin(subtransactions=True):
            try:
                min_ip, max_ip = self._get_multicast_ip_range()
                min_addr = int(min_ip.split('.')[3])
                max_addr = int(max_ip.split('.')[3])
                addr_list = list(xrange(min_addr, max_addr + 1))

                mul_ip = min_ip.split('.')
                mul_ip[3] = str(addr_list[self.multicast_ip_index])

                self.multicast_ip_index += 1
                if self.multicast_ip_index == len(addr_list):
                    self.multicast_ip_index = 0
                mul_ip_str = '.'.join(mul_ip)
                return mul_ip_str

            except exc.NoResultFound:
                raise cisco_exceptions.ProfileNotFound(profile_id=id)

    def _get_multicast_ip_range(self):
        # Assumption: ip range belongs to the same subnet
        # Assumption: ip range is already sorted
        #min_ip, max_ip = sorted(self.multicast_ip_range.split('-'))
        min_ip, max_ip = self.multicast_ip_range.split('-')
        return (min_ip, max_ip)


class N1kvProfile_db_mixin(profile.ProfileBase):
    """Mixin class to add N1kv Profile methods to db_plugin_base_v2"""

    def create_profile(self, context, profile):
        """Create a new N1kv profile."""

        p = profile['profile']
        self._validate_arguments(context, p)
        tenant_id = self._get_tenant_id_for_create(context, p)
        p['profile_id'] = uuid.uuid4()
        try:
            with context.session.begin(subtransactions=True):
                profile_db = N1kvProfile_db(
                        id=p['profile_id'],
                        tenant_id=tenant_id,
                        name=p['name'],
                        profile_type=p['profile_type'],
                        profile_id=p['profile_id'],
                        segment_type=p['segment_type'].lower(),
                        segment_range=p['segment_range'],
                        multicast_ip_range=p['multicast_ip_range'],
                        multicast_ip_index=0)
                context.session.add(profile_db)
        except q_exc.BadRequest:
            LOG.exception("Unable to create profile due to a"
                    "malformed request")
        return self._make_profile_dict(profile_db)

    def delete_profile(self, context, id):
        """Delete a N1kv profile."""

        profile = self._get_profile(context, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(profile)

    def update_profile(self, context, id, profile):
        """Update a N1kv profile."""

        p = profile['profile']
        with context.session.begin(subtransactions=True):
            profile_db = self._get_profile(context, id)
            if p.keys():
                profile_db.update(p)
        return self._make_profile_dict(profile_db)
    '''

    def get_profile_by_type(self, profile_type):
        """List the N1Kv Profiles by its type"""
        session = db.get_session()
        try:
            profile = (session.query(N1kvProfile_db).
                       filter_by(profile_type=profile_type).all())
            return profile
        except exc.NoResultFound:
            raise n1kv_exc.ProfileTypeNotFound(profile_type=profile_type)

    '''

    def add_profile(self, tenant_id, profile_id, name, profile_type):
        session = db.get_session()
        try:
            profiledb = (session.query(N1kvProfile_db).
                    filter_by(profile_id=profile_id).one())
            LOG.debug("Add N1kvProfile_db failed: Profile %s already exists",
                      profile_id)
        except exc.NoResultFound:
            profiledb = N1kvProfile_db(tenant_id=tenant_id,
                                       profile_id=profile_id,
                                       id=profile_id,
                                       name=name,
                                       profile_type=profile_type)
            session.add(profiledb)
            session.flush()
            return profiledb

    def get_profile_by_id(self, profile_id):
        """Get N1kv Profile by its id."""

        session = db.get_session()
        try:
            profile = (session.query(N1kvProfile_db).
                       filter_by(id=profile_id).one())
                       #filter_by(profile_id=profile_id).one())   @@@@@@
            return profile
        except exc.NoResultFound:
            raise cisco_exceptions.ProfileId

    def get_profiles(self, context, filters=None, fields=None):
        return self._get_collection(context, N1kvProfile_db,
                                    self._make_profile_dict,
                                    filters=filters, fields=fields)

    def get_profile(self, context, id, fields=None):
        profile = self._get_profile(context, id)
        return self._make_profile_dict(profile, fields)

    def _make_profile_dict(self, profile, fields=None):
        res = {'profile_id': profile['profile_id'],
               'name': profile['name'],
               'profile_type': profile['profile_type'],
               'tenant_id': profile['tenant_id'],
               'segment_type': profile['segment_type'],
               'segment_range': profile['segment_range'],
               'multicast_ip_range': profile['multicast_ip_range']
              }
        LOG.debug("ABS DB %s\n", res)
        return self._fields(res, fields)

    def _get_profile(self, context, id):
        try:
            profile = self._get_by_id(context, N1kvProfile_db, id)
        except exc.NoResultFound:
            raise cisco_exceptions.ProfileIdNotFound(profile_id=id)
        except exc.MultipleResultsFound:
            LOG.error("Muliple profile match for %s" % id)
            raise cisco_exceptions.ProfileIdNotFound(profile_id=id)
        return profile

    def network_profile_exist(self, context, id):
        try:
            profile = self._get_profile(context, id)
            if profile == None:
                return False
            else:
                return True
        except exc.NoResultFound:
            raise cisco_exceptions.ProfileIdNotFound(profile_id=id)

    def _get_segment_range(self, data):
        # Sort the range to ensure min, max is in order
        seg_min, seg_max = sorted(map(int, data.split('-')))
        return (seg_min, seg_max)

    def _validate_vlan(self, p):
        """Validate if vlan falls within segment boundaries."""

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

    def _validate_vxlan(self, p):
        """Validate if vxlan falls within segment boundaries."""

        seg_min, seg_max = self._get_segment_range(p['segment_range'])
        ranges = conf.CISCO_N1K.tunnel_id_ranges
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

    def _validate_segment_range(self, p):
        """Validate segment range values."""

        mo = re.match(r"(\d+)\-(\d+)", p['segment_range'])
        if mo is None:
            msg = _("invalid segment range. example range: 500-550")
            raise q_exc.InvalidInput(error_message=msg)

    def _validate_network_profile(self, p):
        """Validate completeness of a network profile arguments."""

        if any(p[arg] == '' for arg in ('segment_type', 'segment_range')):
            msg = _("arguments segment_type and segment_range missing"
                    " for network profile")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        if p['segment_type'].lower() not in ['vlan', 'vxlan']:
            msg = _("segment_type should either be vlan or vxlan")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        self._validate_segment_range(p)
        if p['segment_type'].lower() == 'vlan':
            self._validate_vlan(p)
            p['multicast_ip_range'] = '0.0.0.0'
        else:
            self._validate_vxlan(p)

    def _validate_segment_range_uniqueness(self, context, p):
        """Validate that segment range doesn't overlap."""

        profiles = self.get_profiles(context)
        for prfl in profiles:
            if p['name'] == prfl['name']:
                msg = _("N1kvProfile_db name %s already exists" % p['name'])
                LOG.exception(msg)
                raise q_exc.InvalidInput(error_message=msg)
            if (p['profile_type'] == 'network') and (prfl['profile_type'] ==
                'network'):
                seg_min, seg_max = self._get_segment_range(p['segment_range'])
                prfl_seg_min, prfl_seg_max = self._get_segment_range(
                    prfl['segment_range'])
                if (((seg_min >= prfl_seg_min) and
                     (seg_min <= prfl_seg_max)) or
                    ((seg_max >= prfl_seg_min) and
                     (seg_max <= prfl_seg_max)) or
                    ((seg_min <= prfl_seg_min) and
                     (seg_max >= prfl_seg_max))):
                    msg = _("segment range overlaps with another profile")
                    LOG.exception(msg)
                    raise q_exc.InvalidInput(error_message=msg)

    def _validate_arguments(self, context, p):
        """Validate completeness of N1kv profile arguments."""

        if p['profile_type'] == 'network':
            self._validate_network_profile(p)
        else:
            p['segment_type'] = ''
            p['segment_range'] = ''
            p['multicast_ip_range'] = ''
        self._validate_segment_range_uniqueness(context, p)
