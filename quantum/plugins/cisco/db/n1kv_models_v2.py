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
# @author: Aruna Kushwaha, Cisco Systems, Inc.
# @author: Abhishek Raut, Cisco Systems, Inc.

import logging

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum

from quantum.db.models_v2 import model_base, HasId
from quantum.plugins.cisco.common import cisco_exceptions
from sqlalchemy.orm import exc

LOG = logging.getLogger(__name__)
SEGMENT_TYPE_VLAN = 'vlan'
SEGMENT_TYPE_VXLAN = 'vxlan'
SEGMENT_TYPE = Enum(SEGMENT_TYPE_VLAN, SEGMENT_TYPE_VXLAN)
PROFILE_TYPE = Enum('network', 'policy')
# use this to indicate that tenant_id was not yet set
TENANT_ID_NOT_SET = '01020304-0506-0708-0901-020304050607'


class N1kvVlanAllocation(model_base.BASEV2):
    """Represents allocation state of vlan_id on physical network"""
    __tablename__ = 'n1kv_vlan_allocations'

    physical_network = Column(String(64), nullable=False, primary_key=True)
    vlan_id = Column(Integer, nullable=False, primary_key=True,
        autoincrement=False)
    allocated = Column(Boolean, nullable=False)

    def __init__(self, physical_network, vlan_id):
        self.physical_network = physical_network
        self.vlan_id = vlan_id
        self.allocated = False

    def __repr__(self):
        return "<VlanAllocation(%s,%d,%s)>" % (self.physical_network,
                                               self.vlan_id, self.allocated)


class N1kvVxlanAllocation(model_base.BASEV2):
    """Represents allocation state of vxlan_id"""
    __tablename__ = 'n1kv_vxlan_allocations'

    vxlan_id = Column(Integer, nullable=False, primary_key=True,
        autoincrement=False)
    allocated = Column(Boolean, nullable=False)

    def __init__(self, vxlan_id):
        self.vxlan_id = vxlan_id
        self.allocated = False

    def __repr__(self):
        return "<VxlanAllocation(%d,%s)>" % (self.vxlan_id, self.allocated)


class N1kvPortBinding(model_base.BASEV2):
    """Represents binding of ports"""
    __tablename__ = 'n1kv_port_bindings'

    port_id = Column(String(36),
        ForeignKey('ports.id', ondelete="CASCADE"),
        primary_key=True)
    profile_id = Column(String(36))

    def __init__(self, port_id, profile_id):
        self.port_id = port_id
        self.profile_id = profile_id

    def __repr__(self):
        return "<PortBinding(%s,%s)>" % (self.port_id,
                                         self.profile_id)


class N1kvNetworkBinding(model_base.BASEV2):
    """Represents binding of virtual network to physical realization"""
    __tablename__ = 'n1kv_network_bindings'

    network_id = Column(String(36),
        ForeignKey('networks.id', ondelete="CASCADE"),
        primary_key=True)
    # 'vxlan', 'vlan'
    network_type = Column(String(32), nullable=False)
    physical_network = Column(String(64))
    segmentation_id = Column(Integer)  # vxlan_id or vlan_id
    multicast_ip = Column(String(32))  # multicast ip
    profile_id = Column(String(36))  # n1kv profile id

    def __init__(self, network_id, network_type, physical_network,
                 segmentation_id, multicast_ip, profile_id):
        self.network_id = network_id
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.multicast_ip = multicast_ip
        self.profile_id = profile_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s,%s,%d %x %s)>" % (self.network_id,
                                                  self.network_type,
                                                  self.physical_network,
                                                  self.segmentation_id,
                                                  self.multicast_ip,
                                                  self.profile_id)


class N1kvVxlanIP(model_base.BASEV2):
    """Represents vxlan endpoint in DB mode"""
    __tablename__ = 'n1kv_vxlan_ips'

    ip_address = Column(String(255), primary_key=True)

    def __init__(self, ip_address):
        self.ip_address = ip_address

    def __repr__(self):
        return "<VxlanIP(%s)>" % (self.ip_address)


class N1kvVxlanEndpoint(model_base.BASEV2):
    """Represents vxlan endpoint in RPC mode"""
    __tablename__ = 'n1kv_vxlan_endpoints'

    ip_address = Column(String(64), primary_key=True)
    id = Column(Integer, nullable=False)

    def __init__(self, ip_address, id):
        self.ip_address = ip_address
        self.id = id

    def __repr__(self):
        return "<VxlanEndpoint(%s,%s)>" % (self.ip_address, self.id)


class L2NetworkBase(object):
    """Base class for L2Network Models."""
    #__table_args__ = {'mysql_engine': 'InnoDB'}

    def __setitem__(self, key, value):
        """Internal Dict set method"""
        setattr(self, key, value)

    def __getitem__(self, key):
        """Internal Dict get method"""
        return getattr(self, key)

    def get(self, key, default=None):
        """Dict get method"""
        return getattr(self, key, default)

    def __iter__(self):
        """Iterate over table columns"""
        self._i = iter(object_mapper(self).columns)
        return self

    def next(self):
        """Next method for the iterator"""
        n = self._i.next().name
        return n, getattr(self, n)

    def update(self, values):
        """Make the model object behave like a dict"""
        for k, v in values.iteritems():
            setattr(self, k, v)

    def iteritems(self):
        """Make the model object behave like a dict"
        Includes attributes from joins."""
        local = dict(self)
        joined = dict([(k, v) for k, v in self.__dict__.iteritems()
                       if not k[0] == '_'])
        local.update(joined)
        return local.iteritems()


class N1kVmNetwork(model_base.BASEV2):
    """Represents VM Network information"""
    __tablename__ = 'vmnetwork'

    name = Column(String(255), primary_key=True)
    profile_id = Column(String(36))
    network_id = Column(String(36))
    port_count = Column(Integer)

    def __init__(self, name, profile_id, network_id, port_count):
        self.name = name
        self.profile_id = profile_id
        self.network_id = network_id
        self.port_count = port_count

    def __repr__(self):
        return "<VmNetwork(%s,%s,%s,%s)>" % (self.name,
                                          self.profile_id,
                                          self.network_id,
                                          self.port_count)


class NetworkProfile(model_base.BASEV2, HasId):
    """
    Nexus1000V Network Profiles

        segment_type - VLAN, VXLAN
        segment_range - '<integer>-<integer>'
        multicast_ip_index - <integer>
        multicast_ip_range - '<ip>-<ip>'
    """
    __tablename__ = 'network_profiles'

    name = Column(String(255))
    segment_type = Column(SEGMENT_TYPE, nullable=False)
    segment_range = Column(String(255))
    multicast_ip_index = Column(Integer)
    multicast_ip_range = Column(String(255))

    def get_segment_range(self, session):
        """Get the segment range min and max for a network profile."""
        with session.begin(subtransactions=True):
            # Sort the range to ensure min, max is in order
            seg_min, seg_max = sorted(map(int, self.segment_range.split('-')))
            LOG.debug("NetworkProfile: seg_min %s seg_max %s", seg_min, seg_max)
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
                raise cisco_exceptions.NetworkProfileIdNotFound(profile_id=id)

    def _get_multicast_ip_range(self):
        # Assumption: ip range belongs to the same subnet
        # Assumption: ip range is already sorted
        #min_ip, max_ip = sorted(self.multicast_ip_range.split('-'))
        min_ip, max_ip = self.multicast_ip_range.split('-')
        return (min_ip, max_ip)

    def __init__(self, name, segment_type, segment_range=None, mcast_ip_index=None, mcast_ip_range=None):
        self.name = name
        self.segment_type = segment_type
        self.segment_range = segment_range
        self.multicast_ip_index = mcast_ip_index or 0
        self.multicast_ip_range = mcast_ip_range

    def __repr__(self):
        return "<NetworkProfile (%s, %s, %s, %d, %s)>" % (self.id, self.name, self.segment_type,
                                                          self.multicast_ip_index, self.multicast_ip_range)


class PolicyProfile(model_base.BASEV2):
    """
    Nexus1000V Network Profiles

        Both 'id' and 'name' are coming from Nexus1000V switch
    """
    __tablename__ = 'policy_profiles'

    id = Column(String(36), primary_key=True)
    name = Column(String(255))

    def __init__(self, id, name):
        self.id = id
        self.name = name

    def __repr__(self):
        return "<PolicyProfile (%s, %s)>" % (self.id, self.name)


class ProfileBinding(model_base.BASEV2):
    """ Represents a binding of Network Profile or Policy Profile to tenant_id"""
    __tablename__ = 'profile_bindings'

    profile_type = Column(PROFILE_TYPE)
    tenant_id = Column(String(36), primary_key=True, default=TENANT_ID_NOT_SET)
    profile_id = Column(String(36), primary_key=True)

    def __init__(self, profile_type, tenant_id, profile_id):
        self.profile_type = profile_type
        self.tenant_id = tenant_id
        self.profile_id = profile_id

    def __repr__(self):
        return "<ProfileBinding (%s, %s, %s)>" % (self.profile_type, self.tenant_id, self.profile_id)
