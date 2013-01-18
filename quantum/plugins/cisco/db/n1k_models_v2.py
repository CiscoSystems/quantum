# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Cisco Systems, Inc.
# All Rights Reserved.
#
# @author: Aruna Kushwaha, Cisco Systems, Inc.

import uuid

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String

from quantum.db.models_v2 import model_base


class N1kVlanAllocation(model_base.BASEV2):
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


class N1kTunnelAllocation(model_base.BASEV2):
    """Represents allocation state of tunnel_id"""
    __tablename__ = 'n1kv_tunnel_allocations'

    tunnel_id = Column(Integer, nullable=False, primary_key=True,
        autoincrement=False)
    allocated = Column(Boolean, nullable=False)

    def __init__(self, tunnel_id):
        self.tunnel_id = tunnel_id
        self.allocated = False

    def __repr__(self):
        return "<TunnelAllocation(%d,%s)>" % (self.tunnel_id, self.allocated)

class N1kPortBinding(model_base.BASEV2):
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

class N1kNetworkBinding(model_base.BASEV2):
    """Represents binding of virtual network to physical realization"""
    __tablename__ = 'n1kv_network_bindings'

    network_id = Column(String(36),
        ForeignKey('networks.id', ondelete="CASCADE"),
        primary_key=True)
    # 'vxlan', 'vlan'
    network_type = Column(String(32), nullable=False)
    physical_network = Column(String(64))
    segmentation_id = Column(Integer)  # tunnel_id or vlan_id
    multicast_ip = Column(String(32))  # multicast ip
    profile_id = Column(String(36))  #n1kv profile id

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


class N1kTunnelIP(model_base.BASEV2):
    """Represents tunnel endpoint in DB mode"""
    __tablename__ = 'n1kv_tunnel_ips'

    ip_address = Column(String(255), primary_key=True)

    def __init__(self, ip_address):
        self.ip_address = ip_address

    def __repr__(self):
        return "<TunnelIP(%s)>" % (self.ip_address)


class N1kTunnelEndpoint(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode"""
    __tablename__ = 'n1kv_tunnel_endpoints'

    ip_address = Column(String(64), primary_key=True)
    id = Column(Integer, nullable=False)

    def __init__(self, ip_address, id):
        self.ip_address = ip_address
        self.id = id

    def __repr__(self):
        return "<TunnelEndpoint(%s,%s)>" % (self.ip_address, self.id)


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


class N1kCredential(model_base.BASEV2, L2NetworkBase):
    """Represents credentials for a tenant"""
    __tablename__ = 'n1k_credentials'

    credential_id = Column(String(255))
    tenant_id = Column(String(255), primary_key=True)
    credential_name = Column(String(255), primary_key=True)
    user_name = Column(String(255))
    password = Column(String(255))

    def __init__(self, tenant_id, credential_name, user_name, password):
        self.credential_id = str(uuid.uuid4())
        self.tenant_id = tenant_id
        self.credential_name = credential_name
        self.user_name = user_name
        self.password = password

    def __repr__(self):
        return "<Credentials(%s,%s,%s,%s,%s)>" % (self.credential_id,
                                                  self.tenant_id,
                                                  self.credential_name,
                                                  self.user_name,
                                                  self.password)


class N1kVmNetwork(model_base.BASEV2):
    """Represents VM Network information"""
    __tablename__ = 'vmnetwork'
    
    name = Column(String(255), primary_key=True)
    profile_id = Column(String(36))
    network_id = Column(String(36))

    def __init__(self, name, profile_id, network_id):
        self.name = name
        self.profile_id = profile_id
        self.network_id = network_id

    def __repr__(self):
        return "<VmNetwork(%s,%s,%s)>" % (self.name,
                                          self.profile_id,
                                          self.network_id)                                                                 
