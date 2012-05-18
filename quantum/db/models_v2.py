import uuid

from sqlalchemy import Column, String, ForeignKey, Integer, Boolean
from sqlalchemy.orm import relation, object_mapper

from quantum.db import model_base

# we can clearly do better than this, but its a simple start
class IP_Allocation(model_base.BASE, model_base.QuantumBase):
    """Internal representation of a IP address allocation in a Quantum subnet"""
    __tablename__ = "ip_allocations"

    port_uuid = Column(String(255), ForeignKey('ports.uuid'))
    address = Column(String(16), nullable=False, primary_key=True)
    subnet_uuid = Column(String(255), ForeignKey('subnets.uuid'),
                         primary_key=True)
    allocated = Column(Boolean(), nullable=False)

    def __init__(self, address, subnet_uuid, allocated=False):
        self.address = address
        self.subnet_uuid = subnet_uuid
        self.allocated = allocated

    def __repr__(self):
        return "<IP_Allocation(%s,%s,%s,%s)>" % \
          (self.address, self.allocated, self.port_uuid, self.subnet_uuid)


class Port(model_base.BASE, model_base.QuantumBase):
    """Represents a port on a quantum v2 network"""
    __tablename__ = 'ports'

    uuid = Column(String(255), primary_key=True)
    tenant_uuid = Column(String(255), nullable=False)
    network_uuid = Column(String(255), ForeignKey("networks.uuid"),
                        nullable=False)
    fixed_ips = relation(IP_Allocation, order_by=IP_Allocation.address,
                         backref="ip_allocations.port_uuid")
    mac_address = Column(String(32), nullable=False)
    admin_state_up = Column(Boolean(), nullable=False)
    op_status = Column(String(16), nullable=False)
    device_uuid = Column(String(255), nullable=False)

    def __init__(self, tenant_uuid, network_uuid, mac_address,
                 admin_state_up, op_status, device_uuid):
        self.uuid = str(uuid.uuid4())
        self.tenant_uuid = tenant_uuid
        self.network_uuid = network_uuid
        self.mac_address = mac_address
        self.admin_state_up = admin_state_up
        self.op_status = op_status
        self.device_uuid = device_uuid

        #TODO(danwent):
        # store customized routes?

    def __repr__(self):
        return "<Port(%s,%s,%s,%s,%s,%s,%s)>" % (self.uuid,
                                                 self.tenant_uuid,
                                                 self.network_id,
                                                 self.mac_address,
                                                 self.fixed_ips,
                                                 self.admin_state_up,
                                                 self.op_status)


class Subnet(model_base.BASE, model_base.QuantumBase):
    """Represents a quantum subnet"""
    __tablename__ = 'subnets'

    uuid = Column(String(255), primary_key=True)
    network_uuid = Column(String(255), ForeignKey('networks.uuid'))
    tenant_uuid = Column(String(255), nullable=False)
    allocations = relation(IP_Allocation, order_by=IP_Allocation.address,
                              backref="ip_allocations.subnet_uuid")
    ip_version = Column(Integer(), nullable=False)
    prefix = Column(String, nullable=False)
    gateway_ip = Column(String)

    #TODO(danwent):
    # - dns_namservers
    # - excluded_ranges
    # - additional_routes
    # - tags

    def __init__(self, tenant_uuid, network_uuid, ip_version, prefix,
                 gateway_ip):
        self.uuid = str(uuid.uuid4())
        self.network_uuid = network_uuid
        self.tenant_uuid = tenant_uuid
        self.ip_version = ip_version
        self.prefix = prefix
        self.gateway_ip = gateway_ip

    def __repr__(self):
        return "<Subnet(%s,%s,%s,%s)>" % \
          (self.uuid, self.ip_version, self.prefix, self.gateway_ip)


class Network(model_base.BASE, model_base.QuantumBase):
    """Represents a v2 quantum network"""
    __tablename__ = 'networks'

    uuid = Column(String(255), primary_key=True)
    tenant_uuid = Column(String(255), nullable=False)
    name = Column(String(255))
    ports = relation(Port, order_by=Port.uuid,
                     backref="ports.network_uuid")
    subnets = relation(Subnet, order_by=Subnet.uuid,
                       backref="subnets.network_uuid")
    op_status = Column(String(16))
    admin_state_up = Column(Boolean)

    def __init__(self, tenant_uuid, name, admin_state_up, op_status):
        self.uuid = str(uuid.uuid4())
        self.tenant_uuid = tenant_uuid
        self.name = name
        self.admin_state_up = admin_state_up
        self.op_status = op_status

    #TOD0(danwent):
    # store tags

    def __repr__(self):
        return "<Network(%s,%s,%s,%s,%s)>" % \
          (self.uuid, self.name, self.op_status, self.tenant_uuid, self.subnets)


