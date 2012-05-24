# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from sqlalchemy import Column, String, ForeignKey, Integer, Boolean
from sqlalchemy.orm import relation

from quantum.db import model_base


class IPAllocation(model_base.BASEV2):
    """Internal representation of a IP address allocation in a Quantum
       subnet
    """
    port_uuid = Column(String(255), ForeignKey('ports.uuid'))
    address = Column(String(16), nullable=False, primary_key=True)
    subnet_uuid = Column(String(255), ForeignKey('subnets.uuid'),
                         primary_key=True)
    allocated = Column(Boolean(), nullable=False)


class Port(model_base.BASEV2):
    """Represents a port on a quantum v2 network"""
    tenant_uuid = Column(String(255), nullable=False)
    network_uuid = Column(String(255), ForeignKey("networks.uuid"),
                        nullable=False)
    fixed_ips = relation(IPAllocation, order_by=IPAllocation.address,
                         backref="ip_allocations.port_uuid")
    mac_address = Column(String(32), nullable=False)
    admin_state_up = Column(Boolean(), nullable=False)
    op_status = Column(String(16), nullable=False)
    device_uuid = Column(String(255), nullable=False)


class Subnet(model_base.BASEV2):
    """Represents a quantum subnet"""
    network_uuid = Column(String(255), ForeignKey('networks.uuid'))
    tenant_uuid = Column(String(255), nullable=False)
    allocations = relation(IPAllocation, order_by=IPAllocation.address,
                              backref="ip_allocations.subnet_uuid")
    ip_version = Column(Integer(), nullable=False)
    prefix = Column(String, nullable=False)
    gateway_ip = Column(String)

    #TODO(danwent):
    # - dns_namservers
    # - excluded_ranges
    # - additional_routes
    # - tags


class Network(model_base.BASEV2):
    """Represents a v2 quantum network"""
    tenant_uuid = Column(String(255), nullable=False)
    name = Column(String(255))
    ports = relation(Port, order_by=Port.uuid,
                     backref="ports.network_uuid")
    subnets = relation(Subnet, order_by=Subnet.uuid,
                       backref="subnets.network_uuid")
    op_status = Column(String(16))
    admin_state_up = Column(Boolean)
