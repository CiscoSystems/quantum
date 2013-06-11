# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Arvind Somya, Cisco Systems, Inc.
# @author: Kyle Mestery, Cisco Systems, Inc.

from sqlalchemy import Column, ForeignKey, Integer, String

from quantum.db.models_v2 import model_base


class NetworkBinding(model_base.BASEV2):
    """Represents binding of virtual network to physical realization."""
    __tablename__ = 'odl_network_bindings'

    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)
    network_type = Column(String(32), nullable=False)
    segmentation_id = Column(Integer)

    def __init__(self, network_id, network_type,
                 segmentation_id):
        self.network_id = network_id
        self.network_type = network_type
        self.segmentation_id = segmentation_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s,%d)>" % (self.network_id,
                                               self.network_type,
                                               self.segmentation_id)


class Flow(model_base.BASEV2):
    """Represents a flow installed on the ODL controller"""
    __tablename__ = 'odl_flows'

    flow_id = Column(String(36),
                     primary_key=True)
    port_id = Column(String(36), nullable=False)
    flow_type = Column(String(36), nullable=False)
    sec_group_rule = Column(String(36), nullable=True)

    def __init__(self, flow_id, port_id, flow_type, sec_group_rule):
        self.flow_id = flow_id
        self.port_id = port_id
        self.flow_type = flow_type
        self.sec_group_rule = sec_group_rule

    def __repr__(self):
        return "<Flows(%s,%s,%s,%s)>" % (self.flow_id,
                                         self.port_id,
                                         self.flow_type,
                                         self.sec_group_rule)


class OvsPort(model_base.BASEV2):
    """Represents openvswitch port information."""
    __tablename__ = 'odl_ovs_ports'

    port_id = Column(String(36),
                     ForeignKey('ports.id', ondelete="CASCADE"),
                     primary_key=True)
    of_port_id = Column(Integer)
    vif_id = Column(String(36), nullable=False)

    def __init__(self, port_id, of_port_id, vif_id):
        self.port_id = port_id
        self.of_port_id = of_port_id
        self.vif_id = vif_id

    def __repr__(self):
        return "<OvsPort(%s,%d,%s)>" % (self.port_id,
                                        self.of_port_id,
                                        self.vif_id)
