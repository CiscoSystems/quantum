from sqlalchemy import Column, ForeignKey, Integer, String

from quantum.db.models_v2 import model_base

class NetworkBinding(model_base.BASEV2):
    """Represents binding of virtual network to physical realization"""
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
