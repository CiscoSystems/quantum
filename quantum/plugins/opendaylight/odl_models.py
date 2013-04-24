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
