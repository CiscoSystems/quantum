from sqlalchemy.orm import exc

from quantum.common import exceptions as q_exc
import quantum.db.api as db
from quantum.openstack.common import log as logging
from quantum.plugins.opendaylight import odl_models

LOG = logging.getLogger(__name__)


def initialize():
    db.configure_db()


def get_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(odl_models.NetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_network_binding(session, network_id, network_type,
                        segmentation_id):
    session = session or db.get_session()
    with session.begin(subtransactions=True):
        binding = odl_models.NetworkBinding(network_id, network_type,
                                            segmentation_id)
        session.add(binding)


def del_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(odl_models.NetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        session.delete(binding)
    except:
        raise

def allocate_network_segment(session, network_id, network_type, seg_range):
    session = session or db.get_session()
    # Get a free network segment in the range specified
    bindings = session.query(odl_models.NetworkBinding).\
               filter_by(network_type=network_type).\
               all()

    allocated_ids = []
    for binding in bindings:
        allocated_ids.append(binding.segmentation_id)

    # Find a segment in range that's not allocated
    (seg_min, seg_max) = seg_range.split(':')
    allocated_segment = None
    for segment in range(int(seg_min), int(seg_max)):
        if segment not in allocated_ids:
            allocated_segment = segment
            break

    if allocated_segment:
        add_network_binding(session, network_id, network_type, allocated_segment)
    else:
        raise "No usable segment id found"
