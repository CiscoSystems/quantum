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

from sqlalchemy.orm import exc

import quantum.db.api as db
from quantum.db import models_v2
from quantum.db import securitygroups_db as sg_db
from quantum.extensions import securitygroup as ext_sg
from quantum import manager
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
    except exc.NoResultFound:
        LOG.debug(_("Segmentation binding not found"))
    except Exception:
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
        add_network_binding(session, network_id, network_type,
                            allocated_segment)
    else:
        raise "No usable segment id found"


def get_port_from_device(port_id):
    """Get port from database."""
    LOG.debug(_("get_port_with_securitygroups() called:port_id=%s"), port_id)
    session = db.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    query = session.query(models_v2.Port,
                          sg_db.SecurityGroupPortBinding.security_group_id)
    query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                            models_v2.Port.id == sg_binding_port)
    query = query.filter(models_v2.Port.id == port_id)
    port_and_sgs = query.all()
    if not port_and_sgs:
        return None
    port = port_and_sgs[0][0]
    plugin = manager.QuantumManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict[ext_sg.SECURITYGROUPS] = [
        sg_id for port_, sg_id in port_and_sgs if sg_id]
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict


def add_port_flow(session, flow_id, port_id, flow_type, sec_group_rule=None):
    session = session or db.get_session()

    binding = odl_models.Flow(flow_id, port_id, flow_type, sec_group_rule)
    session.add(binding)
    session.flush()


def del_port_flow(session, flow_id):
    session = session or db.get_session()

    try:
        binding = (session.query(odl_models.Flow).
                   filter_by(flow_id=flow_id).
                   one())
        session.delete(binding)
        session.flush()
    except Exception:
        raise


def get_port_flows(session, port_id):
    session = session or db.get_session()

    try:
        bindings = (session.query(odl_models.Flow).
                    filter_by(port_id=port_id).
                    all())
        return bindings
    except Exception:
        raise


def add_ovs_port(session, port_id, of_port_id, vif_id):
    session = session or db.get_session()
    try:
        binding = odl_models.OvsPort(port_id, int(of_port_id), vif_id)
        session.add(binding)
        session.flush()
    except Exception:
        raise


def del_ovs_port(session, port_id):
    session = session or db.get_session()

    try:
        binding = (session.query(odl_models.OvsPort).
                   filter_by(port_id=port_id).
                   one())
        session.delete(binding)
        session.flush()
    except Exception:
        raise


def get_ovs_port(session, port_id):
    session = session or db.get_session()

    binding = (session.query(odl_models.OvsPort).
               filter_by(port_id=port_id).
               one())
    return binding
