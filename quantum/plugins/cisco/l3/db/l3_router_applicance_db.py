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
# @author: Bob Melander, Cisco Systems, Inc.

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy import and_
from sqlalchemy import orm
from sqlalchemy import func
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload

from keystoneclient.v2_0 import client as k_client
from keystoneclient import exceptions as k_exceptions

#from quantum.api.v2 import attributes
#from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum import context as q_context
#from quantum.common import utils
from quantum.common import constants as l3_constants
from quantum.common import exceptions as q_exc
from quantum.db import agents_db
from quantum.db import extraroute_db
from quantum.db import l3_db
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import trunkport
from quantum.plugins.cisco.l3.common import service_vm_lib
from quantum.plugins.cisco.l3.common import l3_rpc_joint_agent_api
from quantum.plugins.cisco.l3.common import constants as cl3_const
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.openstack.common import timeutils


LOG = logging.getLogger(__name__)


#TODO(bob-melander): Update this for the N1kv plugin
TRUNKED_NETWORKS = trunkport.TRUNKED_NETWORKS

#TODO(bob-melander): Revisit these configurations to remove
#some if possible
router_appliance_opts = [
    cfg.StrOpt('l3_admin_tenant', default='L3AdminTenant',
               help=_("Name of the L3 admin tenant")),
    cfg.StrOpt('default_router_type', default='CSR1kv',
               help=_("Default type of router to create")),
    cfg.StrOpt('csr1kv_flavor', default='csr1kv_router',
               help=_("Nova flavor used for CSR1kv VM")),
    cfg.StrOpt('csr1kv_image', default='csr1kv_image',
               help=_("Glance image used for CSR1kv VM")),
    cfg.StrOpt('management_network', default='osn_mgmt_nw',
               help=_("Name of management network for CSR VM configuration")),
    cfg.StrOpt('hosting_scheduler_driver',
               default='quantum.plugins.cisco.l3.scheduler.'
                       'l3_hosting_entity_scheduler.L3HostingEntityScheduler',
               help=_('Driver to use for scheduling router to a hosting '
                      'entity')),
    cfg.StrOpt('max_routers_per_csr1kv', default=3,
               help=_("The maximum number of logical routers a CSR1kv VM "
                      "instance will host")),
    cfg.StrOpt('standby_pool_size', default=2,
               help=_("The number of running CSR1kv VMs to maintain "
                      "as a pool of standby VMs")),
    cfg.StrOpt('csr1kv_booting_time', default=300,
               help=_("The time in seconds it typically takes to "
                      "boot a CSR1kv VM"))
]

# Segmentation types
VLAN_SEGMENTATION = 'VLAN'

MIN_LL_VLAN_TAG = 10
MAX_LL_VLAN_TAG = 200
FULL_VLAN_SET = set(range(MIN_LL_VLAN_TAG, MAX_LL_VLAN_TAG))

cfg.CONF.register_opts(router_appliance_opts)


class RouterCreateInternalError(q_exc.QuantumException):
    message = _("Router could not be created due to internal error.")


class RouterInternalError(q_exc.QuantumException):
    message = _("Internal error during router processing.")


class RouterBindingInfoError(q_exc.QuantumException):
    message = _("Could not get binding information for router %(router_id)s.")


class HostingEntity(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an appliance hosting OsN router(s). When the
       hosting entity is a Nova VM 'id' is uuid of that OsC VM."""
    __tablename__ = 'hostingentities'

    admin_state_up = sa.Column(sa.Boolean, nullable=False, default=True)
    # 'host_type' can be 'NetworkNamespaceNode', 'CSR1kv', ...
    host_type = sa.Column(sa.String(255), nullable=False)
    # 'ip_address' is address of hosting entity's management interface
    ip_address = sa.Column(sa.String(64), nullable=False)
    # 'transport_port' is udp/tcp port of hosting entity. May be empty.
    transport_port = sa.Column(sa.Integer)
    l3_cfg_agent_id = sa.Column(sa.String(36),
                                sa.ForeignKey('agents.id'),
                                nullable=True)
    l3_cfg_agent = orm.relationship(agents_db.Agent)
    # Service VMs take time to boot so we store creation time
    # so we can give preference to older ones when scheduling
    created_at = sa.Column(sa.DateTime, nullable=False)
    status = sa.Column(sa.String(16))
    # 'tenant_bound' is empty or is id of the only tenant allowed to
    # own/place resources on this hosting entity
    tenant_bound = sa.Column(sa.String(255))


class RouterHostingEntityBinding(model_base.BASEV2):
    """Represents binding between OsN routers and
       their hosting entities"""
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          primary_key=True)
    router = orm.relationship(l3_db.Router)
    # 'router_type' can be 'NetworkNamespace', 'CSR1kv', ...
    router_type = sa.Column(sa.String(255), nullable=False)
    share_hosting_entity = sa.Column(sa.Boolean, default=True, nullable=False)
    hosting_entity_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('hostingentities.id',
                                                ondelete='SET NULL'))
    hosting_entity = orm.relationship(HostingEntity)


class TrunkInfo(model_base.BASEV2):
    """Represents trunking info for a router port."""
    router_port_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ports.id',
                                             ondelete="CASCADE"),
                               primary_key=True)
    router_port = orm.relationship(models_v2.Port,
                                   primaryjoin='Port.id==TrunkInfo.'
                                               'router_port_id',
                                   backref=orm.backref('trunk_info',
                                                       cascade='all',
                                                       uselist=False))
    hosting_port_id = sa.Column(sa.String(36),
                                sa.ForeignKey('ports.id',
                                              ondelete='SET NULL'))
    hosting_port = orm.relationship(models_v2.Port,
                                    primaryjoin='Port.id==TrunkInfo.'
                                                'hosting_port_id')
    segmentation_tag = sa.Column(sa.Integer,
                                 autoincrement=False)


class L3_router_appliance_db_mixin(extraroute_db.ExtraRoute_db_mixin):
    """ Mixin class to support router appliances to implement Quantum's
        L3 routing functionality """

    _mgmt_nw_uuid = None
    _l3_tenant_uuid = None
    _svc_vm_mgr = None

    hosting_scheduler = None

    @classmethod
    def l3_tenant_id(cls):
        if cls._l3_tenant_uuid is None:
            endpoint = (cfg.CONF.keystone_authtoken.auth_protocol + "://" +
                        cfg.CONF.keystone_authtoken.auth_host + ":" +
                        str(cfg.CONF.keystone_authtoken.auth_port) + "/v2.0")
            keystone = k_client.Client(token="simple",
                                       endpoint=endpoint)
            try:
                tenant = keystone.tenants.find(name=cfg.CONF.l3_admin_tenant)
                cls._l3_tenant_uuid = tenant.id
            except k_exceptions.NotFound:
                LOG.error(_('No tenant with a name or ID of %s exists.'),
                            cfg.CONF.l3_admin_tenant)
            except k_exceptions.NoUniqueMatch:
                LOG.error(_('Multiple tenants matches found for %s'),
                            cfg.CONF.l3_admin_tenant)
        return cls._l3_tenant_uuid

    @classmethod
    def mgmt_nw_id(cls):
        if cls._mgmt_nw_uuid is None:
            tenant_id=cls.l3_tenant_id()
            if not tenant_id:
                return None
            net = manager.QuantumManager.get_plugin().get_networks(
                q_context.get_admin_context(),
                {'tenant_id': [tenant_id],
                 'name': [cfg.CONF.management_network]},
                ['id', 'subnets'])
            if len(net) == 1:
                num_subnets = len(net[0]['subnets'])
                if num_subnets == 0:
                    LOG.error(_('The virtual management network has no'
                                'subnet. Please refer to admin guide and '
                                'assign one'))
                    return
                elif num_subnets > 1:
                     LOG.info(_('The virtual management network has %s'
                                'subnets. The first one will be used.'),
                              num_subnets)
                cls._mgmt_nw_uuid = net[0].get('id')
            elif len(net) > 1:
                # Management network must have a unique name.
                LOG.error(_('The virtual management network for CSR1kv VMs '
                            'does not have unique name. Please refer to '
                            'admin guide and create one.'))
            else:
                # Management network has not been created.
                LOG.error(_('There is no virtual management network for '
                            'CSR1kv VMs. Please refer to admin guide and '
                            'create one.'))
        return cls._mgmt_nw_uuid

    @classmethod
    def svc_vm_mgr(cls):
        if cls._svc_vm_mgr is None:
            cls._svc_vm_mgr = service_vm_lib.ServiceVMManager()
        return cls._svc_vm_mgr

    def create_router(self, context, router):
        r = router['router']
        # Bob: Hard coding router type to shared CSR1kv for now
        r['router_type'] = cfg.CONF.default_router_type
        r['share_host'] = True
        if (r['router_type'] != cl3_const.NAMESPACE_ROUTER_TYPE and
                self.mgmt_nw_id()) is None:
            raise RouterCreateInternalError()
        router_created = (super(L3_router_appliance_db_mixin, self).
            create_router(context, router))

        with context.session.begin(subtransactions=True):
            r_he_b_db = RouterHostingEntityBinding(
                router_id=router_created['id'],
                router_type=r.get('router_type',
                                  cfg.CONF.default_router_type),
                share_hosting_entity=r.get('share_host', True),
                hosting_entity_id=None)
            context.session.add(r_he_b_db)
        return router_created

    def update_router(self, context, id, router):
        r = router['router']
        # Check if external gateway has changed so we may have to
        # update trunking
        new_ext_gw = r.get(l3_db.EXTERNAL_GW_INFO, {}).get('network_id', '')
        o_r_db = self._get_router(context, id)
        if o_r_db.gw_port is None:
            old_ext_gw = ''
            trunk_network_id = None
        else:
            old_ext_gw = o_r_db.gw_port.network_id
            trunk_network_id = self._get_trunk_network_id(context,
                                                          o_r_db.gw_port)
        ext_gateway_changed = False if old_ext_gw == new_ext_gw else True
        router_updated = (
            super(L3_router_appliance_db_mixin, self).update_router(context,
                                                                    id,
                                                                    router))
        routers = self.get_sync_data_ext(context.elevated(), [id],
                                         ext_gw_changed=ext_gateway_changed,
                                         gw_trunk_network_id=trunk_network_id)
        l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(context,
                                                                  routers)
        return router_updated

    def delete_router(self, context, id):
        # Collect info needed after parent has deleted router
        r_he_b = self.get_router_binding_info(context, id)
        router = self._make_router_dict(r_he_b.router,
                                        process_extensions=False)
        self._add_type_and_hosting_info(context, router,
                                        binding_info=r_he_b,
                                        schedule=False)
        trk_nw_id = self._get_trunk_network_id(context, r_he_b.router.gw_port)
        hosting_entity = r_he_b.hosting_entity
        super(L3_router_appliance_db_mixin, self).delete_router(context, id)
        if router['router_type'] != cl3_const.NAMESPACE_ROUTER_TYPE:
            self._cleanup_gateway_configurations(context, router, trk_nw_id)
            self.hosting_scheduler.unschedule_router_from_hosting_entity(
                self, context, router, hosting_entity)
        l3_rpc_joint_agent_api.L3JointAgentNotify.router_deleted(context,
                                                                 router)

    def _cleanup_gateway_configurations(self, context, router, trunk_nw_id):
        if router['router_type'] != cl3_const.CSR_ROUTER_TYPE:
            return
        if trunk_nw_id is None:
            return
        self._update_trunking_on_hosting_port(context, trunk_nw_id, {})

    def add_router_interface(self, context, router_id, interface_info):
        info = (super(L3_router_appliance_db_mixin, self).
            add_router_interface(context, router_id, interface_info))
        routers = self.get_sync_data_ext(context.elevated(), [router_id],
                                     interfaces_changed=True)
        new_port_db = self._get_port(context, info['port_id'])
        l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(
            context, routers, 'add_router_interface',
            {'network_id': new_port_db['network_id'],
             'subnet_id': info['subnet_id']})
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port_db = self._get_port(context, interface_info['port_id'])
            net_id = port_db['network_id']
        elif 'subnet_id' in interface_info:
            subnet_db = self._get_subnet(context, interface_info['subnet_id'])
            port_db = self._get_router_port_db_on_subnet(context, router_id,
                                                         subnet_db)
            net_id = subnet_db['network_id']
        else:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)

        trunk_network_id = self._get_trunk_network_id(context, port_db)

        info = (super(L3_router_appliance_db_mixin, self).
                remove_router_interface(context, router_id, interface_info))
        routers = self.get_sync_data_ext(context.elevated(), [router_id],
                                         interfaces_changed=True,
                                         int_trunk_network_id=trunk_network_id)
        l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(
            context, routers, 'remove_router_interface',
            {'network_id': net_id,
             'subnet_id': info['subnet_id']})
        return info

    def create_floatingip(self, context, floatingip):
        info = super(L3_router_appliance_db_mixin, self).create_floatingip(
            context, floatingip)
        if info['router_id']:
            routers = self.get_sync_data_ext(context.elevated(),
                                             [info['router_id']])
            l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(
                context, routers, 'create_floatingip')

    def update_floatingip(self, context, id, floatingip):
        orig_fl_ip = super(L3_router_appliance_db_mixin, self).get_floatingip(
            context, id)
        before_router_id = orig_fl_ip['router_id']
        info = super(L3_router_appliance_db_mixin, self).update_floatingip(
            context, id, floatingip)

        router_ids = []
        if before_router_id:
            router_ids.append(before_router_id)
        router_id = info['router_id']
        if router_id and router_id != before_router_id:
            router_ids.append(router_id)
        routers = self.get_sync_data_ext(context.elevated(), router_ids)
        l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(
            context, routers, 'update_floatingip')

    def delete_floatingip(self, context, id):
        floatingip_db = self._get_floatingip(context, id)
        router_id = floatingip_db['router_id']
        super(L3_router_appliance_db_mixin, self).delete_floatingip(
            context, id)
        if router_id:
            routers = self.get_sync_data_ext(context.elevated(), [router_id])
            l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(
                context, routers, 'delete_floatingip')

    def disassociate_floatingips(self, context, port_id):
        with context.session.begin(subtransactions=True):
            try:
                fip_qry = context.session.query(l3_db.FloatingIP)
                floating_ip = fip_qry.filter_by(fixed_port_id=port_id).one()
                router_id = floating_ip['router_id']
                floating_ip.update({'fixed_port_id': None,
                                    'fixed_ip_address': None,
                                    'router_id': None})
            except exc.NoResultFound:
                return
            except exc.MultipleResultsFound:
                # should never happen
                raise Exception(_('Multiple floating IPs found for port %s')
                                % port_id)
        if router_id:
            routers = self.get_sync_data_ext(context.elevated(), [router_id])
            l3_rpc_joint_agent_api.L3JointAgentNotify.routers_updated(context,
                                                                      routers)

    def get_router_type(self, context, id):
        r_he_b = self.get_router_binding_info(context, id, load_he_info=False)

        return r_he_b.router_type

    def create_csr1kv_vm_hosting_entities(self, context, num,
                                          tenant_bound=None):
        """Creates a number of CSR1kv VM instances that will act as
        routing service VM. These hosting entities can be bound to
        a certain tenant or for shared use. A list with the created
        hosting entity CSR1kv VMs is returned.
        """
        svm = self.svc_vm_mgr()
        hosting_entities = []
        with context.session.begin(subtransactions=True):
            # These resources are owned by the L3AdminTenant
            birth_date = timeutils.utcnow()
            for i in xrange(0, num):
                # mgmt_port, t1_n, t1_p, t2_n, t2_p = (
                #     svm.create_service_vm_resources(
                #         self.mgmt_nw_id(),
                #         self.l3_tenant_id(),
                #         cfg.CONF.max_routers_per_csr1kv))
                # if mgmt_port is None:
                #     # Required ports could not be created
                #     return hosting_entities
                mgmt_port, t1_n, t1_p, t2_n, t2_p = None, [], [], [], []
                host_ent = svm.dispatch_service_vm(cfg.CONF.csr1kv_image,
                                                   cfg.CONF.csr1kv_flavor,
                                                   mgmt_port,
                                                   ports=t1_p+t2_p)
                if host_ent is not None:
                    hosting_entities.append(host_ent)
                    he_db = HostingEntity(
                        id=host_ent['id'],
                        tenant_id=self.l3_tenant_id(),
                        admin_state_up=True,
                        host_type=cl3_const.CSR1KV_HOST,
                        ip_address='10.0.100.5',
#                        ip_address=mgmt_port['fixed_ips'][0]['ip_address'],
                        transport_port=cl3_const.CSR1kv_SSH_NETCONF_PORT,
                        l3_cfg_agent_id=None,
                        created_at=birth_date,
                        status=None,
                        tenant_bound=tenant_bound)
                    context.session.add(he_db)
                else:
                    # Fundamental error like could not contact Nova
                    # Cleanup anything we created
                    svm.cleanup_for_service_vm(mgmt_port, t1_n, t2_n,
                                               t1_p, t2_p)
                    return hosting_entities
        return hosting_entities

    def delete_service_vm_hosting_entities(self, context, num,
                                           host_type=cl3_const.CSR1KV_HOST,
                                           tenant_bound=None):
        """Deletes <num> or less unused service VM instances that act as
        <host_type> hosting entities (for a certain tenant or for shared
        use). The number of deleted service vm instances is returned.
        """
        # Delete the "youngest" hosting entities since they are
        # more likely to not have finished booting
        query = context.session.query(HostingEntity)
        query = query.outerjoin(
            RouterHostingEntityBinding,
            HostingEntity.id==RouterHostingEntityBinding.hosting_entity_id)
        query = query.filter(and_(HostingEntity.host_type == host_type,
                                  HostingEntity.admin_state_up == True,
                                  HostingEntity.tenant_bound == None))
        query = query.group_by(HostingEntity.id)
        query = query.having(
            func.count(RouterHostingEntityBinding.router_id) == 0)
        query = query.order_by(
            HostingEntity.created_at.desc(),
            func.count(RouterHostingEntityBinding.router_id))
        he_candidates = query.all()
        svm = self.svc_vm_mgr()
        num_deleted = 0
        num_possible_to_delete = min(len(he_candidates), num)
        with context.session.begin(subtransactions=True):
            for i in xrange(0, num_possible_to_delete):
                if svm.delete_service_vm(he_candidates[i],
                                         self.mgmt_nw_id(),
                                         delete_networks=True):
                    context.session.delete(he_candidates[i])
                    num_deleted += 1
        return num_deleted

    def get_router_binding_info(self, context, id, load_he_info=True):
        query = context.session.query(RouterHostingEntityBinding)
        if load_he_info:
            query = query.options(joinedload('hosting_entity'))
        query = query.filter(RouterHostingEntityBinding.router_id == id)
        try:
            r_he_b = query.one()
            return r_he_b
        except exc.NoResultFound:
            # This should not happen
            LOG.error(_('DB inconsistency: No type and hosting info associated'
                        ' with router %s'), id)
            raise RouterBindingInfoError(router_id=id)
        except exc.MultipleResultsFound:
            # This should not happen either
            LOG.error(_('DB inconsistency: Multiple type and hosting info'
                        ' associated with router %s'), id)
            raise RouterBindingInfoError(router_id=id)

    def get_hosting_entities(self, context, hosting_entity_ids):
        query = context.session.query(HostingEntity)
        if len(hosting_entity_ids) > 1:
            query = query.options(joinedload('l3_cfg_agent')).filter(
                HostingEntity.id.in_(hosting_entity_ids))
        else:
            query = query.options(joinedload('l3_cfg_agent')).filter(
                HostingEntity.id == hosting_entity_ids[0])
        return query.all()

    def host_router(self, context, router_id):
        """Schedules non-hosted router(s) on hosting entities.
        If <router_id> is given, then only the router with that id is
        scheduled (if it is non-hosted). If no <router_id> is given,
        then all non-hosted routers are scheduled.
        """
        if self.hosting_scheduler is None:
            return
        query = context.session.query(RouterHostingEntityBinding)
        query = query.filter(
            RouterHostingEntityBinding.router_type !=
            cl3_const.NAMESPACE_ROUTER_TYPE,
            RouterHostingEntityBinding.hosting_entity == None)
        if router_id:
            query = query.filter(
                RouterHostingEntityBinding.router_id == router_id)
        for r_he_binding in query:
            router = self._make_router_dict(r_he_binding.router,
                                            process_extensions=False)
            router['router_type'] = r_he_binding['router_type']
            router['share_host'] = r_he_binding['share_hosting_entity']
            self.hosting_scheduler.schedule_router_on_hosting_entity(
                self, context, router, r_he_binding)

    # Make parent's call to get_sync_data(...) a noop
    def get_sync_data(self, context, router_ids=None, active=None):
        return []

    def get_sync_data_ext(self, context, router_ids=None, active=None,
                          ext_gw_changed=False, gw_trunk_network_id=None,
                          interfaces_changed=False, int_trunk_network_id=None):
        """Query routers and their related floating_ips, interfaces.
        Adds information about hosting entity as well as trunking.
        """
        sync_data = super(L3_router_appliance_db_mixin, self).get_sync_data(
            context, router_ids, active)
        for r in sync_data:
            self._add_type_and_hosting_info(context, r)
            host_type = (r.get('hosting_entity') or {}).get('host_type', '')
            if host_type == cl3_const.CSR1KV_HOST:
                self._populate_port_trunk_info(
                    context, r, update_gw_trunk=ext_gw_changed,
                    gw_trunk_network_id=gw_trunk_network_id,
                    update_internal_trunk=interfaces_changed,
                    int_trunk_network_id=int_trunk_network_id)
        return sync_data

    def _add_type_and_hosting_info(self, context, router, binding_info=None,
                                   schedule=True):
        """Adds type and hosting entity information to a router."""
        try:
            if binding_info is None:
                binding_info = self.get_router_binding_info(context,
                                                            router['id'])
        except RouterBindingInfoError:
            return
        router['router_type'] = binding_info['router_type']
        router['share_host'] = binding_info['share_hosting_entity']
        if binding_info.router_type == cl3_const.NAMESPACE_ROUTER_TYPE:
            return
        if binding_info.hosting_entity is None and schedule:
            # This router has not been scheduled to a hosting entity
            # so we try to do it now.
            self.hosting_scheduler.schedule_router_on_hosting_entity(
                self, context, router, binding_info)
        if binding_info.hosting_entity is not None:
            router['hosting_entity'] = {
                'id': binding_info.hosting_entity.id,
                'host_type': binding_info.hosting_entity.host_type,
                'ip_address': binding_info.hosting_entity.ip_address,
                'port': binding_info.hosting_entity.transport_port,
                'created_at': binding_info.hosting_entity.created_at}

    def _populate_port_trunk_info(self, context, router,
                                  update_gw_trunk=False,
                                  gw_trunk_network_id=None,
                                  update_internal_trunk=False,
                                  int_trunk_network_id=None):
        """Populate router ports with with trunking information.

        This function should only be called for routers that are hosted
        by hosting entities that use VLANs, e.g., service VMs like CSR1kv.
        """

        # We only populate trunk info, i.e., reach here, if the
        # router has been scheduled to a hosting entity. Hence this
        # a good place to allocate hosting ports to the router ports.
        tr_info = None
        did_allocation = False
        if router['gw_port_id'] is not None:
            tr_info, did_allocation = self._populate_trunk_for_port(
                context, router['gw_port'], router['hosting_entity']['id'],
                router['id'], cl3_const.T2_PORT_NAME,
                l3_db.DEVICE_OWNER_ROUTER_GW)
        if update_gw_trunk and not did_allocation:
            # If allocation of vlan tag for gateway port happened then
            # trunking was done as part of that so no need to do it here.
            trunk_network_id = (gw_trunk_network_id if tr_info is None
                                else tr_info.hosting_port['network_id'])
            if trunk_network_id is not None:
                trunk_mappings = ({} if router['gw_port_id'] is None
                                  or tr_info is None
                                  else {router['gw_port']['network_id']:
                                        tr_info.segmentation_tag})
                self._update_trunking_on_hosting_port(
                    context, trunk_network_id, trunk_mappings)
        hosting_mac = None
        tr_info = None
        for itfc in router.get(l3_constants.INTERFACE_KEY, []):
            tr_info, did_allocation = self._populate_trunk_for_port(
                context, itfc, router['hosting_entity']['id'],
                router['id'], cl3_const.T1_PORT_NAME,
                l3_db.DEVICE_OWNER_ROUTER_INTF, hosting_mac)
            update_internal_trunk |= did_allocation
            if hosting_mac is None and tr_info is not None:
                # All itfc have same hosting interface so this avoids lookups
                hosting_mac = itfc['trunk_info']['hosting_mac']
        if update_internal_trunk:
            # The router has been attached to or detached from a subnet
            # so we need to update the vlan trunking on the hosting port.
            # For internal ports trunking does not happen as part of
            # allocation of vlan tag so it must always be done here.
            trunk_network_id = (int_trunk_network_id if tr_info is None
                               else tr_info.hosting_port['network_id'])
            if trunk_network_id is not None:
                trunk_mappings = self._build_trunk_mapping(
                    context, router['id'], l3_db.DEVICE_OWNER_ROUTER_INTF)
                self._update_trunking_on_hosting_port(context, trunk_network_id,
                                                      trunk_mappings)

    def _populate_trunk_for_port(self, context, port, hosting_entity_id,
                                 router_id, trunk_port_name, device_owner,
                                 hosting_port_mac=None):
        port_db = self._get_port(context, port['id'])
        tr_info = port_db.trunk_info
        new_allocation = False
        if tr_info is None:
            # The port does not yet have a hosting port so
            # allocated one
            tr_info = self._allocate_hosting_port(
                context, port_db, hosting_entity_id, router_id,
                trunk_port_name, device_owner)
            if tr_info is None:
                # This should not happen but just in case ...
                LOG.error(_('Failed to allocate hosting port '
                            'for port %s'), port['id'])
                port['trunk_info'] = None
                return None, new_allocation
            else:
                new_allocation = True
        if hosting_port_mac is None:
            hosting_port_mac = self.get_port(
                context, tr_info.hosting_port_id,
                ['mac_address']).get('mac_address')
        # Including MAC address of hosting port so L3CfgAgent can easily
        # determine which VM VIF to configure VLAN sub-interface on.
        port['trunk_info'] = {'hosting_port_id': tr_info.hosting_port_id,
                              'hosting_mac': hosting_port_mac,
                              'segmentation_id': tr_info.segmentation_tag}
        return tr_info, new_allocation

    def _get_router_port_db_on_subnet(self, context, router_id, subnet):
        try:
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet['id']:
                    return p
        except exc.NoResultFound:
            return

    def _get_router_ports_with_trunkinfo_qry(self, context, router_id,
                                               device_owner=None):
        # Query for a router's ports that have trunking information
        query = context.session.query(models_v2.Port)
        query = query.join(TrunkInfo,
                           models_v2.Port.id == TrunkInfo.router_port_id)
        query = query.filter(models_v2.Port.device_id == router_id)
        if device_owner is not None:
            query = query.filter(models_v2.Port.device_owner == device_owner)
        return query

    def _update_trunking_on_hosting_port(self, context, trunk_network_id,
                                         trunk_mappings):
        # Should return the trunk mapping
        network_dict = {'network': {TRUNKED_NETWORKS: trunk_mappings}}
        net = self.update_network(context, trunk_network_id, network_dict)
        return net.get(TRUNKED_NETWORKS)

    def _get_trunk_network_id(self, context, port_db):
        if port_db and port_db.trunk_info and port_db.trunk_info.hosting_port:
            return port_db.trunk_info.hosting_port['network_id']
        else:
            return

    def _build_trunk_mapping(self, context, router_id, device_owner):
        query = self._get_router_ports_with_trunkinfo_qry(
            context, router_id, device_owner)
        res = {port['network_id']: port.trunk_info.segmentation_tag
               for port in query}
        return res

    def _allocate_hosting_port(self, context, port_db, hosting_entity_id,
                               router_id, trunk_port_name, device_owner):
        allocations = self._get_router_ports_with_trunkinfo_qry(
            context, router_id).all()
        trunk_mappings = {}
        if len(allocations) == 0:
            # Router has no hosting port allocated to it yet so we
            # select an unused port on the hosting entity.
            id_allocated_port = self._get_unused_service_vm_trunk_port(
                context, hosting_entity_id, trunk_port_name)
        else:
            # Iterate over existing allocations to determine used vlan tags
            id_allocated_port = None
            for item in allocations:
                if item['device_owner'] == device_owner:
                    tag = item.trunk_info['segmentation_tag']
                    trunk_mappings[item['network_id']] = tag
                    id_allocated_port = item.trunk_info['hosting_port_id']
                else:
                    port_twin_id = item.trunk_info['hosting_port_id']
                    if trunk_port_name == cl3_const.T2_PORT_NAME:
                        # no need to iterate further since the plugin
                        # provides the vlan tag for this case
                        break
            if id_allocated_port is None:
                id_allocated_port = self._get_other_port_id_in_pair(
                    context, port_twin_id)
        if id_allocated_port is None:
            # Database must have been messed up if this happens ...
            return
        if trunk_port_name == cl3_const.T1_PORT_NAME:
            used_tags = set(trunk_mappings.values())
            allocated_vlan = min(sorted(FULL_VLAN_SET - used_tags))
        else:
            trunk_mappings[port_db['network_id']] = None
            net_id = self.get_port(context, id_allocated_port,
                                   ['network_id'])['network_id']
            res = self._update_trunking_on_hosting_port(context,
                                                        net_id,
                                                        trunk_mappings)
            allocated_vlan = (None if res is None
                              else res.get(port_db['network_id']))
        if allocated_vlan is None:
            # Database must have been messed up if this happens ...
            return
        with context.session.begin(subtransactions=True):
            tr_info = TrunkInfo(
                router_port_id=port_db['id'],
                hosting_port_id=id_allocated_port,
                segmentation_tag=allocated_vlan)
            context.session.add(tr_info)
            context.session.expire(port_db)
        return tr_info

    def _get_unused_service_vm_trunk_port(self, context, he_id, name):
        # mysql> SELECT * FROM ports WHERE device_id = 'he_id1' AND
        # id NOT IN (SELECT hosting_port_id FROM trunkinfos) AND
        # name LIKE '%t1%'
        # ORDER BY name;
        stmt = context.session.query(TrunkInfo.hosting_port_id).subquery()
        query = context.session.query(models_v2.Port.id)
        query = query.filter(and_(models_v2.Port.device_id == he_id,
                                  ~models_v2.Port.id.in_(stmt),
                                  models_v2.Port.name.like('%' + name + '%')))
        query = query.order_by(models_v2.Port.name)
        res = query.first()
        if res is None:
            # This should not happen ...
            LOG.error(_('Trunk port DB inconsistency for hosting entity %s'),
                      he_id)
            return
        return res[0]

    def _get_other_port_id_in_pair(self, context, port_id):
        query = context.session.query(models_v2.Port)
        query = query.filter(models_v2.Port.id == port_id)
        try:
            port = query.one()
            name, index = port['name'].split(':')
            name += ':'
            if name == cl3_const.T1_PORT_NAME:
                other_port_name = cl3_const.T2_PORT_NAME
            else:
                other_port_name = cl3_const.T1_PORT_NAME
            query = context.session.query(models_v2.Port)
            query = query.filter(models_v2.Port.name ==
                                 other_port_name + index)
            other_port = query.one()
            return other_port['id']
        except (exc.NoResultFound, exc.MultipleResultsFound):
            # This should not happen ...
            LOG.error(_('Port trunk pair DB inconsistency for port %s'),
                      port_id)
            return
