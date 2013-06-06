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

import math

from oslo.config import cfg
from sqlalchemy import and_
from sqlalchemy import func
from sqlalchemy import or_

from quantum.openstack.common import log as logging
from quantum.plugins.cisco.l3.common import constants as cl3_const
from quantum.plugins.cisco.l3.db import l3_router_applicance_db as l3_ra_db


LOG = logging.getLogger(__name__)


class L3HostingEntityScheduler(object):
    """Methods to schedule routers to hosting entities."""

    # This variable only count tenant unbound slots
    _avail_svc_vm_slots = -1
    # Number of tenant unbound slots to keep available
    _desired_svc_vm_slots = (
        cfg.CONF.max_routers_per_csr1kv * cfg.CONF.standby_pool_size)

    def sync_service_vm_pool_counters(self, context,
                                      host_type=cl3_const.CSR1KV_HOST):
        #TODO(bob-melander): Make counters indexed on host_type
        # mysql> SELECT COUNT(id) FROM hostingentities
        # WHERE host_type='CSR1kv' AND tenant_bound IS NULL;
        query = context.session.query(func.count(
            l3_ra_db.HostingEntity.id))
        query = query.filter(and_(l3_ra_db.HostingEntity.host_type ==
                                  host_type,
                                  l3_ra_db.HostingEntity.admin_state_up ==
                                  True,
                                  l3_ra_db.HostingEntity.tenant_bound ==
                                  None))
        non_tenant_bound_he = query.scalar()

        #mysql> SELECT hostingentities.id FROM hostingentities AS he
        # JOIN routerhostingentitybindings AS rhe
        # ON he.id = rhe.hosting_entity_id
        # WHERE he.host_type = 'CSR1kv' AND he.tenant_bound IS NULL

        query = context.session.query(l3_ra_db.HostingEntity.id).join(
            l3_ra_db.RouterHostingEntityBinding,
            l3_ra_db.HostingEntity.id ==
            l3_ra_db.RouterHostingEntityBinding.hosting_entity_id)
        query = query.filter(and_(l3_ra_db.HostingEntity.host_type ==
                                  host_type,
                                  l3_ra_db.HostingEntity.admin_state_up ==
                                  True,
                                  l3_ra_db.HostingEntity.tenant_bound ==
                                  None))
        num_used_slots = query.count()
        self._avail_svc_vm_slots = (
            cfg.CONF.max_routers_per_csr1kv * non_tenant_bound_he -
            num_used_slots)

    def maintain_service_vm_pool(self, plugin, context):
        """Ensures that the number of standby service vms is kept at
        a suitable level so that resource creation is not slowed
        down by booting of service vms.
        """
        #TODO(bob-melander): Make pool and counters indexed on host_type
        # Maintain a pool of approximately _desired_svc_vm_slots =
        #     cfg.CONF.max_routers_per_csr1kv * cfg.CONF.standby_pool_size
        # slots available for use.
        # Approximately means _avail_svc_vm_slots =
        #         [ _desired_svc_vm_slots - cfg.CONF.max_routers_per_csr1kv,
        #           _desired_svc_vm_slots - cfg.CONF.max_routers_per_csr1kv ]
        #
        # Spin-up VM condition: _service_vm_slots < _desired_svc_vm_slots
        # Resulting increase of available slots:
        #     _avail_svc_vm_slots + cfg.CONF.max_routers_per_csr1kv
        # Delete VM condition: _service_vm_slots < _desired_svc_vm_slots
        # Resulting reduction of available slots:
        #     _avail_svc_vm_slots - cfg.CONF.max_routers_per_csr1kv

        if (self._avail_svc_vm_slots < self._desired_svc_vm_slots -
            cfg.CONF.max_routers_per_csr1kv):
            num_req = int(math.ceil((self._desired_svc_vm_slots -
                                     self._avail_svc_vm_slots) /
                                    (1.0*cfg.CONF.max_routers_per_csr1kv)))
            num_created = len(plugin.create_csr1kv_vm_hosting_entities(
                context, num_req))
            if num_created < num_req:
                LOG.warn(_('Requested %{n_requested} service VMs but only '
                           '%{n_created} could be created'),
                         {'n_requested': num_req, 'n_created': num_created})
            self._avail_svc_vm_slots += (num_created *
                                         cfg.CONF.max_routers_per_csr1kv)
        elif (self._avail_svc_vm_slots >
                self._desired_svc_vm_slots + cfg.CONF.max_routers_per_csr1kv):
            num_req = int(math.ceil((self._avail_svc_vm_slots -
                                     self._desired_svc_vm_slots) /
                                    (1.0*cfg.CONF.max_routers_per_csr1kv)))
            num_deleted = plugin.delete_service_vm_hosting_entities(context,
                                                                    num_req)
            if num_deleted < num_req:
                LOG.warn(_('Tried to delete %{n_requested} service VMs '
                           'but only %{n_deleted} could be deleted'),
                         {'n_requested': num_req, 'n_deleted': num_deleted})
            self._avail_svc_vm_slots -= (num_deleted *
                                         cfg.CONF.max_routers_per_csr1kv)

    def schedule_router_on_svm_hosting_entity(self, context, router,
                                              host_type=cl3_const.CSR1KV_HOST):
        """Schedules a router on a service VM hosting entity.
        Returns a tuple with selected hosting entity and the number of routers
        it hosts, i.e., the number of slots that are occupied."""

        #TODO(bob-melander): Make indexed on host_type
        # mysql> SELECT *, COUNT(router_id) as num_alloc
        # FROM hostingentities AS he
        # LEFT OUTER JOIN routerhostingentitybindings AS rhe
        # ON he.id=rhe.hosting_entity_id
        # WHERE host_type='CSR1kv' AND admin_state_up=TRUE AND
        # (tenant_bound='t2' OR tenant_bound IS NULL)
        # GROUP BY id HAVING (num_alloc < 4)
        # ORDER BY created_at, num_alloc;

        stmt = context.session.query(
            l3_ra_db.HostingEntity,
            func.count(l3_ra_db.RouterHostingEntityBinding.router_id).
            label('num_alloc'))
        stmt = stmt.outerjoin(
            l3_ra_db.RouterHostingEntityBinding,
            l3_ra_db.HostingEntity.id ==
            l3_ra_db.RouterHostingEntityBinding.hosting_entity_id)
        stmt = stmt.filter(and_(l3_ra_db.HostingEntity.host_type == host_type,
                                l3_ra_db.HostingEntity.admin_state_up == True))
        stmt = stmt.filter(
            or_(l3_ra_db.HostingEntity.tenant_bound == None,
                l3_ra_db.HostingEntity.tenant_bound == router['tenant_id']))
        stmt = stmt.group_by(l3_ra_db.HostingEntity.id)
        if router.get('share_host', True):
            query = stmt.having(func.count(
                l3_ra_db.RouterHostingEntityBinding.router_id) <
                cfg.CONF.max_routers_per_csr1kv)
            query = query.order_by(
                l3_ra_db.HostingEntity.created_at,
                func.count(l3_ra_db.RouterHostingEntityBinding.router_id))
        else:
            # TODO(bob-melander): enhance so that tenant unbound
            # hosting entities that only host routers for this tenant
            # are also included
            stmt = stmt.subquery()
            query = context.session.query(stmt)
            query = query.filter(or_(and_(stmt.c.tenant_bound == None,
                                          stmt.c.num_alloc == 0),
                                     and_(stmt.c.tenant_bound ==
                                          router['tenant_id'],
                                          stmt.c.num_alloc <
                                          cfg.CONF.max_routers_per_csr1kv)))
            query = query.order_by(stmt.c.created_at, stmt.c.num_alloc)
        host_ents = query.all()
        if len(host_ents) == 0:
            return
        else:
            # Choose the hosting entity that has been running for the
            # longest time. If more than one exists, then pick the one
            # with the least occupied slots.
            return host_ents[0]

    def schedule_router_on_hosting_entity(self, plugin, context, router,
                                          r_he_binding):
        if router['router_type'] == cl3_const.CSR_ROUTER_TYPE:
            with context.session.begin(subtransactions=True):
                if self._avail_svc_vm_slots < 0:
                    self.sync_service_vm_pool_counters(context)
                hosting_ent_info = self.schedule_router_on_svm_hosting_entity(
                    context, router)
                if hosting_ent_info is None:
                    # No running CSR1kv VM is able to host this router
                    # so try to spin up a new one
                    tenant = (router['tenant_id']
                              if not router.get('share_host', True) else None)
                    host_ents = plugin.create_csr1kv_vm_hosting_entities(
                        context, 1, tenant)
                    if tenant is None and host_ents:
                        # A tenant unbound hosting entity adds available slots
                        self._avail_svc_vm_slots += (
                            cfg.CONF.max_routers_per_csr1kv)
                    hosting_ent_info = (
                        [host_ents[0], cfg.CONF.max_routers_per_csr1kv]
                        if host_ents else None)

                if hosting_ent_info is not None:
                    if router['share_host']:
                        # For tenant unbound hosting entities we allocate a
                        # single slot available immediately
                        reduce_by = 1
                    elif hosting_ent_info['tenant_bound'] is None:
                        # Make hosting entity tenant bound and remove all of
                        # its slots from the available pool
                        reduce_by = cfg.CONF.max_routers_per_csr1kv
                        hosting_ent_info[0]['tenant_bound'] = router['id']
                        context.session.add(hosting_ent_info[0])
                    else:
                        # Tenant bound slots are all allocated when a
                        # hosting entity becomes tenant bound
                        reduce_by = 0
                    self._avail_svc_vm_slots -= reduce_by
                    r_he_binding.hosting_entity_id = hosting_ent_info[0]['id']
                    context.session.add(r_he_binding)
                    self.maintain_service_vm_pool(plugin, context)
            context.session.expire(r_he_binding)

    def unschedule_router_from_hosting_entity(self, plugin, context, router,
                                              hosting_entity_db):
        if hosting_entity_db is None:
            return
        if router['router_type'] == cl3_const.CSR_ROUTER_TYPE:
            if self._avail_svc_vm_slots < 0:
                self.sync_service_vm_pool_counters(context)
            if hosting_entity_db['tenant_bound'] is not None:
                query = context.session.query(
                    l3_ra_db.RouterHostingEntityBinding)
                query = query.filter(
                    l3_ra_db.RouterHostingEntityBinding.hosting_entity_id ==
                    hosting_entity_db['id'])
                # Have we removed the last OsN Router hosted on
                # this (tenant bound) hosting entity?
                if query.count() == 0:
                    # Make hosting entity tenant unbound again and
                    # return all its slots to available pool
                    inc_by = cfg.CONF.max_routers_per_csr1kv
                    hosting_entity_db['tenant_bound'] = None
                    with context.session.begin(subtransactions=True):
                        context.session.add(hosting_entity_db)
                else:
                    # We return all slots to available pool when
                    # hosting entity becomes tenant unbound
                    inc_by = 0
            else:
                # For tenant unbound hosting entities we can make
                # the slot available immediately
                inc_by = 1
            self._avail_svc_vm_slots += inc_by
            self.maintain_service_vm_pool(plugin, context)
