# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Embrane, Inc.
# All Rights Reserved.
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
# @author: Ivar Lazzaro, Embrane, Inc.

from eventlet import greenthread
from eventlet import queue
from heleosapi import constants as h_con
from heleosapi import exceptions as h_exc

from neutron.openstack.common import log as logging
from neutron.plugins.embrane.agent.operations import router_operations
from neutron.plugins.embrane.common import constants as p_con
from neutron.plugins.embrane.common import contexts as ctx
from neutron.plugins.embrane.common import exceptions as plugin_exc


LOG = logging.getLogger(__name__)


def _validate_operation(event, status, item_id):
    if status and event not in p_con.operation_filter[status]:
        raise plugin_exc.StateConstraintException(operation=event,
                                                  dva_id=item_id, state=status)


class Dispatcher(object):

    def __init__(self, plugin, async=True):
        self._async = async
        self._plugin = plugin
        self.sync_items = dict()

    def dispatch_l3(self, d_context, args=(), kwargs={}):
        item = d_context.item
        event = d_context.event
        q_context = d_context.q_context
        chain = d_context.chain

        item_id = item["id"]
        # First round validation (Controller level)
        _validate_operation(event, item["status"], item_id)

        handlers = router_operations.handlers
        if event in handlers:
            for f in handlers[event]:
                first_run = False
                if item_id not in self.sync_items:
                    self.sync_items[item_id] = queue.Queue()
                    first_run = True
                self.sync_items[item_id].put(
                    ctx.OperationContext(event, q_context, item, chain, f,
                                         args, kwargs))
                if first_run:
                    t = greenthread.spawn(self._consume_l3,
                                          item_id,
                                          self.sync_items[item_id],
                                          self._plugin)
                if not self._async:
                    t.wait()

    def _consume_l3(self, sync_item, sync_queue, plugin):
        current_state = None
        while True:
            try:
                # If the DVA is deleted, the thread (and the associated queue)
                # can die as well
                if current_state == p_con.Status.DELETED:
                    del self.sync_items[sync_item]
                    return
                try:
                    operation_context = sync_queue.get(
                        timeout=p_con.QUEUE_TIMEOUT)
                except queue.Empty:
                    del self.sync_items[sync_item]
                    return
                # Second round validation (enqueued level)
                _validate_operation(operation_context.event,
                                    current_state,
                                    operation_context.item["id"])
                # Execute the preliminary operations
                (operation_context.chain and
                 operation_context.chain.execute_all())
                # Execute the main operation, a transient state is maintained
                # so that the consumer can decide if it has
                # to be burned to the DB
                transient_state = None
                try:
                    dva_state = operation_context.function(
                        plugin._esm_api,
                        operation_context.q_context.tenant_id,
                        operation_context.item,
                        *operation_context.args,
                        **operation_context.kwargs)
                    if dva_state == p_con.Status.DELETED:
                        transient_state = dva_state
                    else:
                        if not dva_state:
                            transient_state = p_con.Status.ERROR
                        elif dva_state == h_con.DvaState.POWER_ON:
                            transient_state = p_con.Status.ACTIVE
                        else:
                            transient_state = p_con.Status.READY

                except (h_exc.PendingDva, h_exc.DvaNotFound,
                        h_exc.BrokenInterface, h_exc.DvaCreationFailed,
                        h_exc.DvaCreationPending, h_exc.BrokenDva,
                        h_exc.ConfigurationFailed) as ex:
                    LOG.warning(p_con.error_map[type(ex)] % ex.message)
                    transient_state = p_con.Status.ERROR
                except h_exc.DvaDeleteFailed as ex:
                    LOG.warning(p_con.error_map[type(ex)] % ex.message)
                    transient_state = p_con.Status.DELETED
                finally:
                    # if the returned transient state is None, no operations
                    # are required on the DVA status
                    if transient_state:
                        if transient_state == p_con.Status.DELETED:
                            current_state = plugin._delete_router(
                                operation_context.q_context,
                                operation_context.item["id"])
                        # Error state cannot be reverted
                        elif current_state != p_con.Status.ERROR:
                            current_state = plugin._update_neutron_state(
                                operation_context.q_context,
                                operation_context.item,
                                transient_state)
            except plugin_exc.StateConstraintException as e:
                LOG.error(_("%s"), e.message)
            except Exception:
                LOG.exception(_("Unhandled exception occurred"))
