# Copyright 2013 Nicira, Inc.
# All Rights Reserved
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

import random

from neutron.common import constants
from neutron.common import exceptions
from neutron import context
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log
from neutron.openstack.common import loopingcall
from neutron.openstack.common import timeutils
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib

LOG = log.getLogger(__name__)


class NvpCache(object):
    """A simple Cache for NVP resources.

    Associates resource id with resource hash to rapidly identify
    updated resources.
    Each entry in the cache also stores the following information:
    - changed: the resource in the cache has been altered following
      an update or a delete
    - hit: the resource has been visited during an update (and possibly
      left unchanged)
    - data: current resource data
    - data_bk: backup of resource data prior to its removal
    """

    def __init__(self):
        # Maps a uuid to the dict containing it
        self._uuid_dict_mappings = {}
        # Dicts for NVP cached resources
        self._lswitches = {}
        self._lswitchports = {}
        self._lrouters = {}

    def __getitem__(self, key):
        # uuids are unique across the various types of resources
        # TODO(salv-orlando): Avoid lookups over all dictionaries
        # when retrieving items
        # Fetch lswitches, lports, or lrouters
        resources = self._uuid_dict_mappings[key]
        return resources[key]

    def _update_resources(self, resources, new_resources):
        # Clear the 'changed' attribute for all items
        for uuid, item in resources.items():
            if item.pop('changed', None) and not item.get('data'):
                # The item is not anymore in NVP, so delete it
                del resources[uuid]
                del self._uuid_dict_mappings[uuid]

        def do_hash(item):
            return hash(jsonutils.dumps(item))

        # Parse new data and identify new, deleted, and updated resources
        for item in new_resources:
            item_id = item['uuid']
            if resources.get(item_id):
                new_hash = do_hash(item)
                if new_hash != resources[item_id]['hash']:
                    resources[item_id]['hash'] = new_hash
                    resources[item_id]['changed'] = True
                    resources[item_id]['data_bk'] = (
                        resources[item_id]['data'])
                    resources[item_id]['data'] = item
                # Mark the item as hit in any case
                resources[item_id]['hit'] = True
            else:
                resources[item_id] = {'hash': do_hash(item)}
                resources[item_id]['hit'] = True
                resources[item_id]['changed'] = True
                resources[item_id]['data'] = item
                # add a uuid to dict mapping for easy retrieval
                # with __getitem__
                self._uuid_dict_mappings[item_id] = resources

    def _delete_resources(self, resources):
        # Mark for removal all the elements which have not been visited.
        # And clear the 'hit' attribute.
        for to_delete in [k for (k, v) in resources.iteritems()
                          if not v.pop('hit', False)]:
            resources[to_delete]['changed'] = True
            resources[to_delete]['data_bk'] = (
                resources[to_delete].pop('data', None))

    def _get_resource_ids(self, resources, changed_only):
        if changed_only:
            return [k for (k, v) in resources.iteritems()
                    if v.get('changed')]
        return resources.keys()

    def get_lswitches(self, changed_only=False):
        return self._get_resource_ids(self._lswitches, changed_only)

    def get_lrouters(self, changed_only=False):
        return self._get_resource_ids(self._lrouters, changed_only)

    def get_lswitchports(self, changed_only=False):
        return self._get_resource_ids(self._lswitchports, changed_only)

    def update_lswitch(self, lswitch):
        self._update_resources(self._lswitches, [lswitch])

    def update_lrouter(self, lrouter):
        self._update_resources(self._lrouters, [lrouter])

    def update_lswitchport(self, lswitchport):
        self._update_resources(self._lswitchports, [lswitchport])

    def process_updates(self, lswitches=None,
                        lrouters=None, lswitchports=None):
        self._update_resources(self._lswitches, lswitches)
        self._update_resources(self._lrouters, lrouters)
        self._update_resources(self._lswitchports, lswitchports)
        return (self._get_resource_ids(self._lswitches, changed_only=True),
                self._get_resource_ids(self._lrouters, changed_only=True),
                self._get_resource_ids(self._lswitchports, changed_only=True))

    def process_deletes(self):
        self._delete_resources(self._lswitches)
        self._delete_resources(self._lrouters)
        self._delete_resources(self._lswitchports)
        return (self._get_resource_ids(self._lswitches, changed_only=True),
                self._get_resource_ids(self._lrouters, changed_only=True),
                self._get_resource_ids(self._lswitchports, changed_only=True))


class SyncParameters():
    """Defines attributes used by the synchronization procedure.

    chunk_size: Actual chunk size
    extra_chunk_size: Additional data to fetch because of chunk size
                      adjustment
    current_chunk: Counter of the current data chunk being synchronized
    Page cursors: markers for the next resource to fetch.
                 'start' means page cursor unset for fetching 1st page
    init_sync_performed: True if the initial synchronization concluded
    """

    def __init__(self, min_chunk_size):
        self.chunk_size = min_chunk_size
        self.extra_chunk_size = 0
        self.current_chunk = 0
        self.ls_cursor = 'start'
        self.lr_cursor = 'start'
        self.lp_cursor = 'start'
        self.init_sync_performed = False
        self.total_size = 0


def _start_loopingcall(min_chunk_size, state_sync_interval, func):
    """Start a loopingcall for the synchronization task."""
    # Start a looping call to synchronize operational status
    # for neutron resources
    if not state_sync_interval:
        # do not start the looping call if specified
        # sync interval is 0
        return
    state_synchronizer = loopingcall.DynamicLoopingCall(
        func, sp=SyncParameters(min_chunk_size))
    state_synchronizer.start(
        periodic_interval_max=state_sync_interval)
    return state_synchronizer


class NvpSynchronizer():

    LS_URI = nvplib._build_uri_path(
        nvplib.LSWITCH_RESOURCE, fields='uuid,tags,fabric_status',
        relations='LogicalSwitchStatus')
    LR_URI = nvplib._build_uri_path(
        nvplib.LROUTER_RESOURCE, fields='uuid,tags,fabric_status',
        relations='LogicalRouterStatus')
    LP_URI = nvplib._build_uri_path(
        nvplib.LSWITCHPORT_RESOURCE,
        parent_resource_id='*',
        fields='uuid,tags,fabric_status,link_status_up',
        relations='LogicalPortStatus')

    def __init__(self, plugin, cluster, state_sync_interval,
                 req_delay, min_chunk_size, max_rand_delay=0):
        random.seed()
        self._nvp_cache = NvpCache()
        # Store parameters as instance members
        # NOTE(salv-orlando): apologies if it looks java-ish
        self._plugin = plugin
        self._cluster = cluster
        self._req_delay = req_delay
        self._sync_interval = state_sync_interval
        self._max_rand_delay = max_rand_delay
        # Validate parameters
        if self._sync_interval < self._req_delay:
            err_msg = (_("Minimum request delay:%(req_delay)s must not "
                         "exceed synchronization interval:%(sync_interval)s") %
                       {'req_delay': self._req_delay,
                        'sync_interval': self._sync_interval})
            LOG.error(err_msg)
            raise nvp_exc.NvpPluginException(err_msg=err_msg)
        # Backoff time in case of failures while fetching sync data
        self._sync_backoff = 1
        # Store the looping call in an instance variable to allow unit tests
        # for controlling its lifecycle
        self._sync_looping_call = _start_loopingcall(
            min_chunk_size, state_sync_interval, self._synchronize_state)

    def _get_tag_dict(self, tags):
        return dict((tag.get('scope'), tag['tag']) for tag in tags)

    def _update_neutron_object(self, context, neutron_data, status):
        if status == neutron_data['status']:
            # do nothing
            return
        with context.session.begin(subtransactions=True):
            LOG.debug(_("Updating status for neutron resource %(q_id)s to: "
                        "%(status)s"), {'q_id': neutron_data['id'],
                                        'status': status})
            neutron_data['status'] = status
            context.session.add(neutron_data)

    def synchronize_network(self, context, neutron_network_data,
                            lswitches=None):
        """Synchronize a Neutron network with its NVP counterpart.

        This routine synchronizes a set of switches when a Neutron
        network is mapped to multiple lswitches.
        """
        if not lswitches:
            # Try to get logical switches from nvp
            try:
                lswitches = nvplib.get_lswitches(
                    self._cluster, neutron_network_data['id'])
            except exceptions.NetworkNotFound:
                # TODO(salv-orlando): We should be catching
                # NvpApiClient.ResourceNotFound here
                # The logical switch was not found
                LOG.warning(_("Logical switch for neutron network %s not "
                              "found on NVP."), neutron_network_data['id'])
                lswitches = []
            else:
                for lswitch in lswitches:
                    self._nvp_cache.update_lswitch(lswitch)
        # By default assume things go wrong
        status = constants.NET_STATUS_ERROR
        # In most cases lswitches will contain a single element
        for ls in lswitches:
            if not ls:
                # Logical switch was deleted
                break
            ls_status = ls['_relations']['LogicalSwitchStatus']
            if not ls_status['fabric_status']:
                status = constants.NET_STATUS_DOWN
                break
        else:
            # No switch was down or missing. Set status to ACTIVE unless
            # there were no switches in the first place!
            if lswitches:
                status = constants.NET_STATUS_ACTIVE
        # Update db object
        self._update_neutron_object(context, neutron_network_data, status)

    def _synchronize_lswitches(self, ctx, ls_uuids, scan_missing=False):
        if not ls_uuids and not scan_missing:
            return
        neutron_net_ids = set()
        neutron_nvp_mappings = {}
        # TODO(salvatore-orlando): Deal with the case the tag
        # has been tampered with
        for ls_uuid in ls_uuids:
            # If the lswitch has been deleted, get backup copy of data
            lswitch = (self._nvp_cache[ls_uuid].get('data') or
                       self._nvp_cache[ls_uuid].get('data_bk'))
            tags = self._get_tag_dict(lswitch['tags'])
            neutron_id = tags.get('neutron_net_id', ls_uuid)
            neutron_net_ids.add(neutron_id)
            neutron_nvp_mappings[neutron_id] = (
                neutron_nvp_mappings.get(neutron_id, []) +
                [self._nvp_cache[ls_uuid]])
        with ctx.session.begin(subtransactions=True):
            # Fetch neutron networks from database
            filters = {'router:external': [False]}
            if not scan_missing:
                filters['id'] = neutron_net_ids
            # TODO(salv-orlando): Filter out external networks
            for network in self._plugin._get_collection_query(
                ctx, models_v2.Network, filters=filters):
                lswitches = neutron_nvp_mappings.get(network['id'], [])
                lswitches = [lswitch.get('data') for lswitch in lswitches]
                self.synchronize_network(ctx, network, lswitches)

    def synchronize_router(self, context, neutron_router_data,
                           lrouter=None):
        """Synchronize a neutron router with its NVP counterpart."""
        if not lrouter:
            # Try to get router from nvp
            try:
                # This query will return the logical router status too
                lrouter = nvplib.get_lrouter(
                    self._cluster, neutron_router_data['id'])
            except exceptions.NotFound:
                # NOTE(salv-orlando): We should be catching
                # NvpApiClient.ResourceNotFound here
                # The logical router was not found
                LOG.warning(_("Logical router for neutron router %s not "
                              "found on NVP."), neutron_router_data['id'])
                lrouter = None
            else:
                # Update the cache
                self._nvp_cache.update_lrouter(lrouter)

        # Note(salv-orlando): It might worth adding a check to verify neutron
        # resource tag in nvp entity matches a Neutron id.
        # By default assume things go wrong
        status = constants.NET_STATUS_ERROR
        if lrouter:
            lr_status = (lrouter['_relations']
                         ['LogicalRouterStatus']
                         ['fabric_status'])
            status = (lr_status and
                      constants.NET_STATUS_ACTIVE
                      or constants.NET_STATUS_DOWN)
        # Update db object
        self._update_neutron_object(context, neutron_router_data, status)

    def _synchronize_lrouters(self, ctx, lr_uuids, scan_missing=False):
        if not lr_uuids and not scan_missing:
            return
        neutron_router_mappings = (
            dict((lr_uuid, self._nvp_cache[lr_uuid]) for lr_uuid in lr_uuids))
        with ctx.session.begin(subtransactions=True):
            # Fetch neutron routers from database
            filters = ({} if scan_missing else
                       {'id': neutron_router_mappings.keys()})
            for router in self._plugin._get_collection_query(
                ctx, l3_db.Router, filters=filters):
                lrouter = neutron_router_mappings.get(router['id'])
                self.synchronize_router(
                    ctx, router, lrouter and lrouter.get('data'))

    def synchronize_port(self, context, neutron_port_data,
                         lswitchport=None, ext_networks=None):
        """Synchronize a Neutron port with its NVP counterpart."""
        # Skip synchronization for ports on external networks
        if not ext_networks:
            ext_networks = [net['id'] for net in context.session.query(
                models_v2.Network).join(
                    l3_db.ExternalNetwork,
                    (models_v2.Network.id ==
                     l3_db.ExternalNetwork.network_id))]
        if neutron_port_data['network_id'] in ext_networks:
            with context.session.begin(subtransactions=True):
                neutron_port_data['status'] = constants.PORT_STATUS_ACTIVE
                return

        if not lswitchport:
            # Try to get port from nvp
            try:
                lp_uuid = self._plugin._nvp_get_port_id(
                    context, self._cluster, neutron_port_data)
                if lp_uuid:
                    lswitchport = nvplib.get_port(
                        self._cluster, neutron_port_data['network_id'],
                        lp_uuid, relations='LogicalPortStatus')
            except exceptions.PortNotFoundOnNetwork:
                # NOTE(salv-orlando): We should be catching
                # NvpApiClient.ResourceNotFound here
                # The logical switch port was not found
                LOG.warning(_("Logical switch port for neutron port %s "
                              "not found on NVP."), neutron_port_data['id'])
                lswitchport = None
            else:
                # Update the cache
                self._nvp_cache.update_lswitchport(lswitchport)

        # Note(salv-orlando): It might worth adding a check to verify neutron
        # resource tag in nvp entity matches Neutron id.
        # By default assume things go wrong
        status = constants.PORT_STATUS_ERROR
        if lswitchport:
            lp_status = (lswitchport['_relations']
                         ['LogicalPortStatus']
                         ['link_status_up'])
            status = (lp_status and
                      constants.PORT_STATUS_ACTIVE
                      or constants.PORT_STATUS_DOWN)
        # Update db object
        self._update_neutron_object(context, neutron_port_data, status)

    def _synchronize_lswitchports(self, ctx, lp_uuids, scan_missing=False):
        if not lp_uuids and not scan_missing:
            return
        # Find Neutron port id by tag - the tag is already
        # loaded in memory, no reason for doing a db query
        # TODO(salvatore-orlando): Deal with the case the tag
        # has been tampered with
        neutron_port_mappings = {}
        for lp_uuid in lp_uuids:
            lport = (self._nvp_cache[lp_uuid].get('data') or
                     self._nvp_cache[lp_uuid].get('data_bk'))
            tags = self._get_tag_dict(lport['tags'])
            neutron_port_id = tags.get('q_port_id')
            if neutron_port_id:
                neutron_port_mappings[neutron_port_id] = (
                    self._nvp_cache[lp_uuid])
        with ctx.session.begin(subtransactions=True):
            # Fetch neutron ports from database
            # At the first sync we need to fetch all ports
            filters = ({} if scan_missing else
                       {'id': neutron_port_mappings.keys()})
            # TODO(salv-orlando): Work out a solution for avoiding
            # this query
            ext_nets = [net['id'] for net in ctx.session.query(
                models_v2.Network).join(
                    l3_db.ExternalNetwork,
                    (models_v2.Network.id ==
                     l3_db.ExternalNetwork.network_id))]
            for port in self._plugin._get_collection_query(
                ctx, models_v2.Port, filters=filters):
                lswitchport = neutron_port_mappings.get(port['id'])
                self.synchronize_port(
                    ctx, port, lswitchport and lswitchport.get('data'),
                    ext_networks=ext_nets)

    def _get_chunk_size(self, sp):
        # NOTE(salv-orlando): Try to use __future__ for this routine only?
        ratio = ((float(sp.total_size) / float(sp.chunk_size)) /
                 (float(self._sync_interval) / float(self._req_delay)))
        new_size = max(1.0, ratio) * float(sp.chunk_size)
        return int(new_size) + (new_size - int(new_size) > 0)

    def _fetch_data(self, uri, cursor, page_size):
        # If not cursor there is nothing to retrieve
        if cursor:
            if cursor == 'start':
                cursor = None
            # Chunk size tuning might, in some conditions, make it larger
            # than 5,000, which is the maximum page size allowed by the NVP
            # API. In this case the request should be split in multiple
            # requests. This is not ideal, and therefore a log warning will
            # be emitted.
            requests = range(0, page_size / (nvplib.MAX_PAGE_SIZE + 1) + 1)
            if len(requests) > 1:
                LOG.warn(_("Requested page size is %(cur_chunk_size)d."
                           "It might be necessary to do %(num_requests)d "
                           "round-trips to NVP for fetching data. Please "
                           "tune sync parameters to ensure chunk size "
                           "is less than %(max_page_size)d"),
                         {'cur_chunk_size': page_size,
                          'num_requests': len(requests),
                          'max_page_size': nvplib.MAX_PAGE_SIZE})
            results = []
            actual_size = 0
            for _req in requests:
                req_results, cursor, req_size = nvplib.get_single_query_page(
                    uri, self._cluster, cursor,
                    min(page_size, nvplib.MAX_PAGE_SIZE))
                results.extend(req_results)
                actual_size = actual_size + req_size
                # If no cursor is returned break the cycle as there is no
                # actual need to perform multiple requests (all fetched)
                # This happens when the overall size of resources exceeds
                # the maximum page size, but the number for each single
                # resource type is below this threshold
                if not cursor:
                    break
            # reset cursor before returning if we queried just to
            # know the number of entities
            return results, cursor if page_size else 'start', actual_size
        return [], cursor, None

    def _fetch_nvp_data_chunk(self, sp):
        base_chunk_size = sp.chunk_size
        chunk_size = base_chunk_size + sp.extra_chunk_size
        LOG.info(_("Fetching up to %s resources "
                   "from NVP backend"), chunk_size)
        fetched = ls_count = lr_count = lp_count = 0
        lswitches = lrouters = lswitchports = []
        if sp.ls_cursor or sp.ls_cursor == 'start':
            (lswitches, sp.ls_cursor, ls_count) = self._fetch_data(
                self.LS_URI, sp.ls_cursor, chunk_size)
            fetched = len(lswitches)
        if fetched < chunk_size and sp.lr_cursor or sp.lr_cursor == 'start':
            (lrouters, sp.lr_cursor, lr_count) = self._fetch_data(
                self.LR_URI, sp.lr_cursor, max(chunk_size - fetched, 0))
        fetched += len(lrouters)
        if fetched < chunk_size and sp.lp_cursor or sp.lp_cursor == 'start':
            (lswitchports, sp.lp_cursor, lp_count) = self._fetch_data(
                self.LP_URI, sp.lp_cursor, max(chunk_size - fetched, 0))
        fetched += len(lswitchports)
        if sp.current_chunk == 0:
            # No cursors were provided. Then it must be possible to
            # calculate the total amount of data to fetch
            sp.total_size = ls_count + lr_count + lp_count
        LOG.debug(_("Total data size: %d"), sp.total_size)
        sp.chunk_size = self._get_chunk_size(sp)
        # Calculate chunk size adjustment
        sp.extra_chunk_size = sp.chunk_size - base_chunk_size
        LOG.debug(_("Fetched %(num_lswitches)d logical switches, "
                    "%(num_lswitchports)d logical switch ports,"
                    "%(num_lrouters)d logical routers"),
                  {'num_lswitches': len(lswitches),
                   'num_lswitchports': len(lswitchports),
                   'num_lrouters': len(lrouters)})
        return (lswitches, lrouters, lswitchports)

    def _synchronize_state(self, sp):
        # If the plugin has been destroyed, stop the LoopingCall
        if not self._plugin:
            raise loopingcall.LoopingCallDone
        start = timeutils.utcnow()
        # Reset page cursor variables if necessary
        if sp.current_chunk == 0:
            sp.ls_cursor = sp.lr_cursor = sp.lp_cursor = 'start'
        LOG.info(_("Running state synchronization task. Chunk: %s"),
                 sp.current_chunk)
        # Fetch chunk_size data from NVP
        try:
            (lswitches, lrouters, lswitchports) = (
                self._fetch_nvp_data_chunk(sp))
        except (NvpApiClient.RequestTimeout, NvpApiClient.NvpApiException):
            sleep_interval = self._sync_backoff
            # Cap max back off to 64 seconds
            self._sync_backoff = min(self._sync_backoff * 2, 64)
            LOG.exception(_("An error occured while communicating with "
                            "NVP backend. Will retry synchronization "
                            "in %d seconds"), sleep_interval)
            return sleep_interval
        LOG.debug(_("Time elapsed querying NVP: %s"),
                  timeutils.utcnow() - start)
        if sp.total_size:
            num_chunks = ((sp.total_size / sp.chunk_size) +
                          (sp.total_size % sp.chunk_size != 0))
        else:
            num_chunks = 1
        LOG.debug(_("Number of chunks: %d"), num_chunks)
        # Find objects which have changed on NVP side and need
        # to be synchronized
        (ls_uuids, lr_uuids, lp_uuids) = self._nvp_cache.process_updates(
            lswitches, lrouters, lswitchports)
        # Process removed objects only at the last chunk
        scan_missing = (sp.current_chunk == num_chunks - 1 and
                        not sp.init_sync_performed)
        if sp.current_chunk == num_chunks - 1:
            self._nvp_cache.process_deletes()
            ls_uuids = self._nvp_cache.get_lswitches(
                changed_only=not scan_missing)
            lr_uuids = self._nvp_cache.get_lrouters(
                changed_only=not scan_missing)
            lp_uuids = self._nvp_cache.get_lswitchports(
                changed_only=not scan_missing)
        LOG.debug(_("Time elapsed hashing data: %s"),
                  timeutils.utcnow() - start)
        # Get an admin context
        ctx = context.get_admin_context()
        # Synchronize with database
        with ctx.session.begin(subtransactions=True):
            self._synchronize_lswitches(ctx, ls_uuids,
                                        scan_missing=scan_missing)
            self._synchronize_lrouters(ctx, lr_uuids,
                                       scan_missing=scan_missing)
            self._synchronize_lswitchports(ctx, lp_uuids,
                                           scan_missing=scan_missing)
        # Increase chunk counter
        LOG.info(_("Synchronization for chunk %(chunk_num)d of "
                   "%(total_chunks)d performed"),
                 {'chunk_num': sp.current_chunk + 1,
                  'total_chunks': num_chunks})
        sp.current_chunk = (sp.current_chunk + 1) % num_chunks
        added_delay = 0
        if sp.current_chunk == 0:
            # Ensure init_sync_performed is True
            if not sp.init_sync_performed:
                sp.init_sync_performed = True
            # Add additional random delay
            added_delay = random.randint(0, self._max_rand_delay)
        LOG.debug(_("Time elapsed at end of sync: %s"),
                  timeutils.utcnow() - start)
        return self._sync_interval / num_chunks + added_delay
