# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation
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

"""ext_gw_mode

Revision ID: 128e042a2b68
Revises: 32b517556ec9
Create Date: 2013-03-27 00:35:17.323280

"""

# revision identifiers, used by Alembic.
revision = '128e042a2b68'
down_revision = '32b517556ec9'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'quantum.plugins.hyperv.hyperv_quantum_plugin.HyperVQuantumPlugin',
    'quantum.plugins.linuxbridge.lb_quantum_plugin.LinuxBridgePluginV2',
    'quantum.plugins.metaplugin.meta_quantum_plugin.MetaPluginV2',
    'quantum.plugins.nec.nec_plugin.NECPluginV2',
    'quantum.plugins.openvswitch.ovs_quantum_plugin.OVSQuantumPluginV2',
    'quantum.plugins.ryu.ryu_quantum_plugin.RyuQuantumPluginV2'
]

from alembic import op
import sqlalchemy as sa


from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.add_column('routers', sa.Column('enable_snat', sa.Boolean(),
                                       nullable=False, default=True))
    # Set enable_snat to True for existing routers
    op.execute("UPDATE routers SET enable_snat=True")


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.drop_column('routers', 'enable_snat')
