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

"""nvp_mac_learning

Revision ID: 3cbf70257c28
Revises: 176a85fc7d79
Create Date: 2013-05-15 10:15:50.875314

"""

# revision identifiers, used by Alembic.
revision = '3cbf70257c28'
down_revision = '176a85fc7d79'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'quantum.plugins.nicira.QuantumPlugin.NvpPluginV2'
]

from alembic import op
import sqlalchemy as sa


from quantum.db import migration


def upgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.create_table(
        'maclearningstates',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('mac_learning_enabled', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
        ['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'))


def downgrade(active_plugin=None, options=None):
    if not migration.should_run(active_plugin, migration_for_plugins):
        return

    op.drop_table('maclearningstates')
