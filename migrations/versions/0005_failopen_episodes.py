"""fail-open episodes and pfSense's reported grace, policy and device map

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-06 00:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('failopen_episodes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('ended_at', sa.DateTime(), nullable=False),
    sa.Column('reported_at', sa.DateTime(), nullable=False),
    sa.Column('dismissed_at', sa.DateTime(), nullable=True),
    sa.Column('dismissed_by', sa.String(length=32), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('failopen_episodes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_failopen_episodes_started_at'), ['started_at'], unique=False)
    with op.batch_alter_table('firewall_acks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('stale_grace_seconds', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('stale_policy', sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column('known_devices', sa.Text(), nullable=False, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('firewall_acks', schema=None) as batch_op:
        batch_op.drop_column('known_devices')
        batch_op.drop_column('stale_policy')
        batch_op.drop_column('stale_grace_seconds')
    with op.batch_alter_table('failopen_episodes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_failopen_episodes_started_at'))
    op.drop_table('failopen_episodes')
