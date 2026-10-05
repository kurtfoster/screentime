"""firewall acknowledgements (pull model)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-05 23:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('firewall_acks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('received_at', sa.DateTime(), nullable=False),
    sa.Column('generation', sa.Integer(), nullable=False),
    sa.Column('mode', sa.String(length=16), nullable=False),
    sa.Column('device_ids', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('firewall_acks', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_firewall_acks_received_at'), ['received_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('firewall_acks', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_firewall_acks_received_at'))
    op.drop_table('firewall_acks')
