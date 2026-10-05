"""sessions.enforced_at (start immediately, refund if never acknowledged)

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-05 23:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('enforced_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_column('enforced_at')
