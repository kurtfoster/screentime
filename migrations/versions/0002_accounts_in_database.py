"""accounts in the database

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-05 21:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('display_name', sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column('password_hash', sa.String(length=255), nullable=False, server_default='')
        )
        batch_op.add_column(sa.Column('password_changed_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('password_changed_by', sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('password_changed_by')
        batch_op.drop_column('password_changed_at')
        batch_op.drop_column('password_hash')
        batch_op.drop_column('display_name')
