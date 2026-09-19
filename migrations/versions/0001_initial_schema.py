"""initial schema

Revision ID: 0001
Revises: none
Create Date: 2026-09-19 16:41:32.671319
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('actor', sa.String(length=64), nullable=False),
    sa.Column('event_type', sa.String(length=48), nullable=False),
    sa.Column('subject', sa.String(length=128), nullable=False),
    sa.Column('result', sa.String(length=16), nullable=False),
    sa.Column('details_json', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_events_timestamp'), ['timestamp'], unique=False)

    op.create_table('day_locks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=False),
    sa.Column('logical_day', sa.Date(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=32), nullable=False),
    sa.Column('reason', sa.String(length=200), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('cleared_at', sa.DateTime(), nullable=True),
    sa.Column('cleared_by', sa.String(length=32), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('day_locks', schema=None) as batch_op:
        batch_op.create_index('ix_day_locks_child_day', ['child_id', 'logical_day'], unique=False)

    op.create_table('devices',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('display_name', sa.String(length=40), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('type', sa.String(length=16), nullable=False),
    sa.Column('owner_child_id', sa.String(length=64), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('firewall_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('action', sa.String(length=32), nullable=False),
    sa.Column('target', sa.String(length=200), nullable=False),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('command_summary', sa.String(length=300), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('error_text', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('firewall_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_firewall_events_timestamp'), ['timestamp'], unique=False)

    op.create_table('login_failures',
    sa.Column('key', sa.String(length=96), nullable=False),
    sa.Column('username', sa.String(length=32), nullable=False),
    sa.Column('failures', sa.Integer(), nullable=False),
    sa.Column('window_started_at', sa.DateTime(), nullable=False),
    sa.Column('locked_until', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('meta',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('notification_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('audience', sa.String(length=16), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=True),
    sa.Column('session_id', sa.Integer(), nullable=True),
    sa.Column('dedupe_key', sa.String(length=160), nullable=False),
    sa.Column('title', sa.String(length=120), nullable=False),
    sa.Column('body', sa.String(length=300), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('dispatched_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dedupe_key', name='uq_notification_dedupe')
    )
    op.create_table('push_subscriptions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=32), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('endpoint', sa.String(length=1024), nullable=False),
    sa.Column('keys_encrypted', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_success_at', sa.DateTime(), nullable=True),
    sa.Column('failure_count', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('endpoint')
    )
    with op.batch_alter_table('push_subscriptions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_push_subscriptions_username'), ['username'], unique=False)

    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=32), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('web_sessions',
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('username', sa.String(length=32), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=True),
    sa.Column('csrf_token', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('token_hash')
    )
    op.create_table('parent_overrides',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=True),
    sa.Column('device_id', sa.String(length=64), nullable=True),
    sa.Column('starts_at', sa.DateTime(), nullable=False),
    sa.Column('ends_at', sa.DateTime(), nullable=False),
    sa.Column('override_type', sa.String(length=24), nullable=False),
    sa.Column('created_by', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('note', sa.String(length=200), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('parent_overrides', schema=None) as batch_op:
        batch_op.create_index('ix_overrides_child_window', ['child_id', 'starts_at', 'ends_at'], unique=False)

    op.create_table('sessions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.String(length=32), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=True),
    sa.Column('device_id', sa.String(length=64), nullable=False),
    sa.Column('session_type', sa.String(length=16), nullable=False),
    sa.Column('start_at', sa.DateTime(), nullable=False),
    sa.Column('planned_end_at', sa.DateTime(), nullable=True),
    sa.Column('actual_end_at', sa.DateTime(), nullable=True),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('reserved_seconds', sa.Integer(), nullable=False),
    sa.Column('charged_seconds', sa.Integer(), nullable=False),
    sa.Column('end_reason', sa.String(length=32), nullable=True),
    sa.Column('until_stopped', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=32), nullable=False),
    sa.Column('idempotency_key', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('idempotency_key')
    )
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.create_index('ix_sessions_child_start', ['child_id', 'start_at'], unique=False)
        batch_op.create_index('ix_sessions_status', ['status'], unique=False)

    op.create_table('allowance_adjustments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('child_id', sa.String(length=64), nullable=False),
    sa.Column('logical_day', sa.Date(), nullable=False),
    sa.Column('delta_minutes', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(length=200), nullable=False),
    sa.Column('created_by', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('override_id', sa.Integer(), nullable=True),
    sa.Column('idempotency_key', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['override_id'], ['parent_overrides.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('idempotency_key')
    )
    with op.batch_alter_table('allowance_adjustments', schema=None) as batch_op:
        batch_op.create_index('ix_adjustments_child_day', ['child_id', 'logical_day'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('allowance_adjustments', schema=None) as batch_op:
        batch_op.drop_index('ix_adjustments_child_day')

    op.drop_table('allowance_adjustments')
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_index('ix_sessions_status')
        batch_op.drop_index('ix_sessions_child_start')

    op.drop_table('sessions')
    with op.batch_alter_table('parent_overrides', schema=None) as batch_op:
        batch_op.drop_index('ix_overrides_child_window')

    op.drop_table('parent_overrides')
    op.drop_table('web_sessions')
    op.drop_table('users')
    with op.batch_alter_table('push_subscriptions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_push_subscriptions_username'))

    op.drop_table('push_subscriptions')
    op.drop_table('notification_events')
    op.drop_table('meta')
    op.drop_table('login_failures')
    with op.batch_alter_table('firewall_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_firewall_events_timestamp'))

    op.drop_table('firewall_events')
    op.drop_table('devices')
    with op.batch_alter_table('day_locks', schema=None) as batch_op:
        batch_op.drop_index('ix_day_locks_child_day')

    op.drop_table('day_locks')
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_events_timestamp'))

    op.drop_table('audit_events')
