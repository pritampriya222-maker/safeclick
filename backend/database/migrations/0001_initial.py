"""Initial migration — Phase 5: create users, devices, reported_sites, shared_threat_intel, analytics_events tables."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('history_sync_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    op.create_table(
        'devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=True),
        sa.Column('refresh_token_hash', sa.String(255), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'reported_sites',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('reporter_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('report_type', sa.Enum('phishing', 'false_positive', 'malware', name='reporttype'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'confirmed', 'rejected', name='reportstatus'), nullable=False, server_default='pending'),
        sa.Column('engine_score', sa.Float(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['reporter_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_reported_sites_domain', 'reported_sites', ['domain'])
    op.create_index('ix_reported_sites_status', 'reported_sites', ['status'])

    op.create_table(
        'shared_threat_intel',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('report_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('avg_engine_score', sa.Float(), nullable=True),
        sa.Column('confirmed_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('domain'),
    )
    op.create_index('ix_shared_threat_intel_domain', 'shared_threat_intel', ['domain'])

    op.create_table(
        'analytics_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.Enum('verdict_served', 'report_submitted', 'threat_intel_hit', name='eventtype'), nullable=False),
        sa.Column('verdict_level', sa.String(20), nullable=True),
        sa.Column('domain_hash', sa.String(64), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_analytics_events_event_type', 'analytics_events', ['event_type'])
    op.create_index('ix_analytics_events_timestamp', 'analytics_events', ['timestamp'])


def downgrade() -> None:
    op.drop_table('analytics_events')
    op.drop_table('shared_threat_intel')
    op.drop_table('reported_sites')
    op.drop_table('devices')
    op.drop_table('users')
    op.execute("DROP TYPE IF EXISTS reporttype")
    op.execute("DROP TYPE IF EXISTS reportstatus")
    op.execute("DROP TYPE IF EXISTS eventtype")
