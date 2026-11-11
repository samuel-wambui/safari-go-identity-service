create table if not exists mobile_sessions (
    id uuid primary key,
    user_id uuid not null,
    client_id varchar(100) not null,
    auth_method varchar(40) not null,
    status varchar(30) not null,
    source_ip varchar(100),
    user_agent varchar(500),
    created_at timestamp with time zone not null,
    expires_at timestamp with time zone not null,
    last_seen_at timestamp with time zone,
    revoked_at timestamp with time zone,
    updated_at timestamp with time zone not null,
    constraint fk_mobile_sessions_user foreign key (user_id) references users (id),
    constraint chk_mobile_sessions_status check (status in ('ACTIVE', 'EXPIRED', 'REVOKED'))
);

create index if not exists idx_mobile_sessions_user_id
    on mobile_sessions (user_id);

create index if not exists idx_mobile_sessions_status
    on mobile_sessions (status);

create index if not exists idx_mobile_sessions_expires_at
    on mobile_sessions (expires_at);
