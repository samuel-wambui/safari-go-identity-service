create table if not exists mobile_google_login_codes (
    id uuid primary key,
    user_id uuid not null,
    code_hash varchar(128) not null,
    redirect_uri varchar(512) not null,
    expires_at timestamp with time zone not null,
    consumed_at timestamp with time zone,
    status varchar(30) not null,
    created_at timestamp with time zone not null,
    constraint uk_mobile_google_login_codes_code_hash unique (code_hash),
    constraint fk_mobile_google_login_codes_user foreign key (user_id) references users (id),
    constraint chk_mobile_google_login_codes_status check (status in ('ACTIVE', 'USED', 'EXPIRED'))
);

create index if not exists idx_mobile_google_login_codes_user_id
    on mobile_google_login_codes (user_id);

create index if not exists idx_mobile_google_login_codes_expires_at
    on mobile_google_login_codes (expires_at);
