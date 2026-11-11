create table if not exists permissions (
    permission_id varchar(20) primary key,
    name varchar(100) not null,
    description varchar(255),
    constraint uk_permissions_name unique (name)
);

create table if not exists roles (
    role_id varchar(20) primary key,
    name varchar(50) not null,
    description varchar(255),
    permission_ids text,
    constraint uk_roles_name unique (name)
);

create table if not exists users (
    id uuid primary key,
    first_name varchar(100) not null,
    last_name varchar(100) not null,
    email varchar(254) not null,
    password varchar(255) not null,
    phone_number varchar(30) not null,
    enabled boolean not null default true,
    email_verified boolean not null default false,
    account_non_locked boolean not null default true,
    failed_login_attempts integer not null default 0,
    locked_at timestamp with time zone,
    lock_expires_at timestamp with time zone,
    last_login_at timestamp with time zone,
    last_failed_login_at timestamp with time zone,
    role_id varchar(20) not null,
    deleted boolean not null default false,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone not null,
    updated_at timestamp with time zone not null,
    version bigint not null default 0,
    constraint uk_users_email unique (email),
    constraint uk_users_phone_number unique (phone_number)
);

alter table roles add column if not exists permission_ids text;

alter table users add column if not exists enabled boolean not null default true;
alter table users add column if not exists email_verified boolean not null default false;
alter table users add column if not exists account_non_locked boolean not null default true;
alter table users add column if not exists failed_login_attempts integer not null default 0;
alter table users add column if not exists locked_at timestamp with time zone;
alter table users add column if not exists lock_expires_at timestamp with time zone;
alter table users add column if not exists last_login_at timestamp with time zone;
alter table users add column if not exists last_failed_login_at timestamp with time zone;
alter table users add column if not exists role_id varchar(20);
alter table users add column if not exists deleted boolean not null default false;
alter table users add column if not exists deleted_at timestamp with time zone;
alter table users add column if not exists version bigint not null default 0;

create index if not exists idx_users_email on users (email);
create index if not exists idx_users_phone_number on users (phone_number);
create index if not exists idx_users_deleted on users (deleted);

create table if not exists audit_logs (
    id uuid primary key,
    event_type varchar(80) not null,
    user_id uuid,
    actor_user_id uuid,
    email varchar(254),
    source_ip varchar(100),
    user_agent varchar(500),
    details varchar(1000),
    created_at timestamp with time zone not null
);

create index if not exists idx_audit_logs_user_id on audit_logs (user_id);
create index if not exists idx_audit_logs_event_type on audit_logs (event_type);
create index if not exists idx_audit_logs_created_at on audit_logs (created_at);

create table if not exists oauth2_registered_client (
    id varchar(100) not null,
    client_id varchar(100) not null,
    client_id_issued_at timestamp with time zone default current_timestamp not null,
    client_secret varchar(200) default null,
    client_secret_expires_at timestamp with time zone default null,
    client_name varchar(200) not null,
    client_authentication_methods varchar(1000) not null,
    authorization_grant_types varchar(1000) not null,
    redirect_uris varchar(1000) default null,
    post_logout_redirect_uris varchar(1000) default null,
    scopes varchar(1000) not null,
    client_settings varchar(2000) not null,
    token_settings varchar(2000) not null,
    primary key (id)
);

create unique index if not exists uk_oauth2_registered_client_client_id
    on oauth2_registered_client (client_id);

create table if not exists oauth2_authorization (
    id varchar(100) not null,
    registered_client_id varchar(100) not null,
    principal_name varchar(200) not null,
    authorization_grant_type varchar(100) not null,
    authorized_scopes varchar(1000) default null,
    attributes text default null,
    state varchar(500) default null,
    authorization_code_value text default null,
    authorization_code_issued_at timestamp with time zone default null,
    authorization_code_expires_at timestamp with time zone default null,
    authorization_code_metadata text default null,
    access_token_value text default null,
    access_token_issued_at timestamp with time zone default null,
    access_token_expires_at timestamp with time zone default null,
    access_token_metadata text default null,
    access_token_type varchar(100) default null,
    access_token_scopes varchar(1000) default null,
    oidc_id_token_value text default null,
    oidc_id_token_issued_at timestamp with time zone default null,
    oidc_id_token_expires_at timestamp with time zone default null,
    oidc_id_token_metadata text default null,
    refresh_token_value text default null,
    refresh_token_issued_at timestamp with time zone default null,
    refresh_token_expires_at timestamp with time zone default null,
    refresh_token_metadata text default null,
    user_code_value text default null,
    user_code_issued_at timestamp with time zone default null,
    user_code_expires_at timestamp with time zone default null,
    user_code_metadata text default null,
    device_code_value text default null,
    device_code_issued_at timestamp with time zone default null,
    device_code_expires_at timestamp with time zone default null,
    device_code_metadata text default null,
    primary key (id)
);

create index if not exists idx_oauth2_authorization_principal_name
    on oauth2_authorization (principal_name);

create table if not exists oauth2_refresh_tokens (
    id uuid primary key,
    authorization_id varchar(100) not null,
    registered_client_id varchar(100) not null,
    principal_name varchar(200) not null,
    token_family_id uuid not null,
    token_hash varchar(128) not null,
    issued_at timestamp with time zone,
    expires_at timestamp with time zone,
    used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    reused_at timestamp with time zone,
    source_ip varchar(100),
    user_agent varchar(500),
    created_at timestamp with time zone not null,
    constraint uk_oauth2_refresh_tokens_token_hash unique (token_hash)
);

create index if not exists idx_oauth2_refresh_tokens_authorization_id
    on oauth2_refresh_tokens (authorization_id);

create index if not exists idx_oauth2_refresh_tokens_family
    on oauth2_refresh_tokens (token_family_id);

create index if not exists idx_oauth2_refresh_tokens_principal_name
    on oauth2_refresh_tokens (principal_name);

create table if not exists oauth2_authorization_consent (
    registered_client_id varchar(100) not null,
    principal_name varchar(200) not null,
    authorities varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);
