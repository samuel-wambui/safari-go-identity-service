alter table users add column if not exists password_login_enabled boolean not null default true;
alter table users add column if not exists last_authentication_method varchar(30);

create table if not exists external_identities (
    id uuid primary key,
    user_id uuid not null,
    provider varchar(30) not null,
    provider_subject varchar(255) not null,
    provider_email varchar(254) not null,
    created_at timestamp with time zone not null,
    updated_at timestamp with time zone not null,
    last_login_at timestamp with time zone,
    constraint uk_external_identities_provider_subject unique (provider, provider_subject),
    constraint uk_external_identities_user_provider unique (user_id, provider)
);

create index if not exists idx_external_identities_user_id
    on external_identities (user_id);

create table if not exists channel_link_challenges (
    id uuid primary key,
    channel varchar(30) not null,
    phone_number varchar(30) not null,
    token_hash varchar(128) not null,
    created_at timestamp with time zone not null,
    expires_at timestamp with time zone not null,
    consumed_at timestamp with time zone,
    status varchar(30) not null,
    requesting_client_id varchar(100),
    version bigint not null default 0,
    constraint uk_channel_link_challenges_token_hash unique (token_hash)
);

create index if not exists idx_channel_link_challenges_phone
    on channel_link_challenges (phone_number);

create index if not exists idx_channel_link_challenges_status
    on channel_link_challenges (status);

create table if not exists channel_authentications (
    id uuid primary key,
    channel varchar(30) not null,
    phone_number varchar(30) not null,
    user_id uuid not null,
    authenticated_at timestamp with time zone not null,
    expires_at timestamp with time zone not null,
    created_at timestamp with time zone not null,
    updated_at timestamp with time zone not null,
    constraint uk_channel_authentications_channel_phone unique (channel, phone_number)
);

create index if not exists idx_channel_authentications_user_id
    on channel_authentications (user_id);
