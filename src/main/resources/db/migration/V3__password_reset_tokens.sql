create table if not exists password_reset_tokens (
    id uuid primary key,
    user_id uuid not null,
    token_hash varchar(128) not null,
    expires_at timestamp with time zone not null,
    used_at timestamp with time zone,
    created_at timestamp with time zone not null,
    constraint uk_password_reset_tokens_token_hash unique (token_hash),
    constraint fk_password_reset_tokens_user foreign key (user_id) references users (id)
);

create index if not exists idx_password_reset_tokens_user_id
    on password_reset_tokens (user_id);

create index if not exists idx_password_reset_tokens_expires_at
    on password_reset_tokens (expires_at);
