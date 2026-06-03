begin;

\ir _support/common.psql

select no_plan();

select ok(
    to_regclass('public.scheduler_locks') is not null,
    'scheduler_locks table exists'
);

select is(
    public.rpc_acquire_scheduler_lock('monthly_hash_chain_verify', 3600),
    true,
    'first acquire succeeds'
);

select is(
    public.rpc_acquire_scheduler_lock('monthly_hash_chain_verify', 3600),
    false,
    'second acquire while lease is active is skipped'
);

select is(
    public.rpc_release_scheduler_lock('monthly_hash_chain_verify'),
    true,
    'release after acquire succeeds'
);

select is(
    public.rpc_acquire_scheduler_lock('monthly_hash_chain_verify', 3600),
    true,
    'acquire after release succeeds'
);

update public.scheduler_locks
set acquired_at = statement_timestamp() - interval '2 hours',
    expires_at = statement_timestamp() - interval '1 hour'
where job_name = 'monthly_hash_chain_verify';

select is(
    public.rpc_acquire_scheduler_lock('monthly_hash_chain_verify', 3600),
    true,
    'expired lease can be acquired again'
);

select is(
    public.rpc_release_scheduler_lock('monthly_hash_chain_verify'),
    true,
    'release after expired reacquire succeeds'
);

select is(
    public.rpc_release_scheduler_lock('monthly_hash_chain_verify'),
    false,
    'release without active row returns false'
);

select throws_ok(
    $$select public.rpc_acquire_scheduler_lock('', 3600)$$,
    '22023',
    'invalid_rpc_input',
    'acquire rejects blank job name'
);

select throws_ok(
    $$select public.rpc_acquire_scheduler_lock('invalid-job-name', 3600)$$,
    '22023',
    'invalid_rpc_input',
    'acquire rejects invalid job name characters'
);

select throws_ok(
    $$select public.rpc_acquire_scheduler_lock('monthly_hash_chain_verify', 0)$$,
    '22023',
    'invalid_rpc_input',
    'acquire rejects zero TTL'
);

select throws_ok(
    $$select public.rpc_release_scheduler_lock('invalid-job-name')$$,
    '22023',
    'invalid_rpc_input',
    'release rejects invalid job name characters'
);

select is(
    has_table_privilege('anon', 'public.scheduler_locks', 'select'),
    false,
    'anon has no direct scheduler_locks select'
);

select is(
    has_table_privilege('authenticated', 'public.scheduler_locks', 'select'),
    false,
    'authenticated has no direct scheduler_locks select'
);

select is(
    has_table_privilege('service_role', 'public.scheduler_locks', 'select'),
    false,
    'service_role has no direct scheduler_locks select'
);

select is(
    has_function_privilege(
        'service_role',
        'public.rpc_acquire_scheduler_lock(text, integer)',
        'execute'
    ),
    true,
    'service_role can execute acquire scheduler lock RPC'
);

select is(
    has_function_privilege(
        'anon',
        'public.rpc_acquire_scheduler_lock(text, integer)',
        'execute'
    ),
    false,
    'anon cannot execute acquire scheduler lock RPC'
);

select is(
    has_function_privilege(
        'authenticated',
        'public.rpc_release_scheduler_lock(text)',
        'execute'
    ),
    false,
    'authenticated cannot execute release scheduler lock RPC'
);

select *
from finish();

rollback;
