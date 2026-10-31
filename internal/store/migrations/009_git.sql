-- Git repositories of the customers (deployed into a folder of a website).
CREATE TABLE git_repos (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        text NOT NULL,
    branch      text NOT NULL,
    target      text NOT NULL,
    remote      text NOT NULL DEFAULT '',
    hook_token  text NOT NULL,
    deployed_at timestamptz,
    deploy_ok   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, name)
);
CREATE UNIQUE INDEX git_repos_token ON git_repos(hook_token);
