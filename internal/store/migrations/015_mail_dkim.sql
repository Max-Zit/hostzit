-- DKIM keys of the customers' domains: website mail that HostZit sends
-- itself is signed with them (the private key is sealed like other secrets).
CREATE TABLE mail_dkim (
    domain      text PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    selector    text NOT NULL,
    private_key text NOT NULL,
    record      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mail_dkim_customer ON mail_dkim(customer_id);
