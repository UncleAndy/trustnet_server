CREATE TABLE transport_public_keys (
    id bigserial NOT NULL PRIMARY KEY,
    server_id bigint NOT NULL, 
    public_key text,
    public_key_id varchar(128)
);
CREATE INDEX transport_pub_keys_ids_idx ON transport_public_keys (server_id, public_key_id);

ALTER TABLE servers_announces ADD COLUMN server_id bigint;
ALTER TABLE servers_announces DROP COLUMN servers;

ALTER TABLE packets ADD COLUMN is_current boolean DEFAULT 't';
ALTER TABLE packets ADD COLUMN sign_person_id varchar(128);

CREATE INDEX packets_current_idx ON packets (is_current);
CREATE INDEX public_keys_current_idx ON public_keys (is_current);
CREATE INDEX sannounces_current_idx ON servers_announces (is_current);
CREATE INDEX attestations_current_idx ON attestations (is_current);
CREATE INDEX trusts_current_idx ON trusts (is_current);
CREATE INDEX tags_current_idx ON tags (is_current);
