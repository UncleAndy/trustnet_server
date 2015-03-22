CREATE TABLE servers (
    host varchar(128), 
    t_last_online integer, 
    t_create integer,
    t_last_packet_send integer
);
CREATE INDEX servers_host_idx ON servers (host, t_last_online);

CREATE TABLE packets (
    id varchar(90) NOT NULL PRIMARY KEY,
    time integer,
    path text,
    data text,
    data_type varchar(24)
);
CREATE INDEX packets_data_type_idx ON packets (data_type);

CREATE TABLE public_keys (
    public_key text,
    public_key_id varchar(48),
    sign text
) INHERITS (packets);
CREATE INDEX public_keys_id_idx ON public_keys (public_key_id);

CREATE TABLE servers_announces (
    servers text,
    sign text,
    sign_pub_key_id varchar(48)
) INHERITS (packets);
CREATE INDEX public_keys_sign_id_idx ON public_keys (sign_pub_key_id);

CREATE TABLE attestations (
    person_id varchar(90),
    public_key_id varchar(48),
    level integer,
    sign text,
    sign_pub_key_id varchar(48)
) INHERITS (packets);
CREATE INDEX attestations_pub_key_id_idx ON attestations (public_key_id);
CREATE INDEX attestations_link_idx ON attestations (person_id, public_key_id);
CREATE INDEX attestations_sign_pub_key_id_idx ON attestations (sign_pub_key_id);

CREATE TABLE trusts (
    person_id varchar(90),
    level integer,
    sign text,
    sign_pub_key_id varchar(48)
) INHERITS (packets);
CREATE INDEX trusts_person_id_idx ON trusts (person_id);
CREATE INDEX trusts_sign_pub_key_id_idx ON trusts (sign_pub_key_id);

CREATE TABLE tags (
    tag_uuid varchar(24),
    person_id varchar(90),
    data text,
    level integer,
    sign text,
    sign_pub_key_id varchar(48)
) INHERITS (packets);
CREATE INDEX tags_uuid_idx ON tags (tag_uuid, person_id);
CREATE INDEX tags_person_id_idx ON tags (person_id);
CREATE INDEX tags_sign_pub_key_id_idx ON tags (sign_pub_key_id);

CREATE TABLE messages (
    from varchar(48),
    to varchar(48),
    data text,
    sign text
) INHERITS (packets);
CREATE INDEX messages_to_idx ON messages (to);
