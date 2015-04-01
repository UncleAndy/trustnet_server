CREATE TABLE servers (
    host varchar(128), 
    rating integer,
    t_last_online integer, 
    t_create integer,
    t_last_packet_send integer
);
CREATE INDEX servers_rating_idx ON servers (rating, t_last_online);
CREATE INDEX servers_host_idx ON servers (host, t_last_online);

CREATE TABLE packets (
    id varchar(90) NOT NULL PRIMARY KEY,
    time integer,
    path text,
    doc_type varchar(24),
    doc text,
    sign text,
    sign_pub_key_id varchar(48)
);
CREATE INDEX packets_data_type_idx ON packets (data_type);

CREATE TABLE public_keys (
    public_key text,
    public_key_id varchar(48)
) INHERITS (packets);
CREATE INDEX public_keys_packets_id_idx ON public_keys (id);
CREATE INDEX public_keys_packets_time_idx ON public_keys (time);
CREATE INDEX public_keys_packets_type_idx ON public_keys (data_type);
CREATE INDEX public_keys_id_idx ON public_keys (public_key_id);

CREATE TABLE servers_announces (
    servers text
) INHERITS (packets);
CREATE INDEX sannounces_packets_id_idx ON servers_announces (id);
CREATE INDEX sannounces_packets_time_idx ON servers_announces (time);
CREATE INDEX sannounces_packets_type_idx ON servers_announces (data_type);
CREATE INDEX sannounces_sign_id_idx ON servers_announces (sign_pub_key_id);

CREATE TABLE attestations (
    person_id varchar(90),
    public_key_id varchar(48),
    level integer
) INHERITS (packets);
CREATE INDEX attestations_packets_id_idx ON attestations (id);
CREATE INDEX attestations_packets_time_idx ON attestations (time);
CREATE INDEX attestations_packets_type_idx ON attestations (data_type);
CREATE INDEX attestations_pub_key_id_idx ON attestations (public_key_id);
CREATE INDEX attestations_link_idx ON attestations (person_id, public_key_id);
CREATE INDEX attestations_sign_pub_key_id_idx ON attestations (sign_pub_key_id);

CREATE TABLE trusts (
    person_id varchar(90),
    level integer
) INHERITS (packets);
CREATE INDEX trusts_packets_id_idx ON trusts (id);
CREATE INDEX trusts_packets_time_idx ON trusts (time);
CREATE INDEX trusts_packets_type_idx ON trusts (data_type);
CREATE INDEX trusts_person_id_idx ON trusts (person_id);
CREATE INDEX trusts_sign_pub_key_id_idx ON trusts (sign_pub_key_id);

CREATE TABLE tags (
    tag_uuid varchar(24),
    person_id varchar(90),
    tag_data text,
    level integer
) INHERITS (packets);
CREATE INDEX tags_packets_id_idx ON tags (id);
CREATE INDEX tags_packets_time_idx ON tags (time);
CREATE INDEX tags_packets_type_idx ON tags (data_type);
CREATE INDEX tags_uuid_idx ON tags (tag_uuid, person_id);
CREATE INDEX tags_person_id_idx ON tags (person_id);
CREATE INDEX tags_sign_pub_key_id_idx ON tags (sign_pub_key_id);

CREATE TABLE messages (
    receiver varchar(48),
    message text,
) INHERITS (packets);
CREATE INDEX messages_packets_id_idx ON messages (id);
CREATE INDEX messages_packets_time_idx ON messages (time);
CREATE INDEX messages_packets_type_idx ON messages (data_type);
CREATE INDEX messages_to_idx ON messages (receiver, time);
