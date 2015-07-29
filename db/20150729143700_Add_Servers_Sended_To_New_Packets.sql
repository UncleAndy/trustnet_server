ALTER TABLE new_packets ADD COLUMN t_create INTEGER DEFAULT 0;
ALTER TABLE new_packets ADD COLUMN count_sended INTEGER DEFAULT 0;
ALTER TABLE new_packets RENAME COLUMN id_packet TO packet_id;
CREATE INDEX new_packets_count_create_idx ON new_packets (count_sended, t_create);

CREATE TABLE new_packets_sended_servers (
    id bigserial NOT NULL PRIMARY KEY,
	new_packet_id BIGINT NOT NULL,
	server_id BIGINT NOT NULL
);
CREATE INDEX new_packets_sended_servers_idx ON new_packets_sended_servers (new_packet_id, server_id);
