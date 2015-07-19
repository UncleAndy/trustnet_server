CREATE TABLE load_packets_queue (
    id varchar(90) NOT NULL PRIMARY KEY,
    server_id bigint NOT NULL,
    t_create integer
);
