ALTER TABLE packets ADD COLUMN content_id VARCHAR(128);

CREATE INDEX packets_content_id_idx ON packets (content_id);
CREATE INDEX public_keys_content_id_idx ON public_keys (content_id);
CREATE INDEX sannounces_content_id_idx ON servers_announces (content_id);
CREATE INDEX attestations_content_id_idx ON attestations (content_id);
CREATE INDEX trusts_content_id_idx ON trusts (content_id);
CREATE INDEX tags_content_id_idx ON tags (content_id);
CREATE INDEX messages_content_id_idx ON messages (content_id);
