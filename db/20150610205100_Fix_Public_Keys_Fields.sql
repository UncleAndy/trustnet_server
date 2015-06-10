ALTER TABLE packets ALTER COLUMN sign_pub_key_id TYPE varchar(128);
ALTER TABLE public_keys ALTER COLUMN public_key_id TYPE varchar(128);
ALTER TABLE attestations ALTER COLUMN public_key_id TYPE varchar(128);
ALTER TABLE messages ALTER COLUMN receiver TYPE varchar(128);
