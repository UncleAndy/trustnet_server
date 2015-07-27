#!/usr/bin/env perl

########################################################################
# Скрипт получения новых пакетов с другого сервера
# Идентификаторы пакетов беруться из очереди пакетов на закачку
# load_packets_queue
########################################################################

BEGIN {
  use YAML;

  my $cfg;
  if (defined($ARGV[0]) && ($ARGV[0] ne '')) {
    if (-e $ARGV[0]) {
      $cfg = YAML::LoadFile($ARGV[0]);
    } else {
      print STDERR 'Can not exists config file "'.$ARGV[0].'"'."\n";
      exit(1);
    };
  } else {
    print STDERR "I need config file path to command line\n";
    exit(1);
  };

  require $cfg->{'base_path'}.'/libs/proc.pm';

  proc::check_command($cfg);
  proc::check_for_one_instance($cfg);

  sub _get_config {
    return $cfg;
  };
}

use strict;
use POSIX;
use Sys::Hostname;
use Sys::Syslog;
use Time::HiRes qw(usleep);
use Switch;
use DBI;
use MIME::Base64 qw(encode_base64);
use LWP::UserAgent;
use Data::Dumper;
use URI::Encode qw(uri_encode uri_decode);
use utf8;
use Encode qw(encode decode_utf8);

use vars qw($cfg $dbh $packet_types);

# Получение конфига из блока BEGIN
$cfg = _get_config();

require $cfg->{'base_path'}.'/libs/proc.pm';
require $cfg->{'base_path'}.'/libs/js.pm';
require $cfg->{'base_path'}.'/libs/db.pm';

# Демонизация
proc::demonize($cfg->{'log_file'}, $cfg->{'pid_file'});

# Инициализация логирования в syslog
Sys::Syslog::setlogsock('unix');
openlog($cfg->{product_name},'ndelay,pid', 'LOG_LOCAL6');

proc::to_syslog("[S2S] Start...");

$packet_types = {
  'ATTESTATION' => { insert_func => \&insert_attestation },
  'TRUST'       => { insert_func => \&insert_trust },
  'TAG'         => { insert_func => \&insert_tag },
  'MESSAGE'     => { insert_func => \&insert_message },
  'PUBLIC_KEY'  => { insert_func => \&insert_public_key },
};

while (1) {
	$dbh = db::check_db_connect($dbh, $cfg->{db}->{host}, $cfg->{db}->{port}, $cfg->{db}->{name}, $cfg->{db}->{user}, $cfg->{db}->{password}, 10);

	my $ua = LWP::UserAgent->new(keep_alive => 1, $cfg->{http_timeout} || 10);

	my $c->prepare('SELECT q.id, s.host FROM load_packets_queue q, servers ORDER BY t_create');
	$c->execute();
	while (my ($packet_id, $host) = $c->fetchrow_array()) {
		proc::to_syslog("[S2S] Get new packet ".$packet_id." from ".$host);
		
		my $uri_packet_id = uri_encode($packet_id);
		my $url = 'http://'.$host.'/s2s/get_packet/'.$uri_packet_id;
		my $response = $ua->get($url);
		
		if ($response->is_success) {
			my $json_response = js::to_hash($response->decoded_content);
			
			if (defined($json_response) && ($json_response ne '') && ($json_response->{status} eq '200')) {
				my $packet = $json_response->{packet};
				my $packet_type = $packet_types->{$packet->{doc_type}};
				if (defined($packet_type) && ($packet_type ne '')) {
					$packet->{path} = $packet->{path}.' '.$cfg->{site};
					$packet_type->{insert_func}->($packet);
				} else {
					proc::to_syslog("[S2S] Unknown packet type: '".$packet->{doc_type}."'";
				}
			} else {
				proc::to_syslog("[S2S] HTTP error when download new packet: ".Dumper($response));
			};
	  }
		else {
			proc::to_syslog("[S2S] HTTP error when download new packet: ".Dumper($response));
		}
				
		
		
		
		
	};
	$c->finish();
	sleep(10);
};

# Функции вставки пакетов по типам

sub insert_public_key {
	my ($packet) = @_;

	return if (is_packet_exists($packet->{id}, 'public_keys'));
	
	my $doc = js::to_hash($packet->{doc});
	my $data = js::to_hash($doc->{dec_data});

	if (defined($data) && ($data ne '')) {
		my $content_id = content_id($data->[0].':'.$packet->{sign_pub_key_id}.':'.$data->[2]);
		
		$dbh->do('INSERT INTO public_keys (id, content_id, time, path, doc, doc_type, public_key, public_key_id, sign, sign_pub_key_id, sign_person_id, is_current) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'f\')', undef, 
			$packet->{id}, 
			$content_id,
			$packet->{time}, 
			$packet->{path}, 
			$packet->{doc}, 
			'PUBLIC_KEY',
			$data->[2],
			$packet->{sign_pub_key_id},
			$packet->{sign}, 
			$packet->{sign_pub_key_id},
			$data->[0]);
			
		if (!$dbh->err) {
			set_current_flag($content_id, 'public_keys');
			notify_new_packet($packet_id);
			post_process($packet_id, $doc, $sign, $sign_pub_key_id);
		} else {
			to_syslog('DB ERROR: '.$dbh->errstr);
		};
	};
};

sub insert_attestation {
	my ($packet) = @_;
	
	return if (is_packet_exists($packet->{id}, 'attestations'));
	
	my $doc = js::to_hash($packet->{doc});
	my $data = js::to_hash($doc->{dec_data});

	if (defined($data) && ($data ne '')) {
		my $person_id = $data->[2];
		my $public_key_id = $data->[3];
		my $level = $data->[4];
	
		# Для идентификатора контента используются:
		# Персональный идентификатор автора документа
		# Идентификатор ключа подписания автора документа
		# Персональный идентификатор заверяемого
		# Идентификатор ключа заверяемого
		my $content_id = content_id($data->[0].':'.$packet->{sign_pub_key_id}.':'.$person_id.':'.$public_key_id);

		$dbh->do('INSERT INTO attestations (id, content_id, time, path, doc, doc_type, person_id, public_key_id, level, sign, sign_pub_key_id, sign_person_id, is_current) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'f\')', undef,
			$packet->{id}, 
			$content_id,
			$packet->{time}, 
			$packet->{path}, 
			$packet->{doc},
			'ATTESTATION',
			$person_id,
			$public_key_id,
			$level,
			$packet->{sign},
			$packet->{sign_pub_key_id},
			$data->[0]
			);
			
		if (!$dbh->err) {
			set_current_flag($content_id, 'attestations');
			notify_new_packet($packet_id);
			post_process($packet_id, $doc, $sign, $sign_pub_key_id);
		} else {
			to_syslog('DB ERROR: '.$dbh->errstr);
		};
	}
};

sub insert_trust {
	my ($packet) = @_;
	
	return if (is_packet_exists($packet->{id}, 'trusts'));
	
	my $doc = js::to_hash($packet->{doc});
	my $data = js::to_hash($doc->{dec_data});

	if (defined($data) && ($data ne '')) {
		my $person_id = $data->[2];
		my $level = $data->[3];
	
		# Для идентификатора контента используются:
		# Персональный идентификатор автора документа
		# Идентификатор ключа подписания автора документа
		# Персональный идентификатор заверяемого
		my $content_id = content_id($data->[0].':'.$packet->{sign_pub_key_id}.':'.$person_id);

		$dbh->do('INSERT INTO trusts (id, content_id, time, path, doc, doc_type, person_id, level, sign, sign_pub_key_id, sign_person_id, is_current) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'f\')', undef,
			$packet->{id},
			$content_id,
			$packet->{time}, 
			$packet->{path}, 
			$packet->{doc},
			'TRUST',
			$person_id,
			$level,
			$packet->{sign},
			$packet->{sign_pub_key_id},
			$data->[0]
			);
		
		if (!$dbh->err) {
			set_current_flag($content_id, 'trusts');
			notify_new_packet($packet_id);
			post_process($packet_id, $doc, $sign, $sign_pub_key_id);
		} else {
			to_syslog('DB ERROR: '.$dbh->errstr);
		};
	};
};

sub insert_tag {
	my ($packet) = @_;
	
	return if (is_packet_exists($packet->{id}, 'tags'));
	
	my $doc = js::to_hash($packet->{doc});
	my $data = js::to_hash($doc->{dec_data});

	if (defined($data) && ($data ne '')) {
		my $tag_id = $data->[2];
		my $person_id = $data->[3];
		my $tag_data = $data->[4];
		my $level = $data->[5];

		# Для идентификатора контента используются:
		# Персональный идентификатор автора документа
		# Идентификатор ключа подписания автора документа
		# Идентификатор тэга
		# Привязываемый персональный идентификатор
		my $content_id = content_id($data->[0].':'.$packet->{sign_pub_key_id}.':'.$data->[2].':'.$data->[3]);
		
		$dbh->do('INSERT INTO tags (id, content_id, time, path, doc, doc_type, tag_uuid, person_id, tag_data, level, sign, sign_pub_key_id, sign_person_id, is_current) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'f\')', undef,
			$packet->{id}, 
			$content_id,
			$packet->{time}, 
			$packet->{path}, 
			$packet->{doc},
			'TAG',
			$tag_id,
			$person_id,
			$tag_data,
			$level,
			$packet->{sign},
			$packet->{sign_pub_key_id},
			$data->[0]
			);
		
		if (!$dbh->err) {
			set_current_flag($content_id, 'tags');
			notify_new_packet($packet_id);
			post_process($packet_id, $doc, $sign, $sign_pub_key_id);
		} else {
			to_syslog('DB ERROR: '.$dbh->errstr);
		};
	};
};

sub insert_message {
	my ($packet) = @_;
	
	return if (is_packet_exists($packet->{id}, 'messages'));
	
	my $doc = js::to_hash($packet->{doc});
	my $data = js::to_hash($doc->{dec_data});

	if (defined($data) && ($data ne '')) {
		my $receiver = $data->[1];
		my $message = $data->[2];

		# Для идентификатора контента используются:
		my $content_id = content_id($data->[0].':'.$packet->{sign_pub_key_id}.':'.$receiver.':'.$message);
		
		$dbh->do('INSERT INTO messages (id, content_id, time, path, doc, doc_type, receiver, message, sign, sign_pub_key_id, pow_nonce) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef,
			$packet->{id},
			$content_id,
			$packet->{time}, 
			$packet->{path}, 
			$packet->{doc},
			'MESSAGE',
			$receiver,
			$message,
			$packet->{sign},
			$packet->{sign_pub_key_id},
			$packet->{pow_nonce}
			);
		
		if (!$dbh->err) {
			notify_new_packet($packet_id);
			post_process($packet_id, $doc, $sign, $sign_pub_key_id);
		} else {
			to_syslog('DB ERROR: '.$dbh->errstr);
		};
	};
};

# Выставлениек флага актуальных данных. Необходимо для анализа сети доверия логикой сервера
sub set_current_flag {
	my ($content_id, $table) = @_;
	
	$dbh->do('UPDATE '.$table.' SET is_current = (time = (SELECT MAX(time) FROM '.$table.' WHERE content_id = ?)) WHERE content_id = ?', undef, $content_id, $content_id);
};

#############################################################
# Общие функции
#############################################################
# TODO: ВЫНЕСТИ В ОТДЕЛЬНЫЙ МОДУЛЬ!!!

sub is_packet_exists {
  my ($packet_id, $table) = @_;
  
  $table = 'packets' if !defined($table) || ($table eq '');
  my $c = $dbh->prepare('SELECT id FROM '.$table.' WHERE id = ?');
  $c->execute($packet_id);
  my ($pk_id) = $c->fetchrow_array;
  $c->execute();
  
  return(defined($pk_id) && ($pk_id ne ''));
};

sub content_id {
  my ($str) = @_;
  
  return(sha512_base64($str));
};

# TODO: Нотификация о новом пакете - пометка пакета как требуемого для отправки на другие сервера
sub notify_new_packet {
  my ($packet_id) = @_;

  $dbh->do('INSERT INTO new_packets (id_packet) VALUES (?)', undef, $packet_id);
};

# Постобработка нового документа
sub post_process {
	my ($packet_id, $doc, $sign, $sign_pub_key_id) = @_;
  
  return if (!defined($doc) || ($doc eq ''));

  # Если это подпись другого сервера админом данного - помещаем сервер в базу серверов для отправки новых пакетов
  if (defined($doc->{type}) && ($doc->{type} eq 'TAG') && ($sign_pub_key_id eq $cfg->{server_owner}->{public_key_id})) {
    my $data = js::to_hash($doc->{dec_data});
    return if (!defined($data) || ($data eq ''));
    
    if ($data->[2] eq 'AAAAAAAAAAAAAAAAAAAAAA==') {
      my $server_data = js::to_hash($data->[4]);
      return if (!defined($server_data) || ($server_data eq '') || !defined($server_data->{host}) || ($server_data->{host} eq '') || ($server_data->{host} eq $cfg->{site}));
      
      # Проверяем нет-ли уже такого сервера в БД
      my $c = $dbh->prepare('SELECT s.id, s.rating, pk.public_key, pk.public_key_id FROM servers s, transport_public_keys pk WHERE s.host = ? AND pk.server_id = s.id');
      $c->execute($server_data->{host});
      my ($server_id, $server_rating, $server_pub_key, $server_pub_key_id) = $c->fetchrow_array();
      $c->finish;
      
      if (defined($server_id) && ($server_id ne '')) {
        # Проверяем рейтинг и ставим 127 если не такой
        $dbh->do('UPDATE servers SET rating = 127 WHERE id = ?', undef, $server_id) if (!defined($server_rating) || ($server_rating ne '127'));
        # Проверяем соответствующий серверу публичный ключ
        if ($server_data->{public_key} ne $server_pub_key) {
          # Если не совпадает - обновляем
          my $new_server_pub_key_id = calc_pub_key_id($server_data->{public_key});
          $dbh->do('UPDATE transport_public_keys SET public_key = ?, public_key_id = ? WHERE server_id = ?', undef, 
            $server_data->{public_key}, new_server_pub_key_id, $server_id);
        };
      } else {
        # Добавляем сервер и публичный ключ
        my $new_server_id = $dbh->do('INSERT INTO servers (host, t_create, rating) VALUES (?, ?, 127) RETURNING id', undef, $server_data->{host}, time());
        $dbh->do('INSERT INTO transport_public_keys (server_id, public_key, public_key_id) VALUES (?, ?, ?)', undef, $new_server_id, $server_data->{public_key}, new_server_pub_key_id);
      };
    };
  };
};
