#!/usr/bin/perl

# FastCGI обрабатывающий запросы в систему:

# Возвращаемые статусы:
# 200 - ок
# 202 - такие данные уже есть на сервере
# 400 - неверные параметры запроса
# 402 - неверная подпись данных
# 404 - на сервере отсутствует запрошенные данные
# 412 - на сервере отсутствует публичный ключ по которому можно проверить подпись переданных данных 

##################################################################
# МЕЖСЕРВЕРНОЕ ВЗАИМОДЕСТВИЕ
# - При наличии новых пакетов в цикле по целевым серверам:
#   - Создается анонсирующий пакет со списком id новых пакетов для данного целевого сервера
#   - Все данные пакетов из этого списка размещаются в кэш (Redis)
#   - Для анонсирующего пакета формируется подпись пакета транспортным ключем сервера
#   - Пакет со списком id отправляется на целевой сервер
#   - При приходе запроса на пакеты по id, пакеты беруться только из кэша (Redis)
##################################################################

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

  $cfg->{'fcgi'}->{'host'} = '127.0.0.1' if (!defined($cfg->{'fcgi'}->{'host'}) || ($cfg->{'fcgi'}->{'host'} eq ''));
  $cfg->{'fcgi'}->{'port'} = '9001' if (!defined($cfg->{'fcgi'}->{'port'}) || ($cfg->{'fcgi'}->{'port'} eq ''));
  $cfg->{'fcgi'}->{'listen_queue'} = 128 if (!defined($cfg->{'fcgi'}->{'listen_queue'}) || ($cfg->{'fcgi'}->{'listen_queue'} eq ''));

  $ENV{FCGI_SOCKET_PATH} = $cfg->{'fcgi'}->{'host'}.":".$cfg->{'fcgi'}->{'port'};
  $ENV{FCGI_LISTEN_QUEUE} = $cfg->{'fcgi'}->{'listen_queue'};

  sub _get_config {
    return $cfg;
  };
}

use strict;
use POSIX;
use CGI::Fast qw/:standard :debug/;
use Sys::Hostname;
use Sys::Syslog;
use Time::HiRes qw(usleep);
use Switch;
use DBI;
use Digest::SHA qw(sha256_base64 sha512_base64);
use Digest::Bcrypt;
use Crypt::OpenSSL::RSA;
use MIME::Base64 qw(encode_base64);
use LWP::UserAgent;
use Data::Dumper;
use URI::Encode qw(uri_encode uri_decode);
use utf8;
use Encode qw(encode decode_utf8);

use GPLVote::SignDoc::Client;
#no warnings;

use vars qw($cfg $dbh $packet_types);

# Получение конфига из блока BEGIN
$cfg = _get_config();

use FCGI::ProcManager::Constrained;
require $cfg->{'base_path'}.'/libs/proc.pm';
require $cfg->{'base_path'}.'/libs/js.pm';
require $cfg->{'base_path'}.'/libs/db.pm';

# Модули
require $cfg->{'base_path'}.'/server/setup.pm';
require $cfg->{'base_path'}.'/server/s2s.pm';

# Демонизация
proc::demonize($cfg->{'log_file'}, $cfg->{'pid_file'});

# Инициализация логирования в syslog
Sys::Syslog::setlogsock('unix');
openlog($cfg->{product_name},'ndelay,pid', 'LOG_LOCAL6');

to_syslog("Start...");

$packet_types = {
  'ATTESTATION' => { table => 'attestations',   insert_func => \&insert_attestation },
  'TRUST'       => { table => 'trusts',         insert_func => \&insert_trust },
  'TAG'         => { table => 'tags',           insert_func => \&insert_tag },
};

$ENV{PM_MAX_REQUESTS} = $cfg->{fcgi}->{max_requests};

# Запуск менеджера рабочих процессов
my $pm = FCGI::ProcManager::Constrained->new({
	n_processes => $cfg->{fcgi}->{nprocs},
});
$pm->pm_manage;

####### Начало рабочего процесса #######

# Начало FastCGI цикла рабочего процесса
while (my $query = new CGI::Fast) {
  $pm->pm_pre_dispatch();

  $dbh = db::check_db_connect($dbh, $cfg->{db}->{host}, $cfg->{db}->{port}, $cfg->{db}->{name}, $cfg->{db}->{user}, $cfg->{db}->{password}, 10);
  
  my $result = {
    'status' => 200,
  };
  
  my $site = $cfg->{site};

  # По URI определяем команду
  my $uri = $ENV{'REQUEST_URI'};
  if ($uri =~ /^(.+)\?/) {
    $uri = $1;
  };
  
  switch ($uri) {
    # Клиентские URI
    # Получение данных приложением с сервера
    case '/get/time' {
      # Возвращает только текущее время сервера
      $result->{time} = time();
    }
    case '/get/servers' {
      # В параметре "c" может передаваться максимальное количество возвращаемых серверов
      # Возвращаеются сервера с максимальным рейтингом
      my @servers;
      
      my $count = $cfg->{trust_net}->{servers_count_for_app};
      $count = $query->param('c') if defined($query->param('c')) && ($query->param('c') ne '');
      my $c = $dbh->prepare('SELECT * FROM servers ORDER BY rating desc LIMIT ?');
      $c->execute($count);
      while (my $server = $c->fetchrow_hashref()) {
        push(@servers, $server->{host});
      };
      $c->finish;

      $result->{time} = time();
      $result->{doc} = {};
      $result->{doc}->{type} = 'SERVERS';
      $result->{doc}->{list} = \@servers;
    }
    case '/get/public_key' {
      # В параметре id должен содержаться идентификатор публичного ключа
      my $id = $query->param('id');
      
      $id =~ s/\=+$//g;
      
      if (defined($id) && ($id ne '')) {
        my $c = $dbh->prepare('SELECT public_key FROM public_keys WHERE public_key_id = ?');
        $c->execute($id);
        my ($public_key) = $c->fetchrow_array();
        $c->finish;
        
        if (defined($public_key) && ($public_key ne '')) {
          $result->{time} = time();
          $result->{doc} = {};
          $result->{doc}->{type} = 'PUBLIC_KEY';
          $result->{doc}->{public_key} = $public_key;
        } else {
          $result->{status} = 404;
          $result->{error} = 'Public key absent on server';
        };
      } else {
        $result->{status} = 400;
        $result->{error} = 'Public key ID parameter absent';
      }
    }
    case '/get/messages_list' {
      # В параметре передается, идентифкатор публичного ключа пользователя, количество последних сообщений для скачивания, время последнего скачивания в unixtime
      # Возвращаются идентификаторы определенного количества последних сообщений
      my $id = $query->param('id');
      my $time = $query->param('time');
      my $count = $query->param('c');
      $count = $cfg->{trust_net}->{messages_list_size} if !defined($count) || ($count eq '');
      $count = 1000 if !defined($count) || ($count eq '');
      
      if (defined($id) && ($id ne '')) {
        my @messages;
      
        if (!defined($time) || ($time eq '')) {
          # По умолчанию берем все сообщения за последний месяц
          $time = time() - 30*24*3600;
        };
      
        my $c = $dbh->prepare('SELECT id FROM messages WHERE receiver = ? AND time >= ? ORDER BY time desc LIMIT ?');
        $c->execute($id, $time, $count);
        while (my ($message_id) = $c->fetchrow_array()) {
          push(@messages, $message_id);
        };
        $c->finish;
        
        $result->{time} = time();
        $result->{doc} = {};
        $result->{doc}->{type} = 'LIST_MESSAGES';
        $result->{doc}->{list} = \@messages;
      } else {
        $result->{status} = 400;
        $result->{error} = 'Public key ID parameter absent';
      }
    }
    case '/get/message' {
      # В параметре - id пакета сообщения для получения
      my $id = $query->param('id');
      
      if (defined($id) && ($id ne '')) {
        my $c = $dbh->prepare('SELECT doc, sign_pub_key_id, sign, pow_nonce FROM messages WHERE id = ?');
        $c->execute($id);
        my $message = $c->fetchrow_hashref();
        $c->finish;

        if (defined($message) && ($message ne '')) {
          $result->{time} = time();
          $result->{doc} = js::to_hash($message->{doc});
          $result->{sign_pub_key_id} = $message->{sign_pub_key_id};
          $result->{sign} = $message->{sign};
          $result->{pow_nonce} = $message->{pow_nonce};
        } else {
          $result->{status} = 404;
          $result->{error} = 'Message not found';
        };
      } else {
        $result->{status} = 400;
        $result->{error} = 'Message ID parameter absent';
      }
    }

    ######################################################################
    # Отправка данных с клиента на сервер - один URI для всех типов пакетов
    ######################################################################
    case '/put/packet' {
      my $packet = json_from_post($query);
      my $doc = $packet->{doc} if defined($packet) && ($packet ne '');
      
      if (!defined($doc)) {
        $result->{status} = 400;
        $result->{error} = 'Input document absent';
      } else {
        if (defined($doc) && $doc->{type} eq 'PUBLIC_KEY') {
          my $dec_data = js::to_hash($doc->{dec_data});
        
          my $public_key = $dec_data->[2];
          my $public_key_id = calc_pub_key_id($public_key);
          
          # Проверяем наличие данного ключа в базе
          if (!is_public_key_exists($public_key_id)) {
            # Проверяем подпись
            if (user_sign_is_valid($public_key, $packet->{sign}, sign_str_for_doc($doc), 1)) {
              insert_public_key($doc, $packet->{sign}, $public_key_id);
            } else {
              $result->{status} = 412;
              $result->{error} = 'Sign is bad';
            };
          } else {
            $result->{status} = 202;
          };
        } elsif (defined($doc) && defined($packet_types->{$doc->{type}})) {
          # Общая процедура обработки и добавления пакетов типа ATTESTATE, TRUST и TAG
          my $packet_type = $packet_types->{$doc->{type}};
          $result = add_packet_from_app($packet_type->{insert_func}, $packet, $packet_type->{table}, $result);
        } elsif (defined($doc) && $doc->{type} eq 'MESSAGE') {
          my $string_for_pow = $doc->{doc_id}.':'.$doc->{dec_data}.':'.$doc->{template};
        
          # Проверяем pow пакета
          
          if (pow_level($packet->{pow_nonce}, $string_for_pow) >= 4) {
            # Сохраняем пакет в базе
            $result = add_packet_from_app(\&insert_message, $packet, 'messages', $result, $packet->{pow_nonce});
          } else {
              $result->{status} = 412;
              $result->{error} = 'PoW is bad';
          };
        } else {
          $result->{status} = 400;
          $result->{error} = 'Input document has unknown type';
        }
      }
    }


    ######################################################################
    # Межсерверные URI
    ######################################################################
    
    else {
      if (defined($cfg->{setup_mode}) && ($cfg->{setup_mode} eq '1') && ($query->request_method() eq 'GET')) {
        # Админка если разрешена
        $result = setup::process($query, $dbh, $cfg);
      } else {
        # Межсерверное взаимодействие
        $result = s2s::process($query, $dbh, $cfg);
      }
    };
  };

  $dbh->commit;
  
  json_out($query, $result);

  $pm->pm_post_dispatch();
};
closelog();

######################################################################

sub json_out {
  my ($query, $outhash) = @_;

  print $query->header(-type=>'application/json',-charset=>'UTF-8');

  print js::from_hash($outhash, 1), "\n";
}

sub json_from_post {
    my ($query) = @_;
    
    return(js::to_hash($query->param('POSTDATA')));
};

sub to_syslog {
  my ($msg) = @_;
  syslog("alert", $msg);
};

######################################################################
# Операции с публичным ключем
######################################################################

sub is_public_key_exists {
  my ($public_key_id) = @_;
  
  $public_key_id =~ s/\=+$//g;
  
  # Проверяем наличие данного ключа в базе
  my $c = $dbh->prepare('SELECT id FROM public_keys WHERE public_key_id = ?');
  $c->execute($public_key_id);
  my ($pk_id) = $c->fetchrow_array();
  $c->finish;
  
  return(defined($pk_id) && ($pk_id ne ''));
}

sub get_public_key_by_id {
  my ($public_key_id) = @_;
  
  $public_key_id =~ s/\=+$//g;
  
  # Проверяем наличие данного ключа в базе
  my $c = $dbh->prepare('SELECT public_key FROM public_keys WHERE public_key_id = ?');
  $c->execute($public_key_id);
  my ($public_key) = $c->fetchrow_array();
  $c->finish;
  
  return($public_key);
}

######################################################################
# Обработка входящих документов (от приложения)
######################################################################

sub add_packet_from_app {
  my ($insert_func, $packet, $table, $result, $pow_nonce) = @_;
  
  my $doc = $packet->{doc} if defined($packet) && ($packet ne '');
  
  if (defined($doc) && ($doc ne '')) {
    # Проверяем наличие такого аттестата в базе
    my $packet_id = packet_id($doc);
    if (!is_packet_exists($packet_id, $table)) {
      # Проверяем наличие в базе ключа из подписи
      my $public_key = get_public_key_by_id($packet->{sign_pub_key_id});
      if (defined($public_key) && ($public_key ne '')) {
        # Проверяем подпись
        if ((defined($pow_nonce) && ($pow_nonce ne '')) || doc_sign_is_valid($public_key, $doc, $packet->{sign})) {
          $insert_func->($doc, $packet->{sign}, $packet->{sign_pub_key_id}, $pow_nonce);
        } else {
          $result->{status} = 412;
          $result->{error} = 'Sign is bad';
        };
      } else {
        $result->{status} = 402;
        $result->{error} = 'Public key for signature not found';
      };
    } else {
      $result->{status} = 202;
    };
  } else {
    $result->{status} = 400;
    $result->{error} = 'Input document absent';
  }

  return($result);
};

sub insert_public_key {
  my ($doc, $sign, $sign_pub_key_id) = @_;
  
  # Вычисляем идентификатор пакета
  my $packet_id = packet_id($doc);
  
  # Ищем такой пакет в базе
  if (!is_packet_exists($packet_id, 'public_keys')) {
    my $data = js::to_hash($doc->{dec_data});

    if (defined($data) && ($data ne '')) {
      # Для идентификатора контента используются:
      # Персональный идентификатор автора документа
      # Идентификатор ключа подписания автора документа
      # Публичный ключ
      my $content_id = content_id($data->[0].':'.$sign_pub_key_id.':'.$data->[2]);

      $dbh->do('UPDATE public_keys SET is_current = \'f\' WHERE content_id = ? AND is_current', undef, $content_id);
      
      $dbh->do('INSERT INTO public_keys (id, content_id, time, path, doc, doc_type, public_key, public_key_id, sign, sign_pub_key_id, sign_person_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef, 
        $packet_id, 
        $content_id,
        time(), 
        '', 
        js::from_hash($doc),
        'PUBLIC_KEY',
        $data->[2],
        $sign_pub_key_id,
        $sign, 
        $sign_pub_key_id,
        $data->[0]);
      if (!$dbh->err) {
        notify_new_packet($packet_id);
        post_process($packet_id, $doc, $sign, $sign_pub_key_id);
      } else {
        to_syslog('DB ERROR: '.$dbh->errstr);
      };
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

sub insert_attestation {
  my ($doc, $sign, $sign_pub_key_id) = @_;
  
  my $packet_id = packet_id($doc);
  
  if (!is_packet_exists($packet_id, 'attestations')) {
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
      my $content_id = content_id($data->[0].':'.$sign_pub_key_id.':'.$person_id.':'.$public_key_id);

      $dbh->do('UPDATE attestations SET is_current = \'f\' WHERE content_id = ? AND is_current', undef, $content_id);
      
      $dbh->do('INSERT INTO attestations (id, content_id, time, path, doc, doc_type, person_id, public_key_id, level, sign, sign_pub_key_id, sign_person_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef,
        $packet_id, 
        $content_id,
        time(), 
        '', 
        js::from_hash($doc),
        'ATTESTATION',
        $person_id,
        $public_key_id,
        $level,
        $sign,
        $sign_pub_key_id,
        $data->[0]
        );
      if (!$dbh->err) {
        notify_new_packet($packet_id);
        post_process($packet_id, $doc, $sign, $sign_pub_key_id);
      } else {
        to_syslog('DB ERROR: '.$dbh->errstr);
      };
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

sub insert_trust {
  my ($doc, $sign, $sign_pub_key_id) = @_;
  
  my $packet_id = packet_id($doc);
  
  if (!is_packet_exists($packet_id, 'trusts')) {
    my $data = js::to_hash($doc->{dec_data});
    
    if (defined($data) && ($data ne '')) {
      my $person_id = $data->[2];
      my $level = $data->[3];
    
      # Для идентификатора контента используются:
      # Персональный идентификатор автора документа
      # Идентификатор ключа подписания автора документа
      # Персональный идентификатор заверяемого
      my $content_id = content_id($data->[0].':'.$sign_pub_key_id.':'.$person_id);

      $dbh->do('UPDATE trusts SET is_current = \'f\' WHERE content_id = ? AND is_current', undef, $content_id);
      
      $dbh->do('INSERT INTO trusts (id, content_id, time, path, doc, doc_type, person_id, level, sign, sign_pub_key_id, sign_person_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef,
        $packet_id, 
        $content_id,
        time(), 
        '', 
        js::from_hash($doc),
        'TRUST',
        $person_id,
        $level,
        $sign,
        $sign_pub_key_id,
        $data->[0]
        );
      if (!$dbh->err) {
        notify_new_packet($packet_id);
        post_process($packet_id, $doc, $sign, $sign_pub_key_id);
      } else {
        to_syslog('DB ERROR: '.$dbh->errstr);
      };
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

sub insert_tag {
  my ($doc, $sign, $sign_pub_key_id) = @_;
  
  my $packet_id = packet_id($doc);
  
  if (!is_packet_exists($packet_id, 'tags')) {
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
      my $content_id = content_id($data->[0].':'.$sign_pub_key_id.':'.$data->[2].':'.$data->[3]);

      $dbh->do('UPDATE tags SET is_current = \'f\' WHERE content_id = ? AND is_current', undef, $content_id);
      
      $dbh->do('INSERT INTO tags (id, content_id, time, path, doc, doc_type, tag_uuid, person_id, tag_data, level, sign, sign_pub_key_id, sign_person_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef,
        $packet_id, 
        $content_id,
        time(), 
        '', 
        js::from_hash($doc),
        'TAG',
        $tag_id,
        $person_id,
        $tag_data,
        $level,
        $sign,
        $sign_pub_key_id,
        $data->[0]
        );
      if (!$dbh->err) {
        notify_new_packet($packet_id);
        post_process($packet_id, $doc, $sign, $sign_pub_key_id);
      } else {
        to_syslog('DB ERROR: '.$dbh->errstr);
      };
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

sub insert_message {
  my ($doc, $sign, $sign_pub_key_id, $pow_nonce) = @_;
  
  my $packet_id = packet_id($doc);
  
  if (!is_packet_exists($packet_id, 'messages')) {
    my $data = js::to_hash($doc->{dec_data});
    
    if (defined($data) && ($data ne '')) {
      my $receiver = $data->[1];
      my $message = $data->[2];

      # Для идентификатора контента используются:
      my $content_id = content_id($data->[0].':'.$sign_pub_key_id.':'.$receiver.':'.$message);
      
      $dbh->do('INSERT INTO messages (id, content_id, time, path, doc, doc_type, receiver, message, sign, sign_pub_key_id, pow_nonce) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef,
        $packet_id,
        $content_id,
        time(), 
        '', 
        js::from_hash($doc),
        'MESSAGE',
        $receiver,
        $message,
        $sign,
        $sign_pub_key_id,
        $pow_nonce
        );
      if (!$dbh->err) {
        notify_new_packet($packet_id);
        post_process($packet_id, $doc, $sign, $sign_pub_key_id);
      } else {
        to_syslog('DB ERROR: '.$dbh->errstr);
      };
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

######################################################################

sub packet_id {
  my ($doc) = @_;
  
  return(sha512_base64(_stringify($doc)));
};

sub content_id {
  my ($str) = @_;
  
  return(sha512_base64($str));
};

sub is_packet_exists {
  my ($packet_id, $table) = @_;
  
  $table = 'packets' if !defined($table) || ($table eq '');
  my $c = $dbh->prepare('SELECT id FROM '.$table.' WHERE id = ?');
  $c->execute($packet_id);
  my ($pk_id) = $c->fetchrow_array;
  $c->execute();
  
  return(defined($pk_id) && ($pk_id ne ''));
};

sub _stringify {
  my ($v) = @_;
  
  if ((ref($v) eq '') || (ref($v) eq 'SCALAR')) {
    return($v);
  } elsif (ref($v) eq 'ARRAY') {
    return('['.join(',', map { _stringify($_) } @{$v}).']');
  } elsif (ref($v) eq 'HASH') {
    my $s = '';
    my $sep = '';
    foreach my $key (sort(keys(%{$v}))) {
      $s .= $sep.'"'.$key.'":"'._stringify($v->{$key}).'"';
      $sep = ';';
    }
    return('{'.$s.'}');
  }
};

######################################################################
# Проверка PoW
######################################################################

# Определяем и возвращаем количество нулевых стартовых бит в хэше
sub pow_level {
  my ($pow_nonce, $string_for_pow) = @_;
  
  my $bcrypt = Digest::Bcrypt->new();
  $bcrypt->cost(8);
  $bcrypt->salt(prepare_bcrypt_salt($pow_nonce));
  $bcrypt->add($string_for_pow);
  my $digest = $bcrypt->digest;
  
  my $level = 0;
  my $i = 0;
  while ($i < length($digest)) {
    my $byte = substr($digest, $i, 1);
    
    my $mask = 128;
    while ($mask > 0) {
      if (!(ord($byte) & $mask)) {
        $level++;
      } else {
        return($level);
      };
      $mask = $mask >> 1;
    };
    
    $i++;
  };
  
  return($level);
};

# Big endian 16 bytes returned
sub prepare_bcrypt_salt {
  my ($pow_nonce) = @_;

  # Если после конвертации размер соли меньше 16 байт - дополняем слева нулевыми байтами до нужнгого размера
  my $salt = pack("N", $pow_nonce);
  if (length($salt) < 16) {
    $salt = ("\x00" x (16 - length($salt))).$salt;
  };
  
  return($salt);
}


######################################################################
# Функции проверки ЭЦП документа, подписанного через Sign Doc
######################################################################
sub doc_sign_is_valid {
  my ($pub_key, $doc, $sign) = @_;

  if (defined($pub_key) && ($pub_key ne '')) {
    my $signed_str = sign_str_for_doc($doc);
    return(user_sign_is_valid($pub_key, $sign, $signed_str, 1));
  } else {
    return(undef);
  }
};

# TODO: Нотификация о новом пакете - пометка пакета как требуемого для отправки на другие сервера
sub notify_new_packet {
  my ($packet_id) = @_;

  $dbh->do('INSERT INTO new_packets (packet_id, t_create) VALUES (?, ?)', undef, $packet_id, time());
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

sub sign_str_for_doc {
  my ($doc) = @_;
  
  return('') if !defined($doc);
  return($doc->{site}.":".$doc->{doc_id}.":".$doc->{dec_data}.":".$doc->{template});
}
