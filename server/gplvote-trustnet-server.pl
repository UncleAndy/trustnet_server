#!/usr/bin/perl

# FastCGI обрабатывающий запросы в систему:

# Возвращаемые статусы:
# 200 - ок
# 202 - такие данные уже есть на сервере
# 400 - неверные параметры запроса
# 402 - неверная подпись данных
# 404 - на сервере отсутствует запрошенные данные
# 412 - на сервере отсутствует публичный ключ по которому можно проверить подпись переданных данных 

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
use Crypt::OpenSSL::RSA;
use MIME::Base64 qw(encode_base64);
use LWP::UserAgent;
use Data::Dumper;
use URI::Encode qw(uri_encode uri_decode);
use utf8;
use Encode qw(encode decode_utf8);

use GPLVote::SignDoc::Client;
#no warnings;

use vars qw($cfg $dbh);

# Получение конфига из блока BEGIN
$cfg = _get_config();

use FCGI::ProcManager::Constrained;
require $cfg->{'base_path'}.'/libs/proc.pm';
require $cfg->{'base_path'}.'/libs/js.pm';
require $cfg->{'base_path'}.'/libs/db.pm';

# Демонизация
proc::demonize($cfg->{'log_file'}, $cfg->{'pid_file'});

# Инициализация логирования в syslog
Sys::Syslog::setlogsock('unix');
openlog($cfg->{product_name},'ndelay,pid', 'LOG_LOCAL6');

to_syslog("Start...");

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
      $result->{packet} = {};
      $result->{packet}->{type} = 'SERVERS';
      $result->{packet}->{list} = \@servers;
    }
    case '/get/public_key' {
      # В параметре id должен содержаться идентификатор публичного ключа
      my $id = $query->param('id');
      
      if (defined($id) && ($id ne '')) {
        my $c = $dbh->prepare('SELECT public_key FROM public_keys WHERE public_key_id = ?');
        $c->execute($id);
        my ($public_key) = $c->fetchrow_array();
        $c->finish;
        
        if (defined($public_key) && ($public_key ne '')) {
          $result->{time} = time();
          $result->{packet} = {};
          $result->{packet}->{type} = 'PUBLIC_KEY';
          $result->{packet}->{public_key} = $public_key;
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
      # В параметре передается, идентифкатор публичного ключа пользователя и количество последних сообщений для скачивания
      # Возвращаются идентификаторы определенного количества последних сообщений
      my $id = $query->param('id');
      my $count = $query->param('c');
      $count = $cfg->{trust_net}->{messages_list_size} if !defined($count) || ($count eq '');
      
      if (defined($id) && ($id ne '')) {
        my @messages;
      
        my $c = $dbh->prepare('SELECT id FROM messages WHERE receiver = ? ORDER BY time desc LIMIT ?');
        $c->execute($id, $count);
        while (my ($message_id) = $c->fetchrow_array()) {
          push(@messages, $message_id);
        };
        $c->finish;
        
        $result->{time} = time();
        $result->{packet} = {};
        $result->{packet}->{type} = 'LIST_MESSAGES';
        $result->{packet}->{list} = \@messages;
      } else {
        $result->{status} = 400;
        $result->{error} = 'Public key ID parameter absent';
      }
    }
    case '/get/message' {
      # В параметре - id пакета сообщения для получения
      my $id = $query->param('id');
      
      if (defined($id) && ($id ne '')) {
        my $c = $dbh->prepare('SELECT sender, message, sign FROM messages WHERE id = ?');
        $c->execute($id);
        my $message = $c->fetchrow_array();
        $c->finish;

        if (defined($message) && ($message ne '')) {
          $result->{time} = time();
          $result->{packet} = {};
          $result->{packet}->{type} = 'MESSAGE';
          $result->{packet}->{from} = $message->{sender};
          $result->{packet}->{to} = $message->{receiver};
          $result->{packet}->{data} = $message->{message};
          $result->{packet}->{sign} = $message->{sign};
        } else {
          $result->{status} = 404;
          $result->{error} = 'Message not found';
        };
      } else {
        $result->{status} = 400;
        $result->{error} = 'Message ID parameter absent';
      }
    }

    #=========================================================================
    # Отправка данных с клиента на сервер
    case '/put/public_key' {
      my $packet = json_from_post($query);
      my $doc = $packet->{doc} if defined($packet) && ($packet ne '');
      
      if (defined($doc)) {
        my $public_key_id = calc_pub_key_id($doc->{public_key});
        
        # Проверяем наличие данного ключа в базе
        if (!is_public_key_exists($public_key_id)) {
          # Проверяем подпись
          if (user_sign_is_valid($doc->{public_key}, $packet->{sign}, $doc->{code}, 1)) {
            insert_public_key($doc, $public_key_id);
          } else {
            $result->{status} = 412;
            $result->{error} = 'Sign is bad';
          };
        } else {
          $result->{status} = 202;
        };
      } else {
        $result->{status} = 400;
        $result->{error} = 'Input document absent';
      }
    }
    case '/put/attestation' {
      my $packet = json_from_post($query);
      my $doc = $packet->{doc} if defined($packet) && ($packet ne '');
      
      if (defined($doc) && ($doc ne '')) {
        # Проверяем наличие такого аттестата в базе
        my $packet_id = packet_id($doc);
        if (!is_packet_exists($packet_id, 'attestations')) {
          # Проверяем наличие в базе ключа из подписи
          if (is_public_key_exists($packet->{sign_pub_key_id})) {
            # Проверяем подпись
            my $public_key = get_public_key_by_id($packet->{sign_pub_key_id});
            if (doc_sign_is_valid($public_key, $doc)) {
              # Добавляем атестат
              insert_attestation($doc, $packet->{sign}, $packet->{sign_pub_key_id});
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
    }
    case '/put/tag' {
    }
    case '/put/message' {
    }


    #=========================================================================
    # Межсерверные URI
    



    else {
        $result->{status} = 400;
        $result->{error} = 'Bad request path';
    };
  };

  $dbh->commit;
  
  json_out($query, $result);

  $pm->pm_post_dispatch();
};
closelog();

###################################################################################


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

# ============================================================

sub is_public_key_exists {
  my ($public_key_id) = @_;
  
  # Проверяем наличие данного ключа в базе
  my $c = $dbh->prepare('SELECT id FROM public_keys WHERE public_key_id = ?');
  $c->execute($public_key_id);
  my ($pk_id) = $c->fetchrow_array();
  $c->finish;
  
  return(defined($pk_id) && ($pk_id ne ''));
}

sub get_public_key_by_id {
  my ($public_key_id) = @_;
  
  # Проверяем наличие данного ключа в базе
  my $c = $dbh->prepare('SELECT public_key FROM public_keys WHERE public_key_id = ?');
  $c->execute($public_key_id);
  my ($public_key) = $c->fetchrow_array();
  $c->finish;
  
  return($public_key);
}

sub insert_public_key {
  my ($doc, $public_key_id) = @_;
  
  # Вычисляем идентификатор пакета
  my $packet_id = packet_id($doc);
  
  # Ищем такой пакет в базе
  if (!is_packet_exists($packet_id, 'public_keys')) {
    $dbh->do('INSERT INTO public_keys (id, time, path, doc, doc_type, public_key, public_key_id) VALUES (?, ?, ?, ?, ?, ?, ?)', undef, 
      $packet_id, 
      time(), 
      $cfg->{site}, 
      js::from_hash($doc),
      'PUBLIC_KEY',
      $doc->{public_key},
      $public_key_id);
    if (!$dbh->err) {
      notify_new_packet($packet_id);
    } else {
      to_syslog('DB ERROR: '.$dbh->errstr);
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

sub insert_attestation {
  my ($doc, $sign, $sign_pub_key_id) = @_;
  
  my $packet_id = packet_id($doc);
  
  if (!is_packet_exists($packet_id, 'attestations')) {
    my $data = js::to_hash($doc->data);
    
    if (defined($data) && ($data ne '')) {
      my $person_id = $data->[0];
      my $public_key_id = $data->[1];
      my $level = $data->[2];
      
      $dbh->do('INSERT INTO attestations (id, time, path, doc, doc_type, person_id, public_key_id, level, sign, sign_pub_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', undef,
        $packet_id, 
        time(), 
        $cfg->{site}, 
        js::from_hash($doc),
        'ATTESTATION',
        $person_id,
        $public_key_id,
        $level,
        $sign,
        $sign_pub_key_id
        );
      if (!$dbh->err) {
        notify_new_packet($packet_id);
      } else {
        to_syslog('DB ERROR: '.$dbh->errstr);
      };
    };
  } else {
    to_syslog('LOGIC ERROR: Packets IDs DUP!!! For '.Dumper($doc));
  };
};

sub packet_id {
  my ($doc) = @_;
  
  return(sha512_base64(_stringify($doc)));
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
  
  if (ref($v) eq 'SCALAR') {
    return('"'.$v.'"');
  } elsif (ref($v) eq 'ARRAY') {
    return('['.join(',', map { _stringify($_) } @{$v}).']');
  } elsif (ref($v) eq 'HASH') {
    my $s = '';
    my $sep = '';
    foreach my $key (sort(keys(%{$v}))) {
      $s .= $sep.'"'.$key.'":"'._stringify($v->{$key});
      $sep = ';';
    }
    return('{'.$s.'}');
  }
};

#============================================================
# Функции проверки ЭЦП документа, подписанного через Sign Doc
#============================================================
sub doc_sign_is_valid {
  my ($pub_key, $doc) = @_;

  if (defined($pub_key) && ($pub_key ne '')) {
    my $signed_str = $doc->{site}.":".$doc->{doc_id}.":".$doc->{data}.":".$doc->{template};
    
    return(user_sign_is_valid($pub_key, $doc->{sign}, $signed_str, 1));
  } else {
    return(undef);
  }
};


# TODO: Нотификация о новом пакете - пометка пакета как требуемого для отправки на другие сервера
sub notify_new_packet {
  my ($packet_id) = @_;
  
  
  
};
