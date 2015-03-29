#!/usr/bin/perl

# FastCGI обрабатывающий запросы в систему:

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
use Digest::SHA qw(sha256_base64);
use Crypt::OpenSSL::RSA;
use MIME::Base64 qw(encode_base64);
use LWP::UserAgent;
use Data::Dumper;
use URI::Encode qw(uri_encode uri_decode);
use Template;
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

$dbh = db::check_db_connect($dbh, $cfg->{db}->{host}, $cfg->{db}->{port}, $cfg->{db}->{name}, $cfg->{db}->{user}, $cfg->{db}->{password});

# Начало FastCGI цикла рабочего процесса
while (my $query = new CGI::Fast) {
  $pm->pm_pre_dispatch();

  my $result = {
    'status' => 0,
    'error' => '',
  };

  ########################################
  
  my $site = $cfg->{site};

  # По URI определяем команду
  my $uri = $ENV{'REQUEST_URI'};
  if ($uri =~ /^(.+)\?/) {
    $uri = $1;
  };
  
  switch ($uri) {
    case '/' {
      do_template($query, 'karkas.tpl', { contentsection => 'c_index.tpl' });
    }

    # Клиентские URI
    # Получение данных приложением с сервера
    case '/get/time' {
      # Возвращает только текущее время сервера
      $result->{time} = time();
      $result->{packet} = {};
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
        my $c = $dbh->prepare('SELECT sender, data, sign FROM messages WHERE id = ?');
        $c->execute($id);
        my $message = $c->fetchrow_array());
        $c->finish;
        
        $result->{time} = time();
        $result->{packet} = {};
        $result->{packet}->{type} = 'MESSAGE';
        $result->{packet}->{from} = $message->{sender};
        $result->{packet}->{to} = $message->{receiver};
        $result->{packet}->{data} = $message->{data};
        $result->{packet}->{sign} = $message->{sign};
      } else {
        $result->{status} = 400;
        $result->{error} = 'Message ID parameter absent';
      }
    }

    # Отправка данных с клиента на сервер
    case '/put/public_key' {
      # Парсим JSON пакет из POST данных
      my $doc = json_from_post($query);
      
      if (defined($doc) && ($doc ne '')) {
      
      
      
      
      
      } else {
        $result->{status} = 400;
        $result->{error} = 'Input document absent';
      }
    }
    case '/put/attestation' {
    }
    case '/put/tag' {
    }
    case '/put/message' {
    }


    # Межсерверные URI
    



    else {
      do_template($query, 'karkas.tpl', { contentsection => 'c_bad_request.tpl' });
    };
  };

  ########################################

  $pm->pm_post_dispatch();
};
closelog();

sub to_syslog {
  my ($msg) = @_;
  syslog("alert", $msg);
};

sub do_template
{
    my ($query, $karkas, $prms) = @_;

    my $vars = {
        env => \ %ENV,
        header => 'b_header.tpl',
        contentsection => 'c_index.tpl',
        footer => 'b_footer.tpl',
        cfg => $cfg,
    };

    foreach my $k (keys %$prms)
    {
        $vars->{$k} = $prms->{$k};
    };

    my $include_path = $cfg->{tmpl_path};

    my $out;
    my $tt = Template->new({
        START_TAG       => quotemeta('<?'),
	END_TAG         => quotemeta('?>'),
	INCLUDE_PATH    => $include_path,
	INTERPOLATE     => 0,
	AUTO_RESET      => 1,
	ERROR           => '_error',
	EVAL_PERL       => 1,
	CACHE_SIZE      => 1024,
	COMPILE_EXT     => '.tpl',
	COMPILE_DIR     => '/var/tmp/tt2cache',
	LOAD_PERL       => 1,
	RECURSION       => 1,
	OUTPUT          => \ $out,
    });

    my $ttresult = $tt->process($karkas, $vars);

    print $query->header(-type=>'text/html',-charset=>'UTF-8');

    print "\n";
    print $out;
};

sub json_from_post {
    my ($query) = @_;
    
    return(js::to_hash($query->param('POSTDATA')));
};