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
use Crypt::RSA;
use MIME::Base64 qw(encode_base64);
use String::Random;
use LWP::UserAgent;
use Data::Dumper;
use HTML::QRCode;
use URI::Encode qw(uri_encode uri_decode);
use Template;
use utf8;
use Encode qw(encode decode_utf8);

use GPLVote::SignDoc::Client;
#no warnings;

use vars qw($cfg $dbh);

# Получение конфига из блока BEGIN
$cfg = _get_config();

use FCGI::ProcManager::Dynamic;
require $cfg->{'base_path'}.'/libs/proc.pm';
require $cfg->{'base_path'}.'/libs/js.pm';
require $cfg->{'base_path'}.'/libs/db.pm';

# Демонизация
proc::demonize($cfg->{'log_file'}, $cfg->{'pid_file'});

# Инициализация логирования в syslog
Sys::Syslog::setlogsock('unix');
openlog($cfg->{product_name},'ndelay,pid', 'LOG_LOCAL6');

to_syslog("Start...");

# Запуск менеджера рабочих процессов
my $pm = FCGI::ProcManager->new({
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
    case '/get/servers' {
      
    }






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
