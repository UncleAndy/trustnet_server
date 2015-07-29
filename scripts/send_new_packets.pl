#!/usr/bin/env perl

########################################################################
# Скрипт отправки новых пакетов с данного сервера на связанные с ним
# Данные о новых пакетах беруться из стандартной таблицы new_packets
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
use HTTP::Request;
use Data::Dumper;
use URI::Encode qw(uri_encode uri_decode);
use utf8;
use Encode qw(encode decode_utf8);

use vars qw($cfg $dbh $packet_types $need_exit);

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

proc::to_syslog("[S2S send] Start...");

$packet_types = {
  'ATTESTATION' => { insert_func => \&insert_attestation },
  'TRUST'       => { insert_func => \&insert_trust },
  'TAG'         => { insert_func => \&insert_tag },
  'MESSAGE'     => { insert_func => \&insert_message },
  'PUBLIC_KEY'  => { insert_func => \&insert_public_key },
};

$SIG{INT} = \&exit_signal;
$need_exit = 0;
while (!$need_exit) {
	$dbh = db::check_db_connect($dbh, $cfg->{db}->{host}, $cfg->{db}->{port}, $cfg->{db}->{name}, $cfg->{db}->{user}, $cfg->{db}->{password}, 10);

	my $send_lists = {};

	# Текущее количество серверов для отправки пакетов
	my $c = $dbh->prepare('SELECT * FROM servers WHERE rating = 127');
	$c->execute();
	while (my $server = $c->fetchrow_hashref()) {
		my @packets_list;
		# Выбираем пакеты не старее суток, для которых количество отправок меньше количества серверов
		my $new_packets_processed_time = $cfg->{new_packets_processed_time} || 24*3600;
		my $cc = $dbh->prepare('SELECT p.* FROM new_packets np, packets p WHERE np.count_sended < ? AND np.t_create >= ? AND np.packet_id = p.id');
		$cc->execute($send_servers_count, time() - $new_packets_processed_time);
		while (my $packet = $cc->fetchrow_hashref()) {
			# Сначала проверяем нет-ли сервера назначения в path пакета
			if ($packet->{path} ~= /(^| )($server->{host})($| )/) {
				# Проверяем есть-ли сервер среди отправленных и добавляем если нет
				mark_packet_as_sended($packet->{id}, $server->{id}) if (!is_packet_server_sended($packet->{id}, $server->{id}));
				next;
			};
			
			# Проверяем нет-ли сервера назначения в списке серверов пакета, куда он уже отправлялся
			if (is_packet_server_sended($packet->{id}, $server->{id})) {
				next;
			};
			
			push(@send_list, $packet->{id});
		};
		$cc->finish;
		
		$send_lists->{$server->{id}} = { host => $server->{host}, list => \@send_lists };
	};
	$c->finish;
	
	# Производим рассылку по серверам с непустым списком пакетов
	foreach my $server_id (keys %{$send_list}) {
		my $host = $send_list->{$server_id}->{host};
		my $list = $send_list->{$server_id}->{list};
	
		next if (!defined($list) || ($#{$list} < 0));
	
		my $ua = LWP::UserAgent->new(keep_alive => 1, $cfg->{http_timeout} || 10);
		
		my $sign_data = $cfg->{site}.'#'.join(',', @{$list});
		my ($sign, $transport_key_id) = sign_data_transport_key($sign_data);
		my $send_packet = {
			host => $cfg->{site},
			admin_personal_id => $cfg->{server_owner}->{personal_id},
			ids => $list,
			sign => $sign,
			sign_public_key_id => $transport_key_id,
		};
		
		my $send_packet_json = js::from_hash($send_packet);
		my $url = 'http://'.$host.'/s2s/new_packets';
		
		my $req = HTTP::Request->new( 'POST', $url );
		$req->header( 'Content-Type' => 'application/json' );
		$req->content( $send_packet_json );
		my $response = $ua->request($req);
		
		if ($response->is_success) {
			my $json_response = js::to_hash($response->decoded_content);
			
			if (defined($json_response) && ($json_response ne '') && defined($json_response->{status}) && ($json_response->{status} eq '200')) {
				# Отмечаем все пакеты из данного списка как отправленные на данные сервер
				foreach my $packet_id (@{$list}) {
					mark_packet_as_sended($packet_id, $server_id);
				};
			};
		};
	};
	$dbh->commit();
	
	# Очищаем список новых пакетов от уже отправленных или устаревших
	clean_old_new_packets();
	$dbh->commit();
	
	sleep(10);
};
proc::to_syslog("[S2S send] Finished.");

sub is_packet_server_sended {
	my ($packet_id, $server_id) = @_;
	
	my $c = $dbh->prepare('SELECT id FROM new_packets_sended_servers WHERE new_packet_id = ? AND server_id = ?');
	$c->execute($packet_id, $server_id);
	my ($is_exists) = $c->fetchrow_array();
	$c->finish;
	
	return($is_exists);
};

sub mark_packet_as_sended {
	my ($packet_id, $server_id) = @_;
	
	$dbh->do('INSERT INTO new_packets_sended_servers (new_packet_id, server_id) VALUES (?, ?)', undef, $packet_id, $server_id);
	$dbh->do('UPDATE new_packets SET count_sended = (SELECT COUNT(*) FROM new_packets_sended_servers WHERE new_packet_id = ?) WHERE packet_id = ?', undef, $packet_id, $packet_id);
};

sub exit_signal {
	$SIG{INT} = \&exit_signal;
	proc::to_syslog("[S2S send] INT SIGNAL: exit...");
	
	$need_exit = 1;
};

sub sign_data_transport_key {
	my ($data) = @_;

	my $public_transport_key = stripe_public_key($cfg->{server_transport_key}->{public});
	my $transport_key_id = calc_pub_key_id($public_transport_key);

	my $sign_rsa = Crypt::OpenSSL::RSA->new_private_key($cfg->{server_transport_key}->{private});
	$sign_rsa->use_sha256_hash;
	my $sign = $sign_rsa->sign($data);
	my $sign_base64 = encode_base64( $sign, '' );
	
	return($sign_base64, $transport_key_id);
};

sub stripe_public_key {
	my ($pub_key) = @_;
	
  $pub_key =~ s/^.+\n//g;
  $pub_key =~ s/\n.+$//g;
  $pub_key =~ s/\n//g;

	return($pub_key);
};

sub clean_old_new_packets {
	
	#### Сначала удаляем устаревшие
	my $time_limit = time() - ($cfg->{new_packets_clear_time} || 7*24*3600);
	# Чистим new_packets_sended_servers
	$dbh->do('DELETE FROM new_packets_sended_servers WHERE new_packetid IN (SELECT packet_id FROM new_packets WHERE t_create <= ?)', undef, $time_limit);
	# Чистим new_packets
	$dbh->do('DELETE FROM new_packets WHERE t_create <= ?', undef, $time_limit);
	
	### Удаляем те записи, в которых количество отправок равно количству серверов для отправки
	my $c = $dbh->prepare('SELECT count(*) FROM servers WHERE rating = 127');
	$c->execute();
	my ($send_servers_count) = $c->fetchrow_array();
	$c->finish;

	if ($send_servers_count > 0) {
		# Чистим new_packets_sended_servers
		$dbh->do('DELETE FROM new_packets_sended_servers WHERE new_packetid IN (SELECT packet_id FROM new_packets WHERE count_sended >= ?)', undef, $send_servers_count);
		# Чистим new_packets
		$dbh->do('DELETE FROM new_packets WHERE count_sended >= ?', undef, $send_servers_count);
	};
};
