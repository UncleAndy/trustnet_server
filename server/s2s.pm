package s2s;

use strict;
use GPLVote::SignDoc::Client;
use Switch;

sub process {
  my ($query, $dbh, $cfg) = @_;
  my $result = {status => 400, error => 'Bad request path' };
  
  my $uri = $ENV{'REQUEST_URI'};
  if ($uri =~ /^(.+)\?/) {
    $uri = $1;
  };
  
  switch ($uri) {
    case '/s2s/new_packets' {
      # Получение списка идентификаторов новых пакетов с другого сервера
      # 1. Определяем исходящий сервер по полю host;
      # 2. Ищем в сети доверия подписанное владельцем данного сервера удостоверение админа сервера источника и публичного транспортного ключа сервера-источника;
      # 3. Проверяем подпись документа-анонса транспортным ключем сервера источника;
      
      my $request_data = js::to_hash($query->param('POSTDATA'));
            
      if (defined($request_data) && ($request_data ne '')) {
        # Для работы с сервером используем служебные таблицы servers (сервера у которых rating == 127) и связанную с ней transport_public_keys
        # Выбираем данные сервера
        my $c = $dbh->prepare('SELECT s.id, pk.public_key
          FROM servers s, transport_public_keys pk 
          WHERE s.host = ? AND s.rating = 127 AND
            pk.server_id = s.id');
        $c->execute($request_data->{host});
        my ($server_id, $public_key) = $c->fetchrow_array();
        $c->finish;
        
        # Проверяем соответствие идентификатора публичного ключа
        my $public_key_id = calc_pub_key_id($public_key);
        if ($public_key_id eq $request_data->{sign_public_key_id}) {
          # Проверяем подпись данных
          my $signed_data = $request_data->{host}.'#'.join(',', $request_data->{ids});
          if (user_sign_is_valid($public_key, $request_data->{sign}, $signed_data, 1)) {
            # Проверяем наличие документов с данным id в локальной базе и если пакета нет, ставим его в очередь закачки
            foreach my $packet_id (@{$request_data->{ids}}) {
              $dbh->do('INSERT INTO load_packets_queue (id, server_id, t_create) VALUES (?, ?, ?) 
                WHERE NOT EXISTS (SELECT id FROM load_packets_queue WHERE id = ?) AND
                NOT EXISTS (SELECT id FROM packets WHERE id = ?)', undef,
                $packet_id, $server_id, time(),
                $packet_id,
                $packet_id);
            };
            $result->{status} = 200;
            $result->{error} = '';
          } else {
            $result->{status} = 412;
            $result->{error} = 'Sign is bad';
          };
        } else {
          $result->{status} = 412;
          $result->{error} = 'Wrong public key id for server';
        };
      }
    }
    case /^\/s2s\/get_packet\/(.+)$/ {
      # Вывод данных пакета по идентификатору
      my $packet_id = $1;
      
      if (defined($packet_id) && ($packet_id ne '')) {
        my $c = $dbh->prepare('SELECT * FROM packets WHERE id = ?');
        $c->execute($packet_id);
        my $packet = $c->fetchrow_hashref();
        $c->finish;

        if (defined($packet) && ($packet ne '')) {
          $result->{status} = 200;
          $result->{packet} = js::from_hash($packet);
        } else {
          $result->{status} = 404;
          $result->{error} = 'Packet not found';
        };
      } else {
        $result->{status} = 400;
        $result->{error} = 'Packet ID parameter absent';
      }
    }
  }
  
  return($result);
}

1;
