package TrustNet::Servers;

# Библиотека функций для работы с серверами сети доверия

# Для вычисления рейтинга серверов нужно:
# 0. Взять последний анонс серверов владельца сервера и поставить максимальный рейтинг всем серверам из данного анонса;
# 1. Взять все доп. удостоверения админов, заверенные владельцем данного сервера (получаем персональные идентификаторы админов);
# 2. Проверить что основное удостоверение данных админов подписаны владельцем данного сервера (получаем ключи админов);
# 2. Взять все анонсы серверов данных админов по их ключам;
# 3. Всем серверам из этих анонсов поставить максимальный рейтинг;

use strict;

# Выводим уровень заверения владельцем данного сервера принадлежности указанного админа к сообществу админов
sub trusted_admin_tag_level {
  my ($dbh, $cfg, $person_id) = @_;
  
  my $c = $dbh->prepare('SELECT level FROM tags WHERE person_id = ? AND tag_uuid = ? AND sign_pub_key_id = ?');
  $c->execute($person_id, '00000000-0000-0000-0000-000000000000', $cfg->{server_owner}->{public_key_id});
  my ($level) = $c->fetchrow_array();
  $c->finish;

  return($level);
};

# Ищем ключ админа, привязанный к персональному идентификатору админа владельцем данного сервера
sub trusted_admin_attestate {
  my ($dbh, $cfg, $person_id) = @_;
  
  my $c = $dbh->prepare('SELECT att.public_key_id, att.level 
                          FROM attestations att
                          WHERE 
                            att.person_id = ? AND 
                            att.sign_pub_key_id = ? AND 
                            att.is_current');
  $c->execute($person_id, $cfg->{server_owner}->{public_key_id});
  my ($public_key_id) = $c->fetchrow_array();
  $c->finish;
  
  return($public_key_id, $level);
};

# Возвращаем последний анонсы серверов данного админа (по публичному ключу)
sub trusted_admin_announce {
  my ($dbh, $cfg, $public_key_id) = @_;
  
  my $c = $dbh->prepare('SELECT sa.servers
                          FROM servers_announces sa
                          WHERE sa.sign_pub_key_id = ?');
  $c->execute($public_key_id);
  my ($servers) = $c->fetchrow_array();
  $c->finish;
  
  return($servers);
};

1;

