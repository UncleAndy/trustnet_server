package TrustNet::Servers;

# Библиотека функций для работы с серверами сети доверия

# Для вычисления рейтинга серверов нужно:
# 0. Взять последний анонс серверов владельца сервера и поставить максимальный рейтинг всем серверам из данного анонса;
# 1. Взять все доп. удостоверения админов, заверенные владельцем данного сервера (получаем персональные идентификаторы админов);
# 2. Проверить что основное удостоверение данных админов подписаны владельцем данного сервера (получаем ключи админов);
# 2. Взять все анонсы серверов данных админов по их ключам;
# 3. Всем серверам из этих анонсов поставить максимальный рейтинг;

use strict;


# Выводит персональные идентификаторы админов, заверенные владельцем данного сервера
sub trusted_admins {
  my ($dbh, $cfg) = @_;
  
  my @admins;
  my $c = $dbh->prepare('SELECT person_id FROM tags WHERE tag_uuid = ? sign_pub_key_id = ?');
  $c->execute('00000000-0000-0000-0000-000000000000', $cfg->{server_owner}->{public_key_id});
  while (my ($person_id) = $c->fetchrow_array()) {
    push(@admins, $person_id);
  };
  $c->finish;

  return(\@admins);
};

# Ищем ключ админа, привязанный к персональному идентификатору админа владельцем данного сервера
sub trusted_admin_public_key_id {
  my ($dbh, $cfg, $person_id) = @_;
  
  my $c = $dbh->prepare('SELECT att.public_key_id 
                          FROM attestations att
                          WHERE 
                            att.person_id = ? AND 
                            att.sign_pub_key_id = ? AND 
                            att.level > 10 AND 
                            att.time = (SELECT max(a.time) 
                                          FROM attestations a 
                                          WHERE 
                                            a.person_id = att.person_id AND 
                                            a.sign_pub_key_id = att.sign_pub_key_id)');
  $c->execute($person_id, $cfg->{server_owner}->{public_key_id});
  my ($public_key_id) = $c->fetchrow_array();
  $c->finish;
  
  return($public_key_id);
};

# Возвращаем последний анонс серверов данного админа (по публичному ключу)
sub trusted_admin_announce {
  my ($dbh, $cfg, $public_key_id) = @_;
  
  my $c = $dbh->prepare('SELECT sa.servers
                          FROM servers_announces sa
                          WHERE 
                            sa.sign_pub_key_id = ? AND 
                            sa.time = (SELECT max(saa.time) 
                                          FROM servers_announces saa 
                                          WHERE saa.sign_pub_key_id = sa.sign_pub_key_id)');
  $c->execute($public_key_id);
  my ($servers) = $c->fetchrow_array();
  $c->finish;
  
  return($servers);
};

# Функция для пересчета рейтингов серверов сети доверия
sub calc_ratings {
  my ($dbh, $cfg) = @_;
  
  
};

# Функция пересчета рейтинга серверов сети доверия для определенного владельца
# За основу береться идентификатор ключа владельца сервера
# $owner_id - персональный идентификатор админа
sub calc_ratings_for_admin {
  my ($dbh, $cfg, $owner_id) = @_;
  
  
};

1;

