package TrustNet::Servers;

############################################################################
# Метода анализа сети доверия
############################################################################

# Необходим метод, возвращающий для удостоверения следующие данные:
# 1. Иерархию удостоверений утостоверивших его до указанного уровня
# 1.2. Для каждого из удостоверений удостоверителей выдается:
# 1.2.1. Иерархия уровней доверия данному удостоверителю до указанного уровня
# Вес каждого удостоверителя при удостоверении вычиляется из уровня его удостоверения и уровня его доверия по иерархии доверия

# ВАЖНО!!! Сначала вычисляются уровни доверия по сети TRUST
# Для этого необходима дополнительная таблица trusts_net, в которой будут заносится результаты изменения вычисления результатирующих уровней доверия
# 1. Сумма внешних доверий
# 2. Количество внешних доверий
# При добавлении нового уровня доверия необходимо делать обход по сети и корректировать результатирующие уровни в соответствии с новой информацией

# При добавлении уровня доверия:
# 1. Проверка что у источника доверия уже есть удостоверение с вычисленным уровнем верификации глубиной 1 уровень выше 0.5
# 2. Обновляем цепочку передачи уровней доверия от нового глубиной 6 уровней (с учетом предыдущего уровня доверия)
# 
# При добавлении атестата:
# 1. Если в новом состоянии уровень верификации глубиной 1 пересек отметку в 0.5
# 1.1. Пересчитываем уровни доверия в которых источником является заверяемый по данному атестату
# 2. Формируем уровень верификации на основе уровня верификации и уровня доверия заверителей глубиной 6

# Возвращает иерархию удостоверений, заверивших данное до уровня $nested_level
sub get_attestates {
  my ($dbh, $person_id, $public_key_id, $nested_level) = @_;
  
  $sql = <<SQL;
  WITH RECURSIVE recursived(sign_person_id, sign_public_key_id, level, nested, path, cycle) AS (
      SELECT sign_person_id, sign_pub_key_id, level, 1, ARRAY[content_id], false 
        FROM attestations 
        WHERE is_current AND person_id = ? AND public_key_id = ?
    UNION ALL
      SELECT a.sign_person_id, a.sign_pub_key_id, a.level, r.nested+1, r.path || a.content_id, a.content_id = ANY(r.path)
        FROM recursived r, attestations a 
        WHERE is_current AND a.person_id = r.sign_person_id AND a.public_key_id = r.sign_public_key_id AND NOT r.cycle AND r.nested <= ?
  )
  SELECT * FROM recursived;
SQL
  
  my @attestations;
  my $c = $dbh->prepare($sql);
  $c->execute($person_id, $public_key_id, $nested_level);
  while (my $att = $c->fetchrow_hashref()) {
    push(@attestations, $att);
  };
  $c->finish;
  
  return(\@attestations);
};

# Возвращает иерархию доверия для заверивших данное удостоверение до уровня $nested_level
sub get_trusts {
  my ($dbh, $person_id, $public_key_id, $nested_level) = @_;
  
  $sql = <<SQL;
  WITH RECURSIVE recursived(sign_person_id, level, nested, path, cycle) AS (
      SELECT t.sign_person_id, t.level, 1, ARRAY[t.content_id], false 
        FROM attestations a, trusts t
        WHERE a.is_current AND t.is_current AND a.person_id = ? AND a.public_key_id = ? AND a.sign_person_id = t.person_id
    UNION ALL
      SELECT t.sign_person_id, t.level, r.nested+1, r.path || t.content_id, t.content_id = ANY(r.path)
        FROM recursived r, trusts t 
        WHERE t.is_current AND t.person_id = r.sign_person_id AND NOT r.cycle AND r.nested <= ?
  )
  SELECT * FROM recursived;
SQL
  
  my @trusts;
  my $c = $dbh->prepare($sql);
  $c->execute($person_id, $public_key_id, $nested_level);
  while (my $trust = $c->fetchrow_hashref()) {
    push(@trusts, $trust);
  };
  $c->finish;
  
  return(\@trusts);
};






1;
