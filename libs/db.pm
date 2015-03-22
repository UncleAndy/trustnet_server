package db;

# Библиотека функций для работы с БД

# check_db_connect			- проверяет соединение к БД и делаер реконнект при необходимости

use strict;
use DBI;

# Процедура контроля соединения к базе данных
#	Если соединение в порядке, возвращает тот-же DBI, который был в параметре $dbh
#	Если соединение разорвано, формируется новый коннект и возвращается новый объект DBI
sub check_db_connect {
	my ($dbh, $dbhost, $dbport, $dbname, $dbuser, $dbpass, $repeattime) = @_;

	# Проверка пингами
	while (!defined($dbh) || !$dbh->ping()) {
		if (defined($dbh)) {
			print STDERR "check_db_connect: NO db connect... restore\n";
			print STDERR ((defined($DBI::errstr))? $DBI::errstr:''), "\n";
			$dbh->disconnect;
			undef($dbh);
		};

		$dbh = DBI->connect("dbi:Pg:host=".$dbhost.";port=".$dbport.";dbname=".$dbname, $dbuser, $dbpass, {AutoCommit => 0, RaiseError => 0, PrintError => 0});

		# Провер после попытки соединения
		if (!defined($dbh) || !$dbh->ping()) {
			print STDERR "check_db_connect: can not restore db connect:\n";
			print STDERR ((defined($DBI::errstr))? $DBI::errstr:''), "\n";
			if (defined($repeattime) && ($repeattime > 0)) {
				sleep($repeattime);
			} else {
				die "Can not connect to database: ".$dbhost.":".$dbport." ".$dbname.": \n".((defined($DBI::errstr))? $DBI::errstr:'');
			};
		};

		# Ожидать подклчюения - несколько повторов
		if ((!defined($dbh) || !$dbh->ping()) && (!defined($repeattime) || ($repeattime eq ''))) {
			undef($dbh);
			last;
		};
	};
	return($dbh);
}

1;
