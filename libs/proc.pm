package proc;

# Библиотека функций для управления fastcgi демонами

# demonize 			- демонизация процесса
# check_for_one_instance 	- блокировка запуска нескольких экземпляров демона

use strict;
use POSIX;

my $logname;

# Переводит скрипт в режим демона с перенаправлением вывода в указанный лог-файл
sub demonize {
  my ($log, $pidfile, $opt) = @_;

  fork_proc() && exit 0;

	# Создаем каталог для log-файла
	my $logdir = $log;
	$logdir =~ s/^(.+)\/[^\/]+$/$1/g;
	if (! -d $logdir) {
		system('mkdir -p "'.$logdir.'"');
		system('chmod 777 "'.$logdir.'"');
	};
	$logname = $log;

	# Создаем каталог для pid-файла
	my $piddir = $pidfile;
	$piddir =~ s/^(.+)\/[^\/]+$/$1/g;
	if (! -d $piddir) {
		system('mkdir -p "'.$piddir.'"');
	};

	my $skipsetuid = 0;
	if (defined($opt) && (ref($opt) eq '')) {
		$skipsetuid = $opt;
		undef($opt);
	};
	$opt = {} if (!defined($opt));

	open(FL, ">".$pidfile);
	print FL $$;
	close(FL);

	if (!defined($opt->{skip_setsid}) || ($opt->{skip_setsid} == 0)) {
		POSIX::setsid() or die "Can't set sid: $!";
	};

	if (!defined($opt->{skip_chdir}) || ($opt->{skip_chdir} == 0)) {
		$opt->{chdir} = '/' if (!defined($opt->{chdir}));
		chdir $opt->{chdir} or die "Can't chdir: $!";
	};

	if ((!defined($skipsetuid) || ($skipsetuid == 0)) && (!defined($opt->{skip_setuid}) || ($opt->{skip_setuid} == 0))) {
		POSIX::setuid(65534) or die "Can't set uid: $!";
	};

  $log = '/dev/null' if (!defined($log) || ($log eq ''));

	if (!defined($opt->{skip_std_redirect}) || ($opt->{skip_std_redirect} == 0)) {
		open(STDIN,  ">>".$log) or die "Can't open STDIN: $!";
		open(STDOUT, ">>".$log) or die "Can't open STDOUT: $!";
		open(STDERR, ">>".$log) or die "Can't open STDERR: $!";
	};

	$SIG{USR1} = \&_sig_rotate_logs;
};

# Служебная процедура форка процесса для демонизации
sub fork_proc {
  my $pid;

  FORK: {
    if (defined($pid = fork)) {
      return $pid;
    }
    elsif ($! =~ /No more process/) {
      sleep 5;
      redo FORK;
    }
    else {
      die "Can't fork: $!";
    };
  };
};

# Процедура для обеспечения запуска приложения в единственном экземпляре
sub check_for_one_instance {
  my $cfg = $_[0];

	if ($< ne '0') {
		print STDERR "ERROR: Application possible running only under root user\n";
		exit();
	};

	open(LOCK, '>'.$cfg->{lock_file}) if (defined($cfg->{lock_file}) && ($cfg->{lock_file} ne ''));
	flock(LOCK, 2) if (defined($cfg->{lock_file}) && ($cfg->{lock_file} ne ''));
  if ( -e $cfg->{pid_file} ) {
    open(FL, '<'.$cfg->{pid_file});
    my $pid = <FL>;
		close(FL);

    my $cmd = "/bin/ps -A|grep -E \"^[^0-9]*".$pid."\"|awk '{print \$1}'";

    my $pidstr = `$cmd`;
    chomp($pidstr);

    if ($pid eq $pidstr) {
      print STDERR "ERROR: Application already running (pid:", $pid, ")\n";
      exit();
    } else {
			open(FL, '>'.$cfg->{pid_file});
			print FL $$;
			close(FL);
		};
	};
	close(LOCK) if (defined($cfg->{lock_file}) && ($cfg->{lock_file} ne ''));
};

# Если в командной строке последним параметром идет команда "restart", "stop" или "check" - выполняем нужное действие с демоном
sub check_command {
	my ($cfg) = @_;

	if (($#ARGV >= 0) && (($ARGV[$#ARGV] eq 'restart') || ($ARGV[$#ARGV] eq 'stop') || ($ARGV[$#ARGV] eq 'check'))) {
    checker_fcgi($cfg, $ARGV[$#ARGV]);
		exit;
	};
};

sub checker_fcgi {
  my ($cfg, $cmd, $inst) = @_;

  $inst = '' if !defined($inst);

  # Если инстанс пустой - проверяем список инстансов из конфига
  my @instances;
  if (($inst eq '') && defined($cfg->{instances}) && ($cfg->{instances} ne '')) {
    my @i = split(/\,/, $cfg->{instances});
    foreach $inst (@i) {
      push(@instances, $inst);
    };
  } else {
    push(@instances, $inst);
  };

  undef($inst);
  my $second = 0;
  foreach $inst (@instances) {
    if (! -e $cfg->{$inst.'pid_file'}) {
      run_process($cfg->{cmd_path}.' '.$inst);
      next;
    };

    open(FL, '<'.$cfg->{$inst.'pid_file'});
    my $pid = <FL>;
    close(FL);

    my $cmd = "/bin/ps -A|grep -E \"^[^0-9]*".$pid."\"|awk '{print \$1}'";

    my $pidstr = `$cmd`;
    chomp($pidstr);

    if (defined($ARGV[1]) && (($ARGV[1] eq 'restart') || ($ARGV[1] eq 'stop') || ($ARGV[1] eq 'force-restart') || ($ARGV[1] eq 'force-stop'))) {
      if (($ARGV[1] eq 'restart') && ($second)) {
        sleep(5);
        $second = 1;
      };
      if ($ARGV[1] !~ /^force/) {
        kill(SIGTERM, $pid);
      } else {
        kill(SIGKILL, $pid);
      };
      while ($pid eq $pidstr) {
        sleep(1);
        $pidstr = `$cmd`;
        chomp($pidstr);
      };
    };

    if ($pid ne $pidstr) {
      if (!defined($ARGV[1]) || (($ARGV[1] ne 'stop') && ($ARGV[1] ne 'force-stop'))) {
        $inst = '' if (!defined($inst));
        run_process($cfg->{cmd_path}.' '.$inst);
      };
    };
  };

  sub run_process {
    system(@_);
  };
}

sub _sig_rotate_logs {
	if (defined($logname)) {
		close(STDIN); open(STDIN,  ">>".$logname);
		close(STDOUT); open(STDOUT, ">>".$logname);
		close(STDERR); open(STDERR, ">>".$logname);
	};
};

1;
