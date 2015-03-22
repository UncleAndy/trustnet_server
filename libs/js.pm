package js;

# Библиотека функций для работы с JSON

# to_hash - конвертирует текст в формате JSON в переменную типа HASH
# from_hash - конвертирует переменную типа HASH в текст в формате JSON

use strict;
use JSON;

sub to_hash {
	my ($json) = @_;
	my $h;
	my $js = JSON->new();
	# позволяет обработать невалидный json
	$js->relaxed(1);
	# преобразование в utf-8
	$js->utf8;
	eval {
		# eval нужен для того что-бы не падало приложение при ошибках обработки json
		$h = $js->decode($json);
	};
	undef($js);
	return($h);
};

sub from_hash {
	my ($h, $pretty) = @_;

	my $s = '';
	my $js = JSON->new();
	# позволяет обработать невалидный json
	$js->relaxed(1);
	# преобразование в utf-8
	# $js->utf8;
	$js->pretty(1) if ($pretty);
	eval {
		# eval нужен для того что-бы не падало приложение при ошибках обработки json
		$s = $js->encode($h);
	};
	undef($js);

	return($s);
};

1;
