package setup;

use strict;
use MIME::Base64 qw(encode_base64);
use Crypt::OpenSSL::RSA;
use GPLVote::SignDoc::Client;

sub process {
  my ($query, $dbh, $cfg) = @_;
  my $result = {status => 400, error => 'Bad request path' };
  
  my $uri = $ENV{'REQUEST_URI'};
  if ($uri =~ /^(.+)\?/) {
    $uri = $1;
  };
  
  # URL с подписью для проверки ключа сервера
  switch ($uri) {
    case '/setup/transport_public_key' {
			my $code = $query->params('code');
			
			my ($sign, $public_key_id) = sign_data_transport_key($code);
			
			$result->{public_key} = $cfg->{server_transport_key}->{public};
			$result->{public_key_id} = $public_key_id;
			$result->{code} = $code;
			$result->{code_sign} = $sign;
			
			$result->{status} = 200;
			$result->{error} = '';
		}
	}
  
  return($result);
}

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

1;
