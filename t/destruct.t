#!/usr/bin/perl
# this test will actually core for version < 2.4.8.2 :-))

use strict;
use Mcrypt qw(:ALGORITHMS :MODES :FUNCS);

my $loaded = 1;
my $totaltests = 1;
BEGIN { $| = 1 }
END {print "not ok 1\n" unless ($loaded > 0);}

print "1..$totaltests\n";
my($input) = "0123456701234567";

my $td = Mcrypt->new( algorithm => Mcrypt::BLOWFISH,
                            mode => Mcrypt::CFB,
                         verbose => 0 );
my($key) = "k" x $td->{KEY_SIZE};
my($iv) = "i" x $td->{IV_SIZE};
$td->init($key, $iv);
$td->decrypt($input);
$td->end();
print "ok $loaded\n"; $loaded++;
