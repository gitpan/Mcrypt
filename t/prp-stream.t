#!/usr/bin/perl

# 9 tests for each alg/mode

@algs = qw (ARCFOUR);

@modes = qw (STREAM);

$totaltests = 9*scalar(@algs)*scalar(@modes);

BEGIN { $| = 1 }
END {print "not ok 1\n" unless ($loaded > 1);}

print "1..$totaltests\n";

use Mcrypt qw(:ALGORITHMS :MODES :FUNCS);

$loaded = 1;
sub doit {
  my($method, $alg, $mode, $infile, $outfile) = @_;
  my($td) = Mcrypt::mcrypt_load( $alg, "", $mode, "");
  (($loaded+=4) && return 0) unless($td);
  print "ok $loaded\n"; $loaded++;
  $keysize = Mcrypt::mcrypt_get_key_size($td);
  $ivsize = Mcrypt::mcrypt_get_iv_size($td);
  my($key) = "k" x $keysize;
  my($iv) = "i" x $ivsize;
  Mcrypt::mcrypt_init($td, $key, $iv) || (($loaded+=3) && return 0);
  print "ok $loaded\n"; $loaded++;
  open(IN,  "<$infile" ) || (($loaded+=2) && return 0);
  open(OUT, ">$outfile") || (($loaded+=2) && return 0);
  if($method eq "encrypt") {
    while(<IN>) {
#      print "In: ".length($_);
      $out = Mcrypt::mcrypt_encrypt($td, $_);
#      print " Out: ".length($out)."\n";
      print OUT $out;
    }
  } else {
    while(<IN>) {
      print OUT Mcrypt::mcrypt_decrypt($td, $_);
    }
  }
  close(IN) && close(OUT);
  print "ok $loaded\n"; $loaded++;
  Mcrypt::mcrypt_end($td);
  print "ok $loaded\n"; $loaded++;
  return 1;
}

sub testam {
 my ($alg, $mode) = @_;
  doit("encrypt", $alg, $mode, "t/testfile", "t/testfile.blown");
  doit("decrypt", $alg, $mode, "t/testfile.blown", "t/testfile.2");
  unlink("t/testfile.blown");

  open(FILE, "<t/testfile");
$oldis = $/;
undef($/);
  $file1 = <FILE>;
$/ = $oldis;
  close(FILE);
  open(FILE, "<t/testfile.2") || return 0;
$oldis = $/;
undef($/);
  $file2 = <FILE>;
$/ = $oldis;
  close(FILE);
  unlink("t/testfile.2");

  if($file1 ne $file2) {
    return 0;
  } else {
    return 1;
  }
}
foreach $alg (@algs) {
  $valg = eval "{ Mcrypt::$alg }";
  foreach $mode (@modes) {
    $vmode = eval "{ Mcrypt::$mode }";
    $result = testam($valg, $vmode);
    if($result) {
      print "ok $loaded ($valg/$mode)\n"; $loaded++;
    } else {
      print "not ok $loaded\n"; $loaded++;
    }
  }
}
