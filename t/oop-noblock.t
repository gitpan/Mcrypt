#!/usr/bin/perl

# 9 tests for each alg/mode

@algs = qw (BLOWFISH
		DES
		3DES
		3WAY
		GOST
		SAFER_SK64
		SAFER_SK128
		CAST_128
		XTEA
		RC2
		TWOFISH
		CAST_256
		SAFERPLUS
		LOKI97
		SERPENT
		RIJNDAEL_128
		RIJNDAEL_192
		RIJNDAEL_256);

@modes = qw (CFB
             OFB);

$totaltests = 9*scalar(@algs)*scalar(@modes);

BEGIN { $| = 1 }
END {print "not ok 1\n" unless ($loaded > 1);}

print "1..$totaltests\n";

use Mcrypt qw(:ALGORITHMS :MODES :FUNCS);

$loaded = 1;
sub doit {
  my($method, $alg, $mode, $infile, $outfile) = @_;
  my($td) = Mcrypt->new( algorithm => $alg,
			 mode => $mode,
		         verbose => 0 );
  (($loaded+=4) && return 0) unless($td);
  print "ok $loaded\n"; $loaded++;
  my($key) = "k" x $td->{KEY_SIZE};
  my($iv) = "i" x $td->{IV_SIZE};
  $td->init($key, $iv) || (($loaded+=3) && return 0);
  print "ok $loaded\n"; $loaded++;
  open(IN,  "<$infile" ) || (($loaded+=2) && return 0);
  open(OUT, ">$outfile") || (($loaded+=2) && return 0);
  if($method eq "encrypt") {
    while(<IN>) {
#      print "In: ".length($_);
      $out = $td->encrypt($_);
#      print " Out: ".length($out)."\n";
      print OUT $out;
    }
  } else {
    while(<IN>) {
#      print "In: ".length($_);
      $out = $td->decrypt($_);
#      print " Out: ".length($out)."\n";
      print OUT $out;
    }
  }
  close(IN) && close(OUT);
  print "ok $loaded\n"; $loaded++;
  # we could cann $td->end(), but the destructor will take care of that
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
#  unlink("t/testfile.2");

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
