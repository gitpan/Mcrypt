require 5.004 ;
use ExtUtils::MakeMaker 5.16 ;
use Config ;

$MCRYPT_LIBDIR = '' ;
$MCRYPT_INCLUDE = '' ;

WriteMakefile(
	NAME		=> 'Mcrypt',
	VERSION_FROM	=> 'Mcrypt.pm',
	LIBS		=> [ "$MCRYPT_LIBDIR -lltdl -lmcrypt" ],
	INC		=> " $MCRYPT_INCLUDE" ,
	);
