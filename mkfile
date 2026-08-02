</$objtype/mkfile

LIB=mlkem.$objtype.a
CFLAGS=-FTVw

PORT=\
	sampling.$O\
	verify.$O\
	compress.$O\
	fips202-plan9.$O\
	poly.$O\
	kem.$O\
	poly_k.$O\
	indcpa.$O\

OFILES=\
	main.$O\
	notrandombytes.$O\

CLEANFILES=$OFILES $LIB $PORT

</sys/src/cmd/mkone


$LIB:V:	$PORT randombytes.$O
	ar vu $LIB $newprereq

&:n:	&.$O
	ar vu $LIB $stem.$O

test:V:	$O.out
	$O.out
