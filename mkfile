</$objtype/mkfile

LIB=mlkem.$objtype.a
CFLAGS=-FTVw

PORT=\
	mlkem.$O\
	verify.$O\

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
