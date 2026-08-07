</$objtype/mkfile

LIB=mlkem.$objtype.a
CFLAGS=-FTVw

PORT=\
	mlkem.$O\
	verify.$O\

TARG=\
	main\
	wych\

</sys/src/cmd/mkmany

CLEANFILES=$OFILES $LIB $PORT

$LIB:V:	$PORT
	ar vu $LIB $newprereq

&:n:	&.$O
	ar vu $LIB $stem.$O

test:V:	$O.main $O.wych
	$O.main
	$O.wych
