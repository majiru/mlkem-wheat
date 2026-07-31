</$objtype/mkfile

LIB=mlkem.$objtype.a
CFLAGS=-FTVw

PORT=\
	sampling.$O\
	verify.$O\
	compress.$O\
	fips202-plan9.$O\
	poly.$O\

BASEFILES=\
	indcpa.$O\
	kem.$O\
	poly_k.$O\

O512=\
	${BASEFILES:%=build/mlkem512/%}\

O768=\
	${BASEFILES:%=build/mlkem768/%}\

O1024=\
	${BASEFILES:%=build/mlkem1024/%}\

OFILES=\
	main.$O\
	notrandombytes.$O\

CLEANFILES=$OFILES $O512 $O768 $O1024 $LIB $PORT

</sys/src/cmd/mkone

build/:
	mkdir -p build/^(mlkem512 mlkem768 mlkem1024)

$O512 $O768 $O1024: build/

main.$O: main.c
	$CC -o $target -p $CFLAGS main.c

build/mlkem512/%.$O:	%.c
	$CC -o $target -p '-DMLK_CONFIG_PARAMETER_SET=512' $CFLAGS $stem.c

build/mlkem768/%.$O:	%.c
	$CC -o $target -p '-DMLK_CONFIG_PARAMETER_SET=768' $CFLAGS $stem.c

build/mlkem1024/%.$O:	%.c
	$CC -o $target -p '-DMLK_CONFIG_PARAMETER_SET=1024' $CFLAGS $stem.c


$LIB:V:	$PORT $O512 $O768 $O1024 randombytes.$O
	ar vu $LIB $newprereq

&:n:	&.$O
	ar vu $LIB $stem.$O

test:V:	$O.out
	$O.out
