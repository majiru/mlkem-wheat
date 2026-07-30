</$objtype/mkfile

LIB=mlkem.$objtype.a
CFLAGS=-Fpw

BASEFILES=\
	compress.$O\
	indcpa.$O\
	kem.$O\
	poly.$O\
	poly_k.$O\
	sampling.$O\
	verify.$O\
	fips202-plan9.$O\

O512=\
	${BASEFILES:%=build/mlkem512/%}\

O768=\
	${BASEFILES:%=build/mlkem768/%}\

O1024=\
	${BASEFILES:%=build/mlkem1024/%}\

OFILES=\
	main.$O\
	notrandombytes.$O\

CLEANFILES=$OFILES $O512 $O768 $O1024 $LIB

</sys/src/cmd/mkone

build/:
	mkdir -p build/^(mlkem512 mlkem768 mlkem1024)

$OFILES: build/

%.$O:	%.c
	$CC -o $target $CFLAGS $stem.c

build/mlkem512/%.$O:	%.c
	$CC -o $target '-DMLK_CONFIG_MULTILEVEL_WITH_SHARED' '-DMLK_CONFIG_PARAMETER_SET=512' $CFLAGS $stem.c

build/mlkem768/%.$O:	%.c
	$CC -o $target '-DMLK_CONFIG_MULTILEVEL_NO_SHARED' '-DMLK_CONFIG_PARAMETER_SET=768' $CFLAGS $stem.c

build/mlkem1024/%.$O:	%.c
	$CC -o $target '-DMLK_CONFIG_MULTILEVEL_NO_SHARED' '-DMLK_CONFIG_PARAMETER_SET=1024' $CFLAGS $stem.c


$LIB:V:	$O512 $O768 $O1024 randombytes.$O
	ar vu $LIB $newprereq

&:n:	&.$O
	ar vu $LIB $stem.$O

test:V:	$O.out
	$O.out
