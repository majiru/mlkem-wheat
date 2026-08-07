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

WYCH=\
	data/mlkem_1024_encaps_test.json\
	data/mlkem_1024_keygen_seed_test.json\
	data/mlkem_1024_semi_expanded_decaps_test.json\
	data/mlkem_1024_test.json\
	data/mlkem_512_encaps_test.json\
	data/mlkem_512_keygen_seed_test.json\
	data/mlkem_512_semi_expanded_decaps_test.json\
	data/mlkem_512_test.json\
	data/mlkem_768_encaps_test.json\
	data/mlkem_768_keygen_seed_test.json\
	data/mlkem_768_semi_expanded_decaps_test.json\
	data/mlkem_768_test.json\

data:
	mkdir -p data

data/%: data
	hget https://raw.githubusercontent.com/C2SP/wycheproof/fc24cd5b787d8e496bff31b0468af693a652b0f2/testvectors_v1/$stem >$target

test:V: $WYCH

test:V:	$O.main $O.wych
	$O.main
	$O.wych
