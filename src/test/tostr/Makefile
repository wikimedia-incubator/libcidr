# Temporary Makefile just to handle early testing
C_FILES = tostr_test.c
C_FLAGS = -I../../../include
CLEAN_FILES = ${O_FILES} tostr_test *core .depend

L_FLAGS = -g -pipe -L../.. -lcidr

.include "../../Makefile.inc"

# This need to be after the include
all build: tostr_test

LCIDR = ../../libcidr.so

tostr_test: ${O_FILES} ${LCIDR}
	${CC} ${L_FLAGS} -o ${@} ${O_FILES}

${LCIDR}:
	(cd ../.. && make)
