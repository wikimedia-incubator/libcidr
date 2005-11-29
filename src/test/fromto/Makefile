# Temporary Makefile just to handle early testing
C_FILES = fromto_test.c
C_FLAGS = -I../../../include
CLEAN_FILES = ${O_FILES} fromto_test *core .depend

L_FLAGS = -g -pipe -L../.. -lcidr

.include "../../Makefile.inc"

# This need to be after the include
all build: fromto_test

LCIDR = ../../libcidr.so

fromto_test: ${O_FILES} ${LCIDR}
	${CC} ${L_FLAGS} -o ${@} ${O_FILES}

${LCIDR}:
	(cd ../.. && make)
