# Shared stuff among various make invocations

# Library naming and versioning
# XXX Keep this in sync with top-level Makefile.inc!
# We can't just .include because GNU make is stupid
LIB_VERS = 0
SHLIB_NAME = libcidr.so.${LIB_VERS}
SHLIB_LINK = libcidr.so

C_WARNS = -Wall -Wstrict-prototypes -Wredundant-decls \
		-Wmissing-prototypes -Wpointer-arith -Winline \
		-Wcast-align -Wcast-qual -Wchar-subscripts \
		-Winline -Wnested-externs -Wmissing-declarations \
		-Werror
_CFLAGS := -g -pipe ${C_WARNS} -I../include -Iinclude ${C_FLAGS}
.ifdef OPTIMIZE
_CFLAGS += -Os
.endif
CFLAGS = ${_CFLAGS}

O_FILES = ${C_FILES:%.c=%.o}
SO_FILES = ${C_FILES:%.c=%.So}

CC = gcc
LD = ld
MV = mv
LN = ln
RM = rm
LORDER = lorder
TSORT = tsort

def: all

${SHLIB_NAME}: ${SO_FILES}
	@echo Linking ${SHLIB_NAME}...
	${CC} -shared -Wl,-x -o ${@} -Wl,-soname,${SHLIB_NAME} \
			`${LORDER} ${SO_FILES} | ${TSORT}`
	${LN} -sf ${SHLIB_NAME} ${SHLIB_LINK}

clean:
	${RM} -f ${CLEAN_FILES}


# bmake needs this to recognize the transform rule
.SUFFIXES: ${.SUFFIXES} -o .So

.c.o:
	${CC} -c ${CFLAGS} -o ${@} ${<}

.c.So:
	${CC} -fpic -DPIC -c ${CFLAGS} -o ${@} ${<}
	@${LD} -o ${@}.tmp -r ${@}
	@${MV} -f ${@}.tmp ${@}
