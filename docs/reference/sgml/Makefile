# Makefile for libcidr docs
#
# Derived from libpostal-docs Makefile
# $Libpostal: Makefile,v 1.9 2003/07/16 15:32:11 fullermd Exp $
#
# TARGETS:
# Only the following targets are useful for manual invocation
# - main: Build the docs and install finished outputs in the docs/
#         directory
# - minimal: Build ONLY HTML and TXT verions
# - validate: Validate the libpostal.sgml file against the DTD
# - clean: Clean out the build directory
# - allclean: Clean out the build and output directories

# Files and paths
RTPATH ?= ${PWD}
INSTALLMODE ?= 644

FNAME = libcidr
INFILE = ${RTPATH}/${FNAME}.sgml
INFILES = ${RTPATH}/inc/geninfo.sgml ${RTPATH}/inc/datastructs.sgml \
		${RTPATH}/inc/functions.sgml

CODELIBDIR = ${RTPATH}/codelibrary
PRINTSS = ${CODELIBDIR}/dsssl/print.dsl
HTMLSS = ${CODELIBDIR}/dsssl/html-onepage.dsl

OUTDIR = ${RTPATH}/..
BUILDDIR = ${RTPATH}/.build

# Args
TIDYARGS = -i -raw -quiet -wrap 75
JADECAT= -c /usr/local/sgml/OpenJade/catalog
CODELIBCAT = -c ${RTPATH}/codelibrary/catalog
JADESTD = ${JADECAT} ${CODELIBCAT}

# All our files
ALLFILES = ${FNAME}.ps ${FNAME}.pdf ${FNAME}.dvi ${FNAME}-big.html \
		${FNAME}.txt ${FNAME}.rtf
MINFILES = ${FNAME}-big.html ${FNAME}.txt

# The main user-invokable 
minimal: build-minimal install-minimal
main: build-docs install-docs
all: main

clean:
	rm -rf ${BUILDDIR}

allclean: clean
	rm -f ${OUTDIR}/${FNAME}* ${OUTDIR}/codelibrary-html.css

validate:
	nsgmls ${CODELIBCAT} -s ${INFILE}

build-docs: ${BUILDDIR}
	cd ${BUILDDIR} && \
		${MAKE} -f ${RTPATH}/Makefile RTPATH=${RTPATH} build-all

install-docs: ${BUILDDIR}
	cd ${BUILDDIR} && \
		${MAKE} -f ${RTPATH}/Makefile RTPATH=${RTPATH} install-all

build-minimal: ${BUILDDIR}
	cd ${BUILDDIR} && \
		${MAKE} -f ${RTPATH}/Makefile RTPATH=${RTPATH} do-build-minimal

install-minimal: ${BUILDDIR}
	cd ${BUILDDIR} && \
		${MAKE} -f ${RTPATH}/Makefile RTPATH=${RTPATH} do-install-minimal

# Don't forget the .css for the HTML file too
install-all:
	mkdir -p ${OUTDIR}
	install -c -m ${INSTALLMODE} ${ALLFILES} ${OUTDIR}
	install -c -m ${INSTALLMODE} ${CODELIBDIR}/css/codelibrary-html.css \
			${OUTDIR}
	@echo %%%%% Install done %%%%%

do-install-minimal:
	mkdir -p ${OUTDIR}
	install -c -m ${INSTALLMODE} ${MINFILES} ${OUTDIR}
	install -c -m ${INSTALLMODE} ${CODELIBDIR}/css/codelibrary-html.css \
			${OUTDIR}
	@echo %%%%% Install done %%%%%
	
# Everything
build-all all-formats: tex ps pdf dvi html txt rtf
do-build-minimal: html txt

# Aliases
ps: ${FNAME}.ps
pdf: ${FNAME}.pdf
dvi: ${FNAME}.dvi
tex: ${FNAME}.tex
txt: ${FNAME}.txt
ascii: ${FNAME}.txt
html: ${FNAME}-big.html
rtf: ${FNAME}.rtf

${FNAME}.ps: dvi
	dvips -o ${FNAME}.ps ${FNAME}.dvi
	@echo %%%%% Postscript built %%%%%

${FNAME}.pdf: tex
	pdftex "&pdfjadetex" ${FNAME}.tex
	@echo %%%%% PDF built %%%%%

${FNAME}.dvi: tex
	jadetex ${FNAME}.tex
	@echo %%%%% DVI built %%%%%

${FNAME}.tex: ${INFILE} ${INFILES}
	openjade ${JADESTD} -d ${PRINTSS} -t tex -o ${@} ${INFILE}
	@echo %%%%% TeX built %%%%%

${FNAME}.rtf: ${INFILE} ${INFILES}
	openjade ${JADESTD} -d ${PRINTSS} -t rtf -o ${@} ${INFILE}
	@echo %%%%% RTF built %%%%%

${FNAME}.txt: html
	lynx -dump -nolist ${FNAME}-big.html > ${FNAME}.txt
	@echo %%%%% ASCII built %%%%%

${FNAME}-big.html: ${INFILE} ${INFILES}
	openjade ${JADESTD} -d ${HTMLSS} -t sgml ${INFILE} > ${FNAME}-big-notidy.html
.ifndef NOTIDY
	tidy ${TIDYARGS} < ${FNAME}-big-notidy.html > ${FNAME}-big.html
.else
	cp ${FNAME}-big-notidy.html ${FNAME}-big.html
.endif
	@echo %%%%% HTML built %%%%%

${BUILDDIR}:
	mkdir -p ${BUILDDIR}
