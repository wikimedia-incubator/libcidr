# Quickie
TDIRS = fromstr tostr fromto

all build clean:
	@for i in ${TDIRS}; do \
		echo "-> Makeing ${@} for $${i}"; \
		(cd $${i} && make ${@}); \
	done
