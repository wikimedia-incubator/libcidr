# Top-level shared/config bits

# Library naming and versioning
# XXX Keep this in sync with src/Makefile.inc!
# We can't just .include because GNU make is stupid
LIB_VERS = 0
SHLIB_NAME = libcidr.so.${LIB_VERS}
SHLIB_LINK = libcidr.so


STATICLIB_NAME = libcidr.a.${LIB_VERS}
STATICLIB_LINK = libcidr.a

