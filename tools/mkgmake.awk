# Convert a bmake Makefile to a gmake Makefile

# Special variables with different names
{ gsub("\\${>}", "${^}", $0); }

# Change cross-references (mostly .include's)
{ gsub("Makefile", "GNUmakefile", $0); }

# Meta-directives
/^.include/ { gsub("\"", "", $2); printf("include %s\n", $2); next; }
/^.ifdef/ { gsub("\"", "", $2); printf("ifdef %s\n", $2); next; }
/^.else/ { print("else\n"); next; }
/^.endif/ { print("endif\n"); next; }

# Else, don't molest it
{ print($0); }
