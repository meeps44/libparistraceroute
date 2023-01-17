@SET_MAKE@

AUTOMAKE_OPTIONS = foreign

###############################################################################
#
# THE PROGRAMS TO BUILD
#

# the program to build (the names of the final binaries)
bin_PROGRAMS = paris-traceroute

# list of sources for the paris-traceroute binary
# $(srcdir)/../libparistraceroute/ext_test.c \
paris_traceroute_SOURCES = \
	paris-traceroute.c

#-L$(srcdir)/../libparistraceroute
paris_traceroute_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(srcdir)/../libparistraceroute

#../libparistraceroute/libparistraceroute-@LIBRARY_VERSION@.la
#paris_traceroute_LDADD = \
	#../libparistraceroute/libparistraceroute-@LIBRARY_VERSION@.la
#Erlend:
paris_traceroute_LDADD = \
	../libparistraceroute/libparistraceroute-@LIBRARY_VERSION@.la \
	-lcrypto \
	-lssl \
	-lsqlite3

# Erlend:
#paris_traceroute_LDFLAGS = \ 
	#-lcrypto -lssl

install-bin: install

