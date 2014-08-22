#
## Copyright (c) 2008 by Seraphim Mellos.  See LICENSE.
#

include ../../Make.defs

TITLE = pam_wheel
PAM_SO_SUFFIX = 
LIBSHARED = $(TITLE).so$(PAM_SO_SUFFIX)
SHLIBMODE = 755
MAN8 = $(TITLE).8
MANMODE = 644
SECUREDIR = /lib/security
MANDIR = /usr/share/man/man8
#DESTDIR =



PROJ = $(LIBSHARED)
OBJS = pam_wheel.o

all:
	case "`uname -s`" in \
	Linux)  $(MAKE) CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			LDLIBS="$(LDLIBS)" $(PROJ);;\
	*) 	 echo "OS not supported.";;\
	esac

$(LIBSHARED): $(OBJS) 
	$(LD) $(LDFLAGS) $(OBJS) $(LDLIBS) -o $(LIBSHARED)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

install: 
	$(INST) -m $(SHLIBMODE) -o root -g root $(LIBSHARED) $(SECUREDIR) 
	$(INST) -m $(MANMODE) -o root -g root $(MAN8) $(MANDIR)



clean:
	$(RM) $(PROJ) *.o



