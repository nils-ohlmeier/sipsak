#
# Basic and crude Makefile...
#

# Targets to build
PROGS= sipsak
MANPAGES=sipsak.1

# Installation directory. By default, go in local.
# Distributions should probably use /usr/sbin, but they probably know better...
# Don't forget trailing slash to avoid issues

INSTALL_DIR= /usr/local/bin/
INSTALL_MAN= /usr/local/man

# ------------ End of config --------------

CC = gcc
RM = rm -f

RM_CMD = $(RM) *.BAK *.bak *.o ,* *~ *.a *.orig *.rej

WARNING = -Wall
DEFS =

FLAGS = $(WARNING) $(DEFS)

all:: $(PROGS)

%: %.o
	$(CC) -o $@ $^
%.o: %.c
	$(CC) $(FLAGS) -c $<

sipsak: sipsak.o

# So crude but so effective ;-)
# Less crude thanks to many contributions ;-)
install::
	install -m 755 $(PROGS) $(INSTALL_DIR)
	install -m 644 $(MANPAGES) $(INSTALL_MAN)/man1/

clean::
	$(RM_CMD) $(PROGS)
