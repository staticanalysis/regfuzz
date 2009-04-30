
SHELL = /bin/sh

CC = gcc
AR = ar
CFLAGS   = -Wall -g -ggdb3 -O2
CPPFLAGS = -I.
CXXFLAGS = $(CFLAGS) 
DLDFLAGS =   
LDSHARED = $(CC) -shared
LDSTATIC = $(AR) rcs
AR = ar
EXEEXT = 

SRCS = regfuzz.c
OBJS = regfuzz.o
TARGET = regfuzz
DLLIB = lib$(TARGET).so
STANDALONE = $(TARGET)
STATIC_LIB = lib$(TARGET).a

RUBYCOMMONDIR = $(sitedir)$(target_prefix)
RUBYLIBDIR    = $(sitelibdir)$(target_prefix)
RUBYARCHDIR   = $(sitearchdir)$(target_prefix)

TARGET_SO     = $(DLLIB)
CLEANLIBS     = lib/lib$(TARGET).*
CLEANOBJS     = *.o *.a *.s[ol] *.pdb *.exp *.bak
CLEANFILES    = $(TARGET)

all:      $(STANDALONE)
static:   $(STATIC_LIB)
shared:   $(DLLIB)

clean:
		@-$(RM) $(CLEANLIBS) $(CLEANOBJS) $(CLEANFILES)

distclean:	clean
		@-$(RM) regfuzz.o

realclean:	distclean

$(RUBYARCHDIR)/$(DLLIB): $(DLLIB)
	$(INSTALL_PROG) $(DLLIB) $(RUBYARCHDIR)
install-rb: pre-install-rb install-rb-default
install-rb-default: pre-install-rb-default
pre-install-rb: Makefile
pre-install-rb-default: Makefile
$(RUBYARCHDIR):
	$(MAKEDIRS) $@

site-install: site-install-so site-install-rb
site-install-so: install-so
site-install-rb: install-rb

.SUFFIXES: .c .m .cc .cxx .cpp .C .o

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

$(DLLIB): $(OBJS)
	@-$(RM) $@
	$(LDSHARED) $(DLDFLAGS) $(LIBPATH) -o $@ $(OBJS) $(LOCAL_LIBS) $(LIBS)
	mkdir -p lib
	mv $@ lib

$(STATIC_LIB): $(OBJS)
	@-$(RM) $@
	$(LDSTATIC) $@ $(OBJS)
	mkdir -p lib
	mv $@ lib

$(STANDALONE): $(SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -DSTANDALONE=1 $< -o $@


$(OBJS): regfuzz.h
