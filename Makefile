TARGET=		libnss_tacplus.so.2
TEST_TARGET=	bin/dlharness
LIBS=		-lnsl -lpthread -ltac
TEST_LIBS=	-ldl

CC=		gcc
CFLAGS=		-D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
		-fstack-clash-protection -std=gnu99 -Werror -Wall -Wextra \
		-ggdb -fPIC -I/usr/local/include
LDFLAGS=	-shared -Wl,-soname,libnss_tacplus.so.2 -Wl,-rpath=/usr/local/lib \
		-Wl,-z,relro -Wl,-z,now
LIBDIR=		/usr/lib64
SYSCONFDIR=	/etc

OBJECTS=	$(patsubst %.c, %.o, $(wildcard src/*.c))
HEADERS=	$(wildcard src/*.h)

TEST_OBJECTS=	$(patsubst %.c, %.o, $(wildcard test/*.c))
TEST_HEADERS=	$(wildcard test/*.h)

default: $(TARGET)
all: default
test: $(TEST_TARGET)

.PHONY: default all test clean install

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

.PRECIOUS: $(TARGET) $(TEST_TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LIBS) $(LDFLAGS) -o $@

$(TEST_TARGET): $(TEST_OBJECTS)
	-mkdir -p bin
	$(CC) $(TEST_OBJECTS) $(TEST_LIBS) $(TEST_LDFLAGS) -o $@

install: $(TARGET)
	install -D -m 755 $(TARGET) $(DESTDIR)$(LIBDIR)/$(TARGET)
	install -D -m 644 etc/tacplus.conf $(DESTDIR)$(SYSCONFDIR)/tacplus.conf

clean:
	-rm -f src/*.o test/*.o
	-rm -f $(TARGET) $(TEST_TARGET)
	-rm -rf bin

