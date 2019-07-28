SRC = $(wildcard src/*.c)
OBJ = bin/freeflow
DESTDIR ?=
PREFIX ?= /opt/freeflow

CC = gcc
LDFLAGS = -lrt -lssl -lcrypto
CFLAGS = -Wall -Ilib

freeflow:
	$(CC) $(LDFLAGS) $(CFLAGS) $(SRC) -o $(OBJ)

install: freeflow
	install -m 0755 -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 -d $(DESTDIR)$(PREFIX)/etc
	install -m 0755 -d $(DESTDIR)$(PREFIX)/var/log/
	install -m 0755 bin/freeflow $(DESTDIR)$(PREFIX)/bin 
	install -m 0644 etc/freeflow.cfg $(DESTDIR)$(PREFIX)/etc
	install -m 0755 systemd/freeflow.service $(DESTDIR)/usr/lib/systemd/system
