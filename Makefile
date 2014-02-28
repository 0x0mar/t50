#
# if DEBUG is defined on make call (ex: make DEBUG=1), then compile with
# __HAVE_DEBUG__ defined, asserts and debug information.
#
# Delete __HAVE_TURBO__ definition, below, if you don't need it.
#
# The final executable will be created at release/ sub-directory.
#

SRC_DIR=./src
OBJ_DIR=./build
RELEASE_DIR=./release
MAN_DIR=/usr/share/man/man8
INCLUDE_DIR=$(SRC_DIR)/include

TARGET=$(RELEASE_DIR)/t50

OBJS=$(OBJ_DIR)/modules/ip.o \
$(OBJ_DIR)/modules/igmpv3.o \
$(OBJ_DIR)/modules/dccp.o \
$(OBJ_DIR)/modules/ripv2.o \
$(OBJ_DIR)/modules/udp.o \
$(OBJ_DIR)/modules/tcp.o \
$(OBJ_DIR)/modules/ospf.o \
$(OBJ_DIR)/modules/ripv1.o \
$(OBJ_DIR)/modules/egp.o \
$(OBJ_DIR)/modules/rsvp.o \
$(OBJ_DIR)/modules/ipsec.o \
$(OBJ_DIR)/modules/eigrp.o \
$(OBJ_DIR)/modules/gre.o \
$(OBJ_DIR)/modules/igmpv1.o \
$(OBJ_DIR)/modules/icmp.o \
$(OBJ_DIR)/common.o \
$(OBJ_DIR)/cksum.o \
$(OBJ_DIR)/cidr.o \
$(OBJ_DIR)/t50.o \
$(OBJ_DIR)/resolv.o \
$(OBJ_DIR)/sock.o \
$(OBJ_DIR)/usage.o \
$(OBJ_DIR)/config.o \
$(OBJ_DIR)/check.o


# OBS: Using Linker Time Optiomizer!
#      -O3 and -fuse-linker-plugin needed on link time to use lto.
CC=gcc
DFLAGS=-D__HAVE_TURBO__ -DVERSION=\"5.5\" 

COPTS=-Wall -Wextra -I$(INCLUDE_DIR)
ifdef DEBUG
	COPTS+=-O0
	DFLAGS+=-D__HAVE_DEBUG__ -g
	LDOPTS=
else
	COPTS+=-O3 -mtune=native -flto -ffast-math -fomit-frame-pointer

	# Get architecture
	ARCH=$(shell arch)
	ifneq ($(ARCH),x86_64)
		COPTS+=-msse -mfpmath=sse		
	endif

  DFLAGS+=-DNDEBUG
	LDOPTS=-s -O3 -fuse-linker-plugin -flto
endif
COPTS+=$(DFLAGS)

.PHONY: clean install

# link

$(TARGET): $(OBJS)
	$(CC) $(LDOPTS) $^ -o $@

# Compile main
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(COPTS) -c -o $@ $<

# Compile modules
$(OBJ_DIR)/modules/%.o: $(SRC_DIR)/modules/%.c
	$(CC) $(COPTS) -c -o $@ $<

clean:
	@rm -rf $(RELEASE_DIR)/* $(OBJ_DIR)/*.o $(OBJ_DIR)/modules/*.o
	@echo Binary executable, temporary files and packed manual file deleted.

install:
	gzip -9 $(RELEASE_DIR)/t50.8.gz ./doc/t50.1
	install $(RELEASE_DIR)/t50 /usr/sbin/
	install $(RELEASE_DIR)/t50.8.gz $(MAN_DIR)/
