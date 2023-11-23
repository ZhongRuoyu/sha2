CPPFLAGS ?= -DNDEBUG
CFLAGS ?= -std=c11 -O3

SOEXT = so
ifeq ($(shell uname -s),Darwin)
	SOEXT = dylib
endif

SHARED_LIB = libsha2.$(SOEXT)
STATIC_LIB = libsha2.a
LIB_SRCS = src/padding.c src/rounds.c src/sha2.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB_HDRS = src/sha2.h src/sha2_impl.h

EXE = sha2
EXE_SRCS = src/main.c
EXE_OBJS = $(EXE_SRCS:.c=.o)
EXE_HDRS =
EXE_SYMLINKS = sha256sum sha224sum sha512sum sha384sum

LINK_SHARED ?=
ifneq ($(LINK_SHARED),)
	EXE_LINK_LIB = $(SHARED_LIB)
	override EXE_LDFLAGS += -L. -lsha2
else
	EXE_LINK_LIB = $(STATIC_LIB)
	override EXE_LDFLAGS += $(STATIC_LIB)
endif

.PHONY: all
all: $(SHARED_LIB) $(STATIC_LIB) $(EXE) $(EXE_SYMLINKS)

$(SHARED_LIB): override LDFLAGS += $(LIB_LDFLAGS)
$(SHARED_LIB): $(LIB_OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $^

$(STATIC_LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(LIB_OBJS): override CPPFLAGS += $(LIB_CPPFLAGS)
$(LIB_OBJS): override CFLAGS += $(LIB_CFLAGS)
$(LIB_OBJS): %.o: %.c $(LIB_HDRS)

$(EXE): override LDFLAGS += $(EXE_LDFLAGS)
$(EXE): $(EXE_OBJS) $(EXE_LINK_LIB)
	$(CC) $(LDFLAGS) $(EXE_OBJS) -o $@

$(EXE_OBJS): override CPPFLAGS += $(EXE_CPPFLAGS)
$(EXE_OBJS): override CFLAGS += $(EXE_CFLAGS)
$(EXE_OBJS): %.o: %.c $(EXE_HDRS)

$(EXE_SYMLINKS): %: $(EXE)
	ln -sf $^ $@

.PHONY: clean
clean:
	rm -f $(SHARED_LIB) $(STATIC_LIB) $(LIB_OBJS) $(EXE) $(EXE_OBJS) $(EXE_SYMLINKS)
