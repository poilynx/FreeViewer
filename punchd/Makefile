SRC = ..
include $(SRC)/config.mak

SRCS = $(CMN)/log.c \
       $(CMN)/avltree.c \
       $(CMN)/sslutil.c \
       ctx.c \
       usermgr.c \
       main.c \
       issue.c \
       server.c \
       serverev.c

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

LDFLAGS = -g -levent -L/usr/lib64/mysql -lmysqlclient -levent_openssl -lssl -lcrypto
TARGETS = punchd

all: $(TARGETS)
$(TARGETS): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.d: %.c
	set -e; $(CC) $(CFLAGS) -MM $< | sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@;

ifneq ($(MAKECMDGOALS), clean)
-include $(DEPS)
endif

clean:
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	$(RM) $(TARGETS)

run: $(TARGETS)
	$(TARGETS)

.PHONY: all clean run
