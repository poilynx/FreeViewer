SRC = ..
include $(SRC)/config.mak

#LDFLAGS = -levent -lssl -lcrypto -levent_openssl
OBJS =client.o $(CMN)/sslutil.o tunnel.o ctx.o clientev.o
#TARGETS = $(BIN)/travclient
TARGETS = libpunch.a
CFLAGS += -I../include

all: $(TARGETS)
$(TARGETS): $(OBJS)
	#$(CC) -o $@ $^ $(LDFLAGS)
	$(AR) rsc $@ $^
clean:
	$(RM) $(OBJS) $(TARGETS)

run: $(TARGETS)
	$(TARGETS)


.PHONY: all clean run

