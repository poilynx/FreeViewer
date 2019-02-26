SRC = ../..
include $(SRC)/config.mak

LDFLAGS = -L$(SRC)/libpunch -lpunch -levent -lssl -lcrypto -levent_openssl 
OBJS = main.o
TARGETS = ./a.out
CFLAGS += -I$(SRC)/libpunch -I$(SRC)/include

all: $(TARGETS)
$(TARGETS): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
clean:
	$(RM) $(OBJS) $(TARGETS)

run: clean
	make
	$(TARGETS)


.PHONY: all clean run
