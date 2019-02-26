LDFLAGS = -levent -lpthread -levent_pthreads
all: feelgood
feelgood: main.o
	$(CC) -o $@ $^ $(LDFLAGS) 
clean:
	$(RM) *.o feelgood
