CC = cc
CFLAGS = -std=c99 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS = 

SRCS = src/cli.c src/util.c src/mosaic.c src/main.c
OBJS = $(SRCS:.c=.o)
BIN  = mosaicCipher

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN)

test: all
	@echo -n "HELLO WORLD" | ./$(BIN) encode | ./$(BIN) decode | diff -q - <(echo -n "HELLO WORLD") || echo "Test failed"
