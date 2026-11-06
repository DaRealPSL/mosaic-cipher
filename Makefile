CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS =

SRCS = src/cli.c src/util.c src/mosaic.c src/xor_key.c src/main.c
OBJS = $(SRCS:.c=.o)
BIN = mosaicCipher

.DEFAULT_GOAL := all
.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

#compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(OS),Windows_NT)
clean:
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue 'src/*.o','$(BIN)','$(BIN).exe'; exit 0"
else
clean:
	rm -f $(OBJS) $(BIN)
endif

test: all
	@echo -n "HELLO WORLD" | ./$(BIN) encode | ./$(BIN) decode | diff -q - <(echo -n "HELLO WORLD") || echo "Test failed"
