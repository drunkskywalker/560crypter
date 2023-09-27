CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto
TARGET = duke-crypter
SRC = duke_crypter.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
