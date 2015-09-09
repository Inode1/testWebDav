iCC=gcc
CFLAGS=-c -Wall -I/usr/local/ssl/include
LDFLAGS=/usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a -ldl
SOURCES=webdav.c utility.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=webdav

all: $(SOURCES) $(EXECUTABLE)
    
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

PHONY: clean 

clean:
	rm *.o webdav
