CC?=clang
AFLCC?=afl-clang
CFLAGS=-no-pie -fno-stack-protector -Wno-address-of-packed-member -O3

all: exifutil static-exifutil san-exifutil afl-exifutil

exifutil: exifutil.c
	$(CC) $(CFLAGS) $^ -o $@

static-exifutil: exifutil.c
	$(CC) $(CFLAGS) -static $^ -o $@

san-exifutil: exifutil.c
	$(CC) $(CFLAGS) $^ -o $@ -fsanitize=address

afl-exifutil: exifutil.c
	$(AFLCC) $(CFLAGS) $^ -o $@

clean:
	rm -f *exifutil
