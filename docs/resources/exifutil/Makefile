CC?=clang
AFLCC?=afl-clang
CFLAGS=-nopie -fno-stack-protector -Wno-address-of-packed-member -O3 -static

all: exifutil

exifutil: exifutil.c
	$(CC) $(CFLAGS) $^ -o $@

san-exifutil: exifutil.c
	$(CC) $(CFLAGS) $^ -o $@ -fsanitize=address

afl-exifutil: exifutil.c
	$(AFLCC) $(CFLAGS) $^ -o $@

clean:
	rm -f *exifutil
