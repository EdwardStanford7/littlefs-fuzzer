CC = afl-clang-fast
CFLAGS ?= -O1 -g -Wall -Wextra -Wpedantic
LDFLAGS ?=

SOURCES = harness.c lfs.c lfs_util.c
OUT ?= afl-out
INSTANCE ?= default
REPORTS ?= reports

.PHONY: all build run triage clean asan seeds
all: build

build: lfs-afl

lfs-afl: $(SOURCES) lfs.h lfs_util.h
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $@

# A useful starting corpus; AFL quickly mutates it into all operation types.
seeds:
	mkdir -p corpus
	printf '\000\001\002\003\005\000\000\000\001\000\000\020\017\000\000\000\021\000\000\000' > corpus/basic

run: build seeds
	afl-fuzz -i corpus -o $(OUT) -- ./lfs-afl

# Useful when confirming a minimized crash outside AFL.
asan: CC = afl-clang-fast
asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address,undefined
asan: lfs-afl-asan

lfs-afl-asan: $(SOURCES) lfs.h lfs_util.h
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $@

triage: asan
	./triage.sh $(OUT)/$(INSTANCE)/crashes $(REPORTS)

clean:
	rm -f lfs-afl lfs-afl-asan
