TARGET := target
SRC := target.c
DRIVER_SRC := driver.c

AFL_CC ?= afl-clang-fast
COVERAGE_CC ?= clang-20

CFLAGS ?= -O2 -g
FUZZER_FLAGS := -fsanitize=fuzzer
COVERAGE_FLAGS := -O0 -g -fprofile-instr-generate -fcoverage-mapping

.PHONY: all clean campaign coverage

all: campaign coverage

campaign: \
	$(TARGET)_normal \
	$(TARGET)_cmplog \
	$(TARGET)_asan_ubsan \
	$(TARGET)_laf \
	$(TARGET)_cfisan

coverage: $(TARGET)_coverage

$(TARGET)_normal: $(SRC)
	AFL_QUIET=1 $(AFL_CC) $(CFLAGS) $(FUZZER_FLAGS) -o $@ $<

$(TARGET)_cmplog: $(SRC)
	AFL_QUIET=1 AFL_LLVM_CMPLOG=1 $(AFL_CC) $(CFLAGS) $(FUZZER_FLAGS) -o $@ $<

$(TARGET)_asan_ubsan: $(SRC)
	AFL_QUIET=1 AFL_USE_ASAN=1 AFL_USE_UBSAN=1 $(AFL_CC) $(CFLAGS) $(FUZZER_FLAGS) -o $@ $<

$(TARGET)_laf: $(SRC)
	AFL_QUIET=1 AFL_LLVM_LAF_ALL=1 $(AFL_CC) $(CFLAGS) $(FUZZER_FLAGS) -o $@ $<

$(TARGET)_cfisan: $(SRC)
	AFL_QUIET=1 AFL_USE_CFISAN=1 $(AFL_CC) $(CFLAGS) $(FUZZER_FLAGS) -o $@ $<

$(TARGET)_coverage: $(TARGET)_coverage_driver.o $(TARGET)_coverage_harness.o
	$(COVERAGE_CC) $(COVERAGE_FLAGS) -o $@ $^

$(TARGET)_coverage_driver.o: $(DRIVER_SRC)
	$(COVERAGE_CC) $(COVERAGE_FLAGS) -c -o $@ $<

$(TARGET)_coverage_harness.o: $(SRC)
	$(COVERAGE_CC) $(COVERAGE_FLAGS) -c -o $@ $<

clean:
	rm -f \
		$(TARGET)_normal \
		$(TARGET)_cmplog \
		$(TARGET)_asan_ubsan \
		$(TARGET)_laf \
		$(TARGET)_cfisan \
		$(TARGET)_coverage \
		$(TARGET)_coverage_driver.o \
		$(TARGET)_coverage_harness.o \
		*.profraw \
		*.profdata
