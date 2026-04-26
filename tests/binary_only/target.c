#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile uint8_t byte_sink;
static volatile int32_t int_sink;

/* Intentional sanitizer-specific bugs used by the binary-only fixture. */
static void maybe_trigger_asan(const uint8_t *data, size_t len) {
    if (len < 2) {
        return;
    }

    size_t idx = data[0];
    if (idx < 8 || idx > 15) {
        return;
    }

    uint8_t *buf = malloc(8);
    if (!buf) {
        return;
    }

    memset(buf, 0, 8);
    /* ASAN should report this when idx is outside the 8-byte allocation. */
    buf[idx] = data[1];
    byte_sink ^= buf[0];
    free(buf);
}

static void maybe_trigger_ubsan(const uint8_t *data, size_t len) {
    if (len < sizeof(int32_t) + 1) {
        return;
    }

    int32_t value;
    memcpy(&value, data, sizeof(value));
    if (value <= INT32_MAX - 32) {
        return;
    }

    int32_t bump = 1 + (int32_t)(data[sizeof(value)] & 31);
    /* UBSAN should report signed overflow when value is near INT32_MAX. */
    int_sink = value + bump;
}

__attribute__((noinline))
static int cfi_target_int(int value) {
    return value + 1;
}

typedef int (*cfi_wrong_signature_fn)(const uint8_t *, size_t);

static void maybe_trigger_cfisan(const uint8_t *data, size_t len) {
    if (len < 2 || data[0] <= 200 || data[1] >= 16) {
        return;
    }

    uintptr_t raw_fn = (uintptr_t)&cfi_target_int;
    cfi_wrong_signature_fn fn = (cfi_wrong_signature_fn)raw_fn;
    /* CFISAN should report the mismatched indirect-call signature. */
    int_sink ^= fn(data, len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    const char *target = "HELLO WORLD";
    size_t target_len = strlen(target);

    maybe_trigger_asan(data, len);
    maybe_trigger_ubsan(data, len);
    maybe_trigger_cfisan(data, len);

    if (len >= target_len) {
        if (data[0] == 'H') {
            if (data[1] == 'E') {
                if (data[2] == 'L') {
                    if (data[3] == 'L') {
                        if (data[4] == 'O') {
                            if (memcmp(&data[5], target + 5, target_len - 5) ==
                                0) {
                                printf("HELLO WORLD hit!\n");
                                *((volatile char *)NULL) = 'A';
                                // or crash:
                                // __builtin_trap();
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}
