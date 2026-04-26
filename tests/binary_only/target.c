#include <stdint.h>
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    const char *target = "HELLO WORLD";
    size_t target_len = strlen(target);

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
