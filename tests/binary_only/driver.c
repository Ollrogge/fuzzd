/* coverage_driver.c - Replay driver for LLVMFuzzerTestOneInput harnesses.
 * Reads files from command-line arguments and calls LLVMFuzzerTestOneInput.
 * Crash handler flushes coverage data on signals so crashing inputs still
 * contribute to the report.
 *
 * Compile and link example:
 *   clang -fprofile-instr-generate -fcoverage-mapping \
 *     -c coverage_driver.c -o coverage_driver.o
 *   clang -fprofile-instr-generate \
 *     coverage_driver.o -L./build -ltarget -o cov
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));
int LLVMFuzzerTestOneInput(const unsigned char*, size_t);

extern int __llvm_profile_write_file(void);

static void crash_handler(int sig) {
    __llvm_profile_write_file();
    fprintf(stderr, "ERROR: Coverage gathering aborted due to signal!\n");
    raise(sig);
}

__attribute__((constructor))
static void install_crash_handlers(void) {
    const int sigs[] = { SIGABRT, SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTERM };
    struct sigaction sa = {
        .sa_handler = crash_handler,
        .sa_flags   = SA_RESETHAND,
    };
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < (int)(sizeof(sigs) / sizeof(sigs[0])); i++)
        sigaction(sigs[i], &sa, NULL);
}

int main(int argc, char **argv) {
    // needed for auto-detection in compiled binaries:
    if (argc == 2 && strcmp(argv[1], "--printsignature") == 0) {
        printf("###SIGNATURE_LLVMFUZZERTESTONEINPUT_COVERAGE###\n");
    }

    if (LLVMFuzzerInitialize) {
        fprintf(stderr, "Running LLVMFuzzerInitialize ...\n");
        LLVMFuzzerInitialize(&argc, &argv);
    }

    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long len = ftell(f);
            if (len > 0) {
                fseek(f, 0, SEEK_SET);
                unsigned char *buf = (unsigned char *)malloc((size_t)len);
                if (buf) {
                    size_t n_read = fread(buf, 1, (size_t)len, f);
                    if (n_read > 0) {
                        fprintf(stderr, "Running: %s (%d/%d) %zu bytes\n",
                                argv[i], i, argc - 1, n_read);
                        LLVMFuzzerTestOneInput((const unsigned char*)buf, n_read);
                    } else {
                        fprintf(stderr, "Error: Read failed for %s\n", argv[i]);
                    }
                    free(buf);
                }
            }
            fclose(f);
        }
    }

    fprintf(stderr, "Done.\n");
    return 0;
}
