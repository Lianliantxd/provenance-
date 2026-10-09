#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* Narrow application instrumentation: addresses, never a flow/mode label. */
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned char input[17];
    const unsigned char fixed[16] = "KKKKKKKKKKKKKKKK";
    int in = open(argv[1], O_RDONLY);
    if (in < 0) return 3;
    ssize_t n = read(in, input, sizeof input);
    if (close(in) != 0 || n != (ssize_t)sizeof input) return 4;
    if (input[0] != 'F' && input[0] != 'N') return 5;
    const unsigned char *source = input[0] == 'F' ? input + 1 : fixed;
    char record[128];
    int length = snprintf(record, sizeof record, "read_payload_ptr=%p write_source_ptr=%p\n", (void *)(input + 1), (void *)source);
    if (length < 1 || length >= (int)sizeof record) return 8;
    int probe = open("pointer_observation.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (probe < 0 || write(probe, record, (size_t)length) != length || close(probe) != 0) return 9;
    int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) return 6;
    n = write(out, source, 16);
    if (close(out) != 0 || n != 16) return 7;
    return 0;
}
