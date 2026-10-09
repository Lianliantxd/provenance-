#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <unistd.h>

/* Benign fixed-length source experiment; mode resides only in local input. */
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
    int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) return 6;
    n = write(out, source, 16);
    if (close(out) != 0 || n != 16) return 7;
    return 0;
}
