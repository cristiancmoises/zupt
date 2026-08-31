/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <ctype.h>
#include <stdio.h>

static int hex_value(int character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *input = fopen(argv[1], "rb");
    FILE *output = input ? fopen(argv[2], "wb") : NULL;
    if (!input || !output) {
        if (input) fclose(input);
        if (output) fclose(output);
        return 1;
    }
    int high_nibble = -1;
    int character;
    int failed = 0;
    while ((character = fgetc(input)) != EOF) {
        if (isspace((unsigned char)character)) continue;
        int value = hex_value(character);
        if (value < 0) {
            failed = 1;
            break;
        }
        if (high_nibble < 0) {
            high_nibble = value;
        } else {
            if (fputc((high_nibble << 4) | value, output) == EOF) {
                failed = 1;
                break;
            }
            high_nibble = -1;
        }
    }
    if (ferror(input) || high_nibble >= 0 || fflush(output) != 0)
        failed = 1;
    if (fclose(input) != 0) failed = 1;
    if (fclose(output) != 0) failed = 1;
    return failed ? 1 : 0;
}
