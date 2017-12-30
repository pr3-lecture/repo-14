#include <memory.h>
#include <stdio.h>
#include <libgen.h>
#include "crypto.h"


int main(int args, char** argv) {
    char *temp = basename(argv[0]);
    char filename[8];
    strncpy(filename,temp, 7);

    KEY k;
    // 1. Parameter: KEY
    k.chars = argv[1];
    printf("%s\n", temp);

    // If Key is Missing Cancel
    if (argv[1] == NULL) {
        printf("KEY missing!");
        return -1;
    }

    // 2. Check for Input
    char input[100];
    if (argv[2] != NULL) {
        FILE *f = fopen(argv[2], "r");

        if (f != NULL) {
            fgets(input, 100, f);
            fclose(f);
        }
    } else {
        printf("Please enter message: ");
        scanf("%s", input);
    }

    char result[strlen(input)];

    if (strcmp(filename, "encrypt") == 0) {
        if (encrypt(k, input, result) == 0) {
            printf("Message: %s\nKey: %s\nEncrypted Message: %s\n", input, argv[1], result);
        }
    } else {
        if (decrypt(k, input, result) == 0) {
            printf("Encrypted Message: %s\nKey: %s\nMessage: %s\n", input, argv[1], result);
        }
    }

    return 0;
}