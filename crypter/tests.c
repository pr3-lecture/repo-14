#include <stdio.h>
#include <memory.h>
#include "crypto.h"

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
                                if (message) return message; } while (0)

int tests_run = 0;
static char* testEncryption() {
    char* text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    KEY k;
    k.chars = "PRUEFUNGSPHASE";
    char* expectedResult = "QPVACSIOZZCM^K_BDWUA[QDHQ[";
    char result[strlen(text)];

    encrypt(k, text, result);

    mu_assert("Encryption succeeded", strcmp(expectedResult, result) == 0);
    return 0;
}

static char* testDecryption() {
    char* text = "QPVACSIOZZCM^K_BDWUA[QDHQ[";
    KEY k;
    k.chars = "PRUEFUNGSPHASE";
    char* expectedResult = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char result[strlen(text)];

    decrypt(k, text , result);

    mu_assert("Decryption succeeded", strcmp(expectedResult, result) == 0);
    return 0;
}

static char* testCypherError() {
    char* text = "QPVAggIOÄZCM^K_BDWUA[QDHQ[";
    KEY k;
    k.chars = "PRUEFUNGSPHASE";
    char result[strlen(text)];

    int response = decrypt(k, text , result);

    mu_assert("Cypher Text Error Success", response == 4);
    return 0;
}

static char* testMessageError() {
    char* text = "ABCDEFGHIJKLMNÖPQRSTUVWXYZ";
    KEY k;
    k.chars = "PRUEFUNGSPHASE";
    char result[strlen(text)];

    int response = encrypt(k, text , result);

    mu_assert("Cypher Text Error Success", response == 3);
    return 0;
}

static char* testKeyError() {
    char* text = "QPVACSIOZZCM^K_BDWUA[QDHQ[";
    KEY k;
    k.chars = "PRÜFUNGSPHASE";
    char result[strlen(text)];

    int response = decrypt(k, text , result);

    mu_assert("Cypher Text Error Success", response == 2);
    return 0;
}

static char* testKeyLengthError() {
    char* text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    KEY k;
    k.chars = "A";
    char result[strlen(text)];

    int response = decrypt(k, text , result);

    mu_assert("Cypher Text Error Success", response == 1);
    return 0;
}



static char* allTests() {
    mu_run_test(testEncryption);
    mu_run_test(testDecryption);
    mu_run_test(testMessageError);
    mu_run_test(testCypherError);
    mu_run_test(testKeyError);
    mu_run_test(testKeyLengthError);
    return 0;
}

int main() {
    char* result = allTests();

    if (result != 0) {
        printf("%s\n", 'Not Passed');
        printf("%s\n", result);
    } else {
        printf("TESTS PASSED\n");
    }

    printf("Runned Tests: %d\n", tests_run);

    return result != 0;
}