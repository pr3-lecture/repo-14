#include <stdio.h>
#include <memory.h>
#include "crypto.h"

#define ENCRYPT 0
#define DECRYPT 1

/**
 * Returns position of the variable in the alphabet
 * @param x letter
 * @param alphabet Alphabet
 * @return the position or -1 if not found in the alphabet
 */
int positionAlphabet(char x, const char* alphabet) {
    int i;
    for (i = 0; i < strlen(alphabet); i++) {
        if (alphabet[i] == x) {
            return i;
        }
    }
    return -1;
}

/**
 * Cheks, if the string only contains valid chars
 * @param mode 0: encrypt, 1: decrypt
 * @param message to checked message/key
 * @return 1 if valid 0 else
 */
int charValidation(int mode, const char* message) {
    char* alphabet;
    int i;
    int j;

    if (mode == 0) {
        alphabet = MESSAGE_CHARACTERS;
    } else {
        alphabet = CYPHER_CHARACTERS;
    }

    for (i = 0; i < strlen(message); i++) {
        char zeichen = message[i];
        int ok = 0;

        for (j = 0; j < strlen(alphabet); j++) {
            if (zeichen == alphabet[j]) {
                ok = 1;
                break;
            }
        }

        if (ok == 0) {
            return 0;
        }
    }

    return 1;
}

/**
 * Checks, if Key and Message or Cypher are okay
 * @param k Key
 * @param input Message/Cypher message
 * @param mode 0: encrypt, 1: decrypt
 * @return 0 wenn alles ok, ansonsten Fehlercode
 */
int validateKey(KEY k, char* input, int mode) {
    /* Key length check */
    if (strlen(k.chars) < 2) {
        printf("Key too short!\n");
        return E_KEY_TOO_SHORT;
    }

    /* Encrypt */
    if (mode == ENCRYPT) {
        /* Check for char validation in text and key*/
        if (charValidation(ENCRYPT, input) == 0) {
            printf("Illegal chars in message!\n");
            return E_MESSAGE_ILLEGAL_CHAR;
        }

        if (charValidation(ENCRYPT, k.chars) == 0) {
            printf("Illegal chars in key!\n");
            return E_KEY_ILLEGAL_CHAR;
        }
    } else {
        /* Decrypt */
        /* Check for char validation in cypher text and key*/
        if (charValidation(DECRYPT, input) == 0) {
            printf("Illegal chars in cypher text!\n");
            return E_CYPHER_ILLEGAL_CHAR;
        }

        if (charValidation(DECRYPT, k.chars) == 0) {
            printf("Illegal chars in key!\n");
            return E_KEY_ILLEGAL_CHAR;
        }
    }

    return 0;
}

/**
 * XOR Function
 * @param key Key for encryption / decryption
 * @param input Message/Cyphertext
 * @param output result
 * @param mode 0: encrypt, 1: decrypt
 * @param len Length of the Message
 */
void crypt(KEY key, const char* input, char* output, int mode, int len) {
    int i;
    for (i = 0; i < len; i++) {
        /* Key position correction due to different length between key and message */
        int correctPosition = (int) (i % strlen(key.chars));
        int positionKey = positionAlphabet(key.chars[correctPosition], KEY_CHARACTERS) + 1;
        int positionMessage = 0;

        if (mode == ENCRYPT) {
            positionMessage = positionAlphabet(input[i], MESSAGE_CHARACTERS) + 1;
        } else {
            positionMessage = positionAlphabet(input[i], CYPHER_CHARACTERS);
        }

        if (mode == ENCRYPT) {
            output[i] = CYPHER_CHARACTERS[positionMessage ^ positionKey];
        } else {
            output[i] = MESSAGE_CHARACTERS[(positionMessage ^ positionKey) - 1];
        }
    }

    output[strlen(input)] = '\0';
}


/**
 * Encrypt the given text
 *
 * @param key Key to be used for the encryption
 * @param input Clear text
 * @param output Encrypted text
 * @return 0 on success, otherwise error code
 */
int encrypt(KEY key, const char* input, char* output) {

    int validation = validateKey(key, (char *) input, ENCRYPT);
    if(validation == 0) {
        crypt(key, input, output, ENCRYPT, (int) strlen(input));
        return 0;
    } else {
        return validation;
    }
}

/**
 * Decrypt the given text
 *
 * @param key Key to be used for the decryption
 * @param cypherText Cypher text
 * @param output Decrypted text
 * @return 0 on success, otherwise error code
 */
int decrypt(KEY key, const char* cypherText, char* output) {

    int validation = validateKey(key, (char *) cypherText, DECRYPT);

    if (validation == 0) {
        crypt(key, cypherText, output, DECRYPT, (int) strlen(cypherText));
        return 0;
    } else {
        return validation;
    }
}