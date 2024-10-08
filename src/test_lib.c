#include "../vodozemac_ios.h"
#include <stdio.h>

int main() {
    SessionConfig res = sessionConfigV2();
    int result = getVersionSessionConfig(&res);
    printf("%d\n", result);
    struct Account* acc = newAccount();
    printf("%d\n", acc);

    const char* str;
    VodozemacError err = accountPickle(acc, "12345678912345678912345678912345", &str);
    printf("Received string: %d\n", err.code);
    if (err.code == 0) {
        printf("Received string: %s\n", str);
        free_string(str);
    } else {
        printf("Received error string: %s\n", err.message);
    }

    const CIdentityKeys* keys;
    VodozemacError err2 = accountIdentityKeys(acc, &keys);
    printf("Received string: %d\n", err2.code);
    if (err2.code == 0) {
        printf("Received ed25519: %s\n", keys->ed25519);
        printf("Received curve25519: %s\n", keys->curve25519);
    } else {
        printf("Received error string: %s\n", err2.message);
    }

    return 0;
}