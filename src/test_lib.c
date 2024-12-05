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
        struct Account* acc2;
        VodozemacError err3 = accountFromPickle(str, "12345678912345678912345678912345", &acc2);
        if (err3.code == 0) {
           VodozemacError err4 = accountMarkedAsPublished(acc2);
           if (err4.code == 0) {
               printf("Received accountMarkedAsPublished\n");
           } else {
                printf("Received error string: %s\n", err4.message);
           }
        }
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

    struct Account* acc2 = newAccount();

    VodozemacError ee2 = accountGenerateOneTimeKeys(acc2, 10);
    printf("Received error string: %s\n", ee2.message);

    //for(int i = 0; i < 10; i++) {
    //    const char* key;
    //    VodozemacError ee3 = accountOneTimeKey(acc2, i, &key);
    //    printf("Received key: %s\n", key);
    //}

    for(int i = 0; i < 140; i++) {
        const unsigned int *amount2;
        VodozemacError ee4 = accountMaxNumberOfOneTimeKeys(acc2, &amount2);
        printf("Received amount: %d\n", *amount2);
    }

    return 0;
}