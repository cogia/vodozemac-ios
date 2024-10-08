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

    return 0;
}