#include "../vodozemac_ios.h"
#include <stdio.h>

int main() {
    SessionConfig res = sessionConfigV2();
    int result = getVersionSessionConfig(&res);
    printf("%d\n", result);
    return 0;
}