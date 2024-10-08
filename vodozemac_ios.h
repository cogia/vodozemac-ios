/* Hello Guys! We Are Cogia Intelligence!👁️ vodozemac-ios is an IOS binding  of Matrix vodozemac. */

#ifndef common.h
#define common.h

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct VodozemacError {
  int32_t code;
  char *message;
} VodozemacError;

typedef struct CIdentityKeys {
  const char *ed25519;
  const char *curve25519;
} CIdentityKeys;

typedef struct SessionConfig {
  uint8_t _version;
} SessionConfig;

typedef struct OlmMessage {
  const char *ciphertext;
  uint32_t message_type;
} OlmMessage;

struct VodozemacError accountCurve25519Key(struct Account *ptr, const char **data);

struct VodozemacError accountEd25519Key(struct Account *ptr, const char **data);

struct VodozemacError accountIdentityKeys(struct Account *ptr, const struct CIdentityKeys **data);

struct VodozemacError accountMaxNumberOfOneTimeKeys(struct Account *ptr, const uint32_t **max);

struct VodozemacError accountPickle(struct Account *ptr, const char *pickle, const char **data);

struct VodozemacError accountSign(struct Account *ptr, const char *message, const char **data);

void free_string(char *s);

uint8_t getVersionSessionConfig(struct SessionConfig *config);

struct Account *newAccount(void);

struct OlmMessage newOlmMessage(uint32_t message_type, const char *ciphertext);

struct SessionConfig sessionConfigV1(void);

struct SessionConfig sessionConfigV2(void);

#endif  /* common.h */
