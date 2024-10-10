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

typedef struct OlmMessage {
  const char *ciphertext;
  uint32_t message_type;
} OlmMessage;

typedef struct SessionConfig {
  uint8_t _version;
} SessionConfig;

typedef struct CIdentityKeys {
  const char *ed25519;
  const char *curve25519;
} CIdentityKeys;

struct VodozemacError accountCreateInboundSession(struct Account *ptr,
                                                  const char *identity_key,
                                                  struct OlmMessage *ptr_session_config,
                                                  struct Session **session,
                                                  const char **data);

struct VodozemacError accountCreateOutboundSession(struct Account *ptr,
                                                   const char *identity_key,
                                                   const char *one_time_key,
                                                   struct SessionConfig *ptr_session_config,
                                                   struct Session **session);

struct VodozemacError accountCurve25519Key(struct Account *ptr, const char **data);

struct VodozemacError accountEd25519Key(struct Account *ptr, const char **data);

struct VodozemacError accountFallbackKey(struct Account *ptr, const char **data);

struct VodozemacError accountFallbackKeys(struct Account *ptr);

struct VodozemacError accountFromLibOlmPickle(const char *pickle,
                                              const char *password,
                                              struct Account **ptr);

struct VodozemacError accountFromPickle(const char *pickle,
                                        const char *password,
                                        struct Account **ptr);

struct VodozemacError accountGenerateOneTimeKeys(struct Account *ptr, uint32_t number);

struct VodozemacError accountIdentityKeys(struct Account *ptr, const struct CIdentityKeys **data);

struct VodozemacError accountMarkedAsPublished(struct Account *ptr);

struct VodozemacError accountMaxNumberOfOneTimeKeys(struct Account *ptr, const uint32_t **max);

struct VodozemacError accountOneTimePerKeys(struct Account *ptr, const char **data);

struct VodozemacError accountPickle(struct Account *ptr, const char *pickle, const char **data);

struct VodozemacError accountSign(struct Account *ptr, const char *message, const char **data);

void free_string(char *s);

uint8_t getVersionSessionConfig(struct SessionConfig *config);

struct Account *newAccount(void);

struct OlmMessage newOlmMessage(uint32_t message_type, const char *ciphertext);

struct SessionConfig sessionConfigV1(void);

struct SessionConfig sessionConfigV2(void);

struct VodozemacError sessionDecrypt(struct Session *ptr,
                                     struct OlmMessage *message,
                                     const char **data);

struct VodozemacError sessionEncrypt(struct Session *ptr,
                                     char *plaintext,
                                     const struct OlmMessage **data);

struct VodozemacError sessionFromLibOlmPickle(const char *pickle,
                                              const char *password,
                                              struct Session **ptr);

struct VodozemacError sessionFromPickle(const char *pickle,
                                        const char *password,
                                        struct Session **ptr);

struct VodozemacError sessionPickle(struct Session *ptr, const char *pickle, const char **data);

struct VodozemacError sessionSessionId(struct Session *ptr, const char **data);

struct VodozemacError sessionSessionMatches(struct Session *ptr,
                                            struct OlmMessage *ptr_session_config,
                                            const size_t **data);

#endif  /* common.h */
