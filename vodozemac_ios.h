/* Hello Guys! We Are Cogia Intelligence!👁️ vodozemac-ios is an IOS binding  of Matrix vodozemac. */

#ifndef common.h
#define common.h

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct Option_Sas Option_Sas;

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

typedef struct CDecryptedMessage {
  const char *plaintext;
  size_t message_index;
} CDecryptedMessage;

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
                                              const struct Account **ptr);

struct VodozemacError accountFromPickle(const char *pickle,
                                        const char *password,
                                        const struct Account **ptr);

struct VodozemacError accountGenerateOneTimeKeys(struct Account *ptr, uint32_t number);

struct VodozemacError accountIdentityKeys(struct Account *ptr, const struct CIdentityKeys **data);

struct VodozemacError accountMarkedAsPublished(struct Account *ptr);

struct VodozemacError accountMaxNumberOfOneTimeKeys(struct Account *ptr, const uint32_t **max);

struct VodozemacError accountOneTimePerKeys(struct Account *ptr, const char **data);

struct VodozemacError accountPickle(struct Account *ptr, const char *pickle, const char **data);

struct VodozemacError accountSign(struct Account *ptr, const char *message, const char **data);

struct VodozemacError establishedSasBytes(struct EstablishedSas *ptr,
                                          const char *info,
                                          const struct SasBytes **data);

struct VodozemacError establishedSasCalculateMac(struct EstablishedSas *ptr,
                                                 const char *input,
                                                 const char *info,
                                                 const char **data);

struct VodozemacError establishedSasCalculateMacInvalidBase64(struct EstablishedSas *ptr,
                                                              const char *input,
                                                              const char *info,
                                                              const char **data);

struct VodozemacError establishedSasVerifyMac(struct EstablishedSas *ptr,
                                              const char *input,
                                              const char *info,
                                              const char *tag,
                                              const int32_t **data);

void free_string(char *s);

uint8_t getVersionSessionConfig(struct SessionConfig *config);

struct VodozemacError groupSessionEncrypt(struct GroupSession *ptr,
                                          const char *plaintext,
                                          const char **data);

struct VodozemacError groupSessionFromPickle(const char *pickle,
                                             const char *password,
                                             const struct GroupSession **ptr);

struct VodozemacError groupSessionMessageIndex(struct GroupSession *ptr, const size_t **data);

struct VodozemacError groupSessionPickle(struct GroupSession *ptr,
                                         const char *password,
                                         const char **data);

struct VodozemacError groupSessionSessionId(struct GroupSession *ptr, const char **data);

struct VodozemacError groupSessionSessionKey(struct GroupSession *ptr, const char **data);

struct VodozemacError inboundGroupSessionDecrypt(struct InboundGroupSession *ptr,
                                                 const char *ciphertext,
                                                 const struct CDecryptedMessage **data);

struct VodozemacError inboundGroupSessionExportAt(struct InboundGroupSession *ptr,
                                                  const size_t *index,
                                                  const char **data);

struct VodozemacError inboundGroupSessionFirstKnownIndex(struct InboundGroupSession *ptr,
                                                         const size_t **data);

struct VodozemacError inboundGroupSessionFromLibOlmPickle(const char *pickle,
                                                          const char *password,
                                                          const struct InboundGroupSession **ptr);

struct VodozemacError inboundGroupSessionFromPickle(const char *pickle,
                                                    const char *password,
                                                    const struct InboundGroupSession **ptr);

struct VodozemacError inboundGroupSessionNew(const char *session_key,
                                             struct SessionConfig *ptr_session_config,
                                             const struct InboundGroupSession **ptr);

struct VodozemacError inboundGroupSessionPickle(struct InboundGroupSession *ptr,
                                                const char *pickle,
                                                const char **data);

struct VodozemacError inboundGroupSessionSessionId(struct InboundGroupSession *ptr,
                                                   const char **data);

struct Account *newAccount(void);

struct GroupSession *newGroupSession(struct SessionConfig *ptr_session_config);

struct OlmMessage newOlmMessage(uint32_t message_type, const char *ciphertext);

struct Sas *newSas(void);

struct VodozemacError newSasDiffieHellman(struct Sas *ptr,
                                          const char *key,
                                          const struct EstablishedSas **data);

struct VodozemacError newSasPublicKey(struct Sas *ptr, const char **data);

struct VodozemacError sasBytesDecimals(struct SasBytes *ptr, const uint16_t **data, size_t *len);

struct VodozemacError sasBytesEmojiIndices(struct SasBytes *ptr, const uint8_t **data, size_t *len);

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
