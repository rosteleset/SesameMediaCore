#ifndef SESAME_MEDIA_CORE_H
#define SESAME_MEDIA_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SesameMediaBuffer {
    uint8_t *data;
    size_t len;
} SesameMediaBuffer;

typedef struct CbcsDecryptionContext CbcsDecryptionContext;

uint32_t sesame_media_core_abi_version(void);

void sesame_media_buffer_free(SesameMediaBuffer buffer);
void sesame_cmaf_cbcs_context_free(CbcsDecryptionContext *context);

int32_t sesame_cmaf_cbcs_clear_initialization(
    const uint8_t *encrypted_data,
    size_t encrypted_len,
    SesameMediaBuffer *clear_out,
    CbcsDecryptionContext **context_out,
    SesameMediaBuffer *error_out
);

int32_t sesame_cmaf_normalize_clear_initialization(
    const uint8_t *clear_data,
    size_t clear_len,
    SesameMediaBuffer *normalized_out,
    SesameMediaBuffer *error_out
);

size_t sesame_cmaf_cbcs_context_key_count(const CbcsDecryptionContext *context);

int32_t sesame_cmaf_cbcs_context_copy_key_id(
    const CbcsDecryptionContext *context,
    size_t index,
    uint8_t *key_id_out,
    size_t key_id_len
);

/* key_material contains key_count records of kid[16] followed by cek[16]. */
int32_t sesame_cmaf_cbcs_clear_fragment(
    const uint8_t *encrypted_data,
    size_t encrypted_len,
    const CbcsDecryptionContext *context,
    const uint8_t *key_material,
    size_t key_count,
    uint8_t has_timeline,
    uint64_t base_time_microseconds,
    uint8_t has_fragment_sequence,
    uint32_t fragment_sequence,
    SesameMediaBuffer *clear_out,
    SesameMediaBuffer *error_out
);

#ifdef __cplusplus
}
#endif

#endif
