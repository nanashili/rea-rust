#ifndef REA_H
#define REA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REA_OK UINT32_C(0)
#define REA_INVALID_ARGUMENT UINT32_C(1)
#define REA_INVALID_UTF8 UINT32_C(2)
#define REA_INVALID_RECORD UINT32_C(3)
#define REA_INTERNAL_ERROR UINT32_C(4)

#define REA_LIFECYCLE_UNKNOWN UINT32_C(0)
#define REA_LIFECYCLE_NON_ZOMBIE UINT32_C(1)
#define REA_LIFECYCLE_EXITING UINT32_C(2)
#define REA_LIFECYCLE_ZOMBIE UINT32_C(3)
#define REA_LIFECYCLE_DEAD UINT32_C(4)

#define REA_PARSE_ERROR_NONE UINT32_C(0)
#define REA_PARSE_ERROR_COMMAND UINT32_C(1)
#define REA_PARSE_ERROR_PID UINT32_C(2)
#define REA_PARSE_ERROR_MISSING_FIELD UINT32_C(3)
#define REA_PARSE_ERROR_INVALID_FIELD UINT32_C(4)

#define REA_PROCESS_STATUS_ERROR_NONE UINT32_C(0)
#define REA_PROCESS_STATUS_ERROR_MISSING_UID UINT32_C(1)
#define REA_PROCESS_STATUS_ERROR_DUPLICATE_UID UINT32_C(2)
#define REA_PROCESS_STATUS_ERROR_INVALID_UID UINT32_C(3)

/* Native-endian process-local ABI, not a serialized disk/network format.
 * Offsets are bytes into the original input, preserving decimal spelling.
 * Neither parsing nor a lifecycle tag establishes authority to signal a PID. */
typedef struct rea_process_stat_v1 {
    uint64_t pid;
    uint64_t parent_pid;
    uint64_t process_group_id;
    uint64_t session_id;
    size_t start_time_offset;
    size_t start_time_length;
    uint32_t lifecycle;
    uint32_t error_kind;
    uint32_t error_field;
    uint32_t reserved;
} rea_process_stat_v1;

/* Effective UID from one Linux /proc/<pid>/status record. The value is only a
 * parsed fact; callers must bracket it with process-generation checks before
 * attributing it to a PID. This operation grants no process control authority. */
typedef struct rea_process_status_v1 {
    uint64_t effective_uid;
    uint32_t error_kind;
    uint32_t reserved;
} rea_process_status_v1;

/* input: immutable initialized UTF-8 bytes in one allocation; no NUL terminator
 * required. NULL is allowed only with length zero. Length <= PTRDIFF_MAX.
 * out: aligned writable storage, non-overlapping with input, exclusively owned
 * during this call. out_size must equal sizeof(rea_process_stat_v1).
 * No allocation, retained pointers, callbacks or allocator-specific free call.
 * INVALID_ARGUMENT leaves output untouched; other statuses initialize every
 * field. Error outputs contain zero facts; INVALID_RECORD sets error details.
 * Calls are reentrant with independent output storage. Rust unwinding is caught;
 * invalid caller memory and process aborts are not recoverable ABI errors. */
uint32_t rea_parse_linux_process_stat_v1(const uint8_t *input, size_t length,
                                       rea_process_stat_v1 *out, size_t out_size);

/* Same pointer/size/error contract as rea_parse_linux_process_stat_v1. */
uint32_t rea_parse_linux_process_status_v1(const uint8_t *input, size_t length,
                                           rea_process_status_v1 *out, size_t out_size);

#ifdef __cplusplus
}
#endif
#endif
