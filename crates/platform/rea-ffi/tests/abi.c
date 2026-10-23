/* Exercise the published header against the actual shared Rust library. */
#include "rea.h"
#include <assert.h>
#include <string.h>

int main(void) {
    const char record[] =
        "42 (worker ) old (name)\n) S 17 18 19 0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 000123";
    rea_process_stat_v1 out = {0};
    assert(rea_parse_linux_process_stat_v1((const uint8_t *)record, sizeof record - 1,
                                          &out, sizeof out) == REA_OK);
    assert(out.pid == 42 && out.parent_pid == 17 && out.process_group_id == 18);
    assert(out.session_id == 19 && out.lifecycle == REA_LIFECYCLE_EXITING);
    assert(out.start_time_length == 6);
    assert(out.start_time_offset == sizeof record - 7);
    assert(memcmp(record + out.start_time_offset, "000123", 6) == 0);
    assert(out.error_kind == REA_PARSE_ERROR_NONE && out.error_field == 0 && out.reserved == 0);

    /* Bad ABI arguments must not clobber the caller's last successful result. */
    assert(rea_parse_linux_process_stat_v1(NULL, 1, &out, sizeof out) == REA_INVALID_ARGUMENT);
    assert(out.pid == 42);
    assert(rea_parse_linux_process_stat_v1(NULL, 0, &out, sizeof out - 1) == REA_INVALID_ARGUMENT);
    assert(out.pid == 42);
    assert(rea_parse_linux_process_stat_v1(NULL, 0, NULL, sizeof out) == REA_INVALID_ARGUMENT);
    assert(rea_parse_linux_process_stat_v1((const uint8_t *)record, SIZE_MAX,
                                          &out, sizeof out) == REA_INVALID_ARGUMENT);
    assert(out.pid == 42);

    const uint8_t invalid_utf8[] = {0xff};
    assert(rea_parse_linux_process_stat_v1(invalid_utf8, 1, &out, sizeof out) == REA_INVALID_UTF8);
    assert(out.pid == 0 && out.start_time_length == 0 && out.error_kind == 0);
    assert(rea_parse_linux_process_stat_v1(NULL, 0, &out, sizeof out) == REA_INVALID_RECORD);
    assert(out.error_kind == REA_PARSE_ERROR_COMMAND && out.pid == 0);

    const char missing[] = "42 (worker) S 1 2 3";
    assert(rea_parse_linux_process_stat_v1((const uint8_t *)missing, sizeof missing - 1,
                                          &out, sizeof out) == REA_INVALID_RECORD);
    assert(out.error_kind == REA_PARSE_ERROR_MISSING_FIELD && out.error_field == 22);
    assert(out.pid == 0 && out.lifecycle == REA_LIFECYCLE_UNKNOWN);

    /* Check C numeric tags, independently of Rust enum layout/discriminants. */
    const char states[] = {'S', 'S', 'S', 'Z', 'X', 'x'};
    const char flags[] = {'0', '4', '?', '?', '?', '?'};
    const uint32_t expected[] = {
        REA_LIFECYCLE_NON_ZOMBIE, REA_LIFECYCLE_EXITING, REA_LIFECYCLE_UNKNOWN,
        REA_LIFECYCLE_ZOMBIE, REA_LIFECYCLE_DEAD, REA_LIFECYCLE_DEAD
    };
    for (size_t i = 0; i < sizeof states; ++i) {
        char changed[sizeof record];
        memcpy(changed, record, sizeof record);
        strrchr(changed, ')')[2] = states[i];
        strstr(changed, " 4 ")[1] = flags[i];
        assert(rea_parse_linux_process_stat_v1((const uint8_t *)changed, sizeof changed - 1,
                                              &out, sizeof out) == REA_OK);
        assert(out.pid == 42 && out.lifecycle == expected[i]);
        assert(out.error_kind == 0 && out.error_field == 0);
    }

    const char status[] = "Name:\tworker\nUid:\t1000\t1001\t1002\t1003\nGid:\t20\t20\t20\t20\n";
    rea_process_status_v1 status_out = {0};
    assert(rea_parse_linux_process_status_v1((const uint8_t *)status, sizeof status - 1,
                                              &status_out, sizeof status_out) == REA_OK);
    assert(status_out.effective_uid == 1001);
    assert(status_out.error_kind == REA_PROCESS_STATUS_ERROR_NONE && status_out.reserved == 0);

    assert(rea_parse_linux_process_status_v1(NULL, 1, &status_out, sizeof status_out) == REA_INVALID_ARGUMENT);
    assert(status_out.effective_uid == 1001);
    assert(rea_parse_linux_process_status_v1((const uint8_t *)status, sizeof status - 1,
                                              &status_out, sizeof status_out - 1) == REA_INVALID_ARGUMENT);
    assert(status_out.effective_uid == 1001);

    const char missing_uid[] = "Name:\tworker\nGid:\t20\t20\t20\t20\n";
    assert(rea_parse_linux_process_status_v1((const uint8_t *)missing_uid, sizeof missing_uid - 1,
                                              &status_out, sizeof status_out) == REA_INVALID_RECORD);
    assert(status_out.effective_uid == 0);
    assert(status_out.error_kind == REA_PROCESS_STATUS_ERROR_MISSING_UID);

    const char duplicate_uid[] = "Uid:\t1\t2\t3\t4\nUid:\t1\t2\t3\t4\n";
    assert(rea_parse_linux_process_status_v1((const uint8_t *)duplicate_uid, sizeof duplicate_uid - 1,
                                              &status_out, sizeof status_out) == REA_INVALID_RECORD);
    assert(status_out.error_kind == REA_PROCESS_STATUS_ERROR_DUPLICATE_UID);

    const char malformed_uid[] = "Uid:\t1\t18446744073709551616\t3\t4\n";
    assert(rea_parse_linux_process_status_v1((const uint8_t *)malformed_uid, sizeof malformed_uid - 1,
                                              &status_out, sizeof status_out) == REA_INVALID_RECORD);
    assert(status_out.error_kind == REA_PROCESS_STATUS_ERROR_INVALID_UID);
    assert(status_out.effective_uid == 0 && status_out.reserved == 0);

    const uint8_t invalid_status_utf8[] = {0xff};
    assert(rea_parse_linux_process_status_v1(invalid_status_utf8, sizeof invalid_status_utf8,
                                              &status_out, sizeof status_out) == REA_INVALID_UTF8);
    assert(status_out.effective_uid == 0 && status_out.error_kind == REA_PROCESS_STATUS_ERROR_NONE);
    return 0;
}
