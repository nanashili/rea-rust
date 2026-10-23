/* Inspect a caller-supplied textual stat record, without acquiring a process. */
#include "rea.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: inspect-process-stat 'PID (command) state ...'\n");
        return 2;
    }
    const uint8_t *input = (const uint8_t *)argv[1];
    rea_process_stat_v1 facts = {0};
    uint32_t status = rea_parse_linux_process_stat_v1(input, strlen(argv[1]),
                                                     &facts, sizeof facts);
    if (status != REA_OK) {
        fprintf(stderr, "parse failed: status=%" PRIu32 " kind=%" PRIu32
                        " field=%" PRIu32 "\n",
                status, facts.error_kind, facts.error_field);
        return 1;
    }
    printf("pid=%" PRIu64 " parent=%" PRIu64 " group=%" PRIu64
           " session=%" PRIu64 " lifecycle=%" PRIu32 " start_time=",
           facts.pid, facts.parent_pid, facts.process_group_id,
           facts.session_id, facts.lifecycle);
    if (fwrite(input + facts.start_time_offset, 1, facts.start_time_length, stdout)
        != facts.start_time_length) return 1;
    if (putchar('\n') == EOF || fflush(stdout) == EOF) return 1;
    return 0;
}
