/* Compile-time owner controls. No process is spawned and no credential changes occur. */
#ifndef REMOZIO_PRODUCTION_CHILD_OWNER_FIXTURE
#error "This owner fixture requires explicit compilation."
#endif
#include "RemozioCommandMonitor.h"
#include "result.h"
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sysexits.h>
#include <signal.h>
#include <unistd.h>
struct remozio_command_monitor { remozio_command_monitor_observation_t state; };
static struct remozio_command_monitor fixture_owner;
static int rejection_error, scenario, fixture_input, fixture_output = -1, polls, releases, disposals;
static bool cancelled, negative;
static unsigned ticks;
static int fixture_clock(clockid_t id, struct timespec *value) {
    (void)id;
    if (polls && scenario == 14) return -1;
    value->tv_sec = polls && scenario == 15 ? 0 : ++ticks;
    value->tv_nsec = 0; return 0;
}
static int fixture_pause(useconds_t delay) { (void)delay; return 0; }
static int fixture_spawn(const char *monitor, const char *child, const void *frame, size_t count,
    int input, int output, int error, int directory, remozio_command_monitor_t **owner) {
    (void)monitor; (void)child; (void)frame; (void)count; (void)error; (void)directory;
    fixture_input = input; fixture_output = dup(output);
    if (fixture_output < 0) return errno;
    *owner = &fixture_owner; return scenario == 3 ? EIO : 0;
}
static int fixture_poll(remozio_command_monitor_t *owner, remozio_command_monitor_observation_t *state) {
    polls++; owner->state.configured = true;
    if (scenario == 12) owner->state.monitor_ownership_lost = true;
    if (!cancelled && !owner->state.release_attempted && polls == 1) {
        if (negative && scenario != 17) {
            owner->state.status.failed = true;
            owner->state.status.failure_error = scenario == 16 ? ETIMEDOUT : (uint32_t)rejection_error;
        }
        else if (scenario != 4) { owner->state.prepared = true; owner->state.target_kernel_registered = true; }
        if (scenario == 5) (void)write(fixture_output, "X", 1);
        if (scenario == 6) { char byte; (void)read(fixture_input, &byte, 1); }
    }
    if ((cancelled || owner->state.release_attempted || (negative && polls > 1)) && scenario != 11 && scenario != 12) {
        owner->state.monitor_reaped = true;
        owner->state.monitor_wait_status = negative ? EX_SOFTWARE << 8 : 0;
        if (scenario == 22 || scenario == 24) owner->state.monitor_wait_status = EX_SOFTWARE << 8;
        if (scenario == 23) owner->state.monitor_wait_status = SIGTERM;
        if (scenario == 25) owner->state.monitor_wait_status = 0;
        owner->state.status.reaped = scenario != 13;
        owner->state.target_exit_observed = owner->state.release_attempted;
        owner->state.target_exec_observed = owner->state.release_attempted && scenario != 9;
        owner->state.status.latest.tag = REMOZIO_MONITOR_TARGET_REAPED;
        if (fixture_output >= 0) { close(fixture_output); fixture_output = -1; }
    }
    if (owner->state.release_attempted) {
        if (scenario == 19) owner->state.fault = EIO;
        if (scenario == 20) owner->state.protocol_failed = true;
        if (scenario == 21) owner->state.status.failed = true;
    }
    *state = owner->state;
    return ((scenario == 4 && !cancelled) || (scenario == 18 && owner->state.release_attempted)) ? EIO : 0;
}
static int fixture_release(remozio_command_monitor_t *owner) {
    releases++;
    if (releases > 1) return scenario == 8 ? 0 : EALREADY;
    if (scenario == 7) return EIO;
    owner->state.release_attempted = true; owner->state.status.target_release_attempted = true;
    fixed_result_t result = {FIXED_RESULT_MAGIC, 1, scenario == 10 ? 0U : 1U, 1, 1};
    char byte; (void)read(fixture_input, &byte, 1);
    return write(fixture_output, &result, sizeof(result)) == sizeof(result) ? 0 : EIO;
}
static int fixture_cancel(remozio_command_monitor_t *owner) { (void)owner; cancelled = true; return 0; }
static int fixture_dispose(remozio_command_monitor_t *owner) {
    if (!owner->state.monitor_reaped) return EBUSY;
    disposals++; return 0;
}
#define clock_gettime fixture_clock
#define usleep fixture_pause
#define remozio_command_monitor_spawn fixture_spawn
#define remozio_command_monitor_poll fixture_poll
#define remozio_command_monitor_release fixture_release
#define remozio_command_monitor_cancel fixture_cancel
#define remozio_command_monitor_dispose fixture_dispose
#define main production_child_probe_entry
#include "probe.c"
#undef main
int main(void) {
    struct account target = {.uid = 501, .gid = 20, .name = "fixture", .groups = {20,100,200}, .count = 3};
    strcpy(directory, "/private/tmp"); strcpy(target_path, "/fixture/target");
    const struct { int scenario; enum case_kind kind; int error; bool retired; int disposed; } cases[] = {
        {0,positive,0,true,1}, {0,wrong_name,0,true,1}, {0,missing_group,0,true,1}, {0,legacy,0,true,1},
        {0,cancel_prepared,0,true,1}, {3,positive,4,true,1}, {4,positive,13,true,1},
        {5,positive,5,true,1}, {6,positive,5,true,1}, {7,positive,6,true,1}, {8,positive,6,true,1},
        {9,positive,9,true,1}, {10,positive,9,true,1}, {11,positive,11,false,0},
        {12,positive,11,false,0}, {13,positive,11,false,1}, {14,positive,11,false,0}, {15,positive,11,false,0},
        {16,wrong_name,5,true,1}, {17,missing_group,5,true,1},
        {18,positive,13,true,1}, {19,positive,13,true,1}, {20,positive,13,true,1}, {21,positive,13,true,1},
        {22,positive,14,true,1}, {23,positive,14,true,1}, {24,cancel_prepared,14,true,1}, {25,wrong_name,14,true,1}
    };
    for (unsigned i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        rejection_error = cases[i].kind == legacy ? EINVAL : ESTALE;
        scenario = cases[i].scenario; negative = cases[i].kind == wrong_name || cases[i].kind == missing_group || cases[i].kind == legacy;
        memset(&fixture_owner, 0, sizeof(fixture_owner)); polls = releases = disposals = 0; ticks = 1; cancelled = false;
        bool retired = true; int result = one(&target, cases[i].kind, &retired);
        if (fixture_output >= 0) { close(fixture_output); fixture_output = -1; }
        if (result != cases[i].error || retired != cases[i].retired || disposals != cases[i].disposed) {
            fprintf(stderr, "Owner control %u: result=%d cleanup=%d dispose=%d\n", i, result, retired, disposals); return 1;
        }
    }
    puts("{\"schemaVersion\":1,\"ownerControls\":28,\"privilegedControlsRun\":false,\"realProcessesSpawned\":0}"); return 0;
}
