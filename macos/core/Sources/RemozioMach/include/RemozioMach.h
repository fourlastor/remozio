#ifndef REMOZIO_MACH_H
#define REMOZIO_MACH_H
#include <mach/mach.h>
#include <Security/Security.h>
#include <stdbool.h>
#include <sys/fileport.h>
#include <sys/types.h>
#include <membership.h>
#include "RemozioCommandChild.h"
#include "RemozioCommandCredentials.h"
#include "RemozioCommandProcess.h"
#include "RemozioCommandMonitorProtocol.h"
#include "RemozioCommandMonitor.h"
#include "RemozioCommandCaller.h"
#include "RemozioCommandPTY.h"
#include "RemozioFrontendTerminal.h"
#include "RemozioFrontendRuntime.h"
#include "RemozioCommandStreamSource.h"
#include "RemozioCommandTerminalContext.h"
typedef struct {
    mach_port_seqno_t sequence;
    mach_msg_size_t size;
    mach_msg_id_t identifier;
    audit_token_t token;
} remozio_mach_preview_t;
kern_return_t remozio_pid_audit_token(pid_t pid, audit_token_t * _Nonnull token, bool * _Nonnull missing);
kern_return_t remozio_preview_audit(mach_port_t endpoint, mach_msg_timeout_t timeout,
    remozio_mach_preview_t * _Nonnull preview);
kern_return_t remozio_discard_message(mach_port_t endpoint);
kern_return_t remozio_receive_audit(mach_msg_header_t * _Nonnull buffer, mach_msg_size_t capacity,
    mach_port_t endpoint, mach_msg_timeout_t timeout);
OSStatus remozio_copy_dynamic_signing_information(SecCodeRef _Nonnull code,
    CFDictionaryRef _Nullable * _Nonnull CF_RETURNS_RETAINED information);
bool remozio_code_is_adhoc(uint32_t flags);
#include "RemozioAuthorityBootstrap.h"
#endif
