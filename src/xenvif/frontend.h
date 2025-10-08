/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _XENVIF_FRONTEND_H
#define _XENVIF_FRONTEND_H

#include <ntddk.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <evtchn_interface.h>
#include <store_interface.h>
#include <range_set_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <vif_interface.h>

#include "pdo.h"
#include "ethernet.h"

typedef struct _XENVIF_FRONTEND XENVIF_FRONTEND, *PXENVIF_FRONTEND;

typedef enum _XENVIF_FRONTEND_STATE {
    FRONTEND_UNKNOWN,
    FRONTEND_CLOSED,
    FRONTEND_PREPARED,
    FRONTEND_CONNECTED,
    FRONTEND_ENABLED
} XENVIF_FRONTEND_STATE, *PXENVIF_FRONTEND_STATE;

typedef VOID (*XENVIF_FRONTEND_HASH_CALLBACK)(
    _In_opt_ PVOID      Context,
    _In_ NTSTATUS       CallbackStatus,
    _In_ ULONG          Data
    );

typedef VOID (*XENVIF_FRONTEND_STATE_CALLBACK)(
    _In_opt_ PVOID      Context,
    _In_ NTSTATUS       CallbackStatus
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
FrontendInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_FRONTEND    *Frontend
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
FrontendTeardown(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern VOID
FrontendEjectFailed(
    IN PXENVIF_FRONTEND Frontend
    );

NTSTATUS
extern FrontendSetStateAsync(
    _In_ PXENVIF_FRONTEND               Frontend,
    _In_ XENVIF_FRONTEND_STATE_CALLBACK Callback,
    _In_ PVOID                          Argument,
    _In_ XENVIF_FRONTEND_STATE          State
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetState(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_FRONTEND_STATE   State
    );

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendResume(
    IN  PXENVIF_FRONTEND    Frontend
    );

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENVIF_PDO
FrontendGetPdo(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetPrefix(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetPath(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetBackendPath(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern USHORT
FrontendGetBackendDomain(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern ULONG
FrontendGetMaxQueues(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern ULONG
FrontendGetNumQueues(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern BOOLEAN
FrontendIsSplit(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern BOOLEAN
FrontendIsSplit(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendFormatPath(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  ULONG               Index
    );

extern VOID
FrontendFreePath(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PCHAR               Path
    );

#include "mac.h"

extern PXENVIF_MAC
FrontendGetMac(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "receiver.h"

extern PXENVIF_RECEIVER
FrontendGetReceiver(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "transmitter.h"

extern PXENVIF_TRANSMITTER
FrontendGetTransmitter(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "controller.h"

extern PXENVIF_CONTROLLER
FrontendGetController(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern VOID
FrontendQueryStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    );

extern VOID
FrontendIncrementStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Index,
    IN  ULONGLONG               Delta
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetMulticastAddresses(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetFilterLevel(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
FrontendAdvertiseIpAddresses(
    IN  PXENVIF_FRONTEND    Frontend
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashAlgorithm(
    _In_ PXENVIF_FRONTEND                   Frontend,
    _In_opt_ XENVIF_FRONTEND_HASH_CALLBACK  Callback,
    _In_opt_ PVOID                          Argument,
    _In_ XENVIF_PACKET_HASH_ALGORITHM       Algorithm
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendQueryHashTypes(
    _In_ PXENVIF_FRONTEND                   Frontend,
    _In_opt_ XENVIF_FRONTEND_HASH_CALLBACK  Callback,
    _In_opt_ PVOID                          Argument
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashMapping(
    _In_ PXENVIF_FRONTEND                   Frontend,
    _In_opt_ XENVIF_FRONTEND_HASH_CALLBACK  Callback,
    _In_opt_ PVOID                          Argument,
    _In_reads_bytes_(Size) PULONG           Mapping,
    _In_ ULONG                              Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashKey(
    _In_ PXENVIF_FRONTEND                               Frontend,
    _In_opt_ XENVIF_FRONTEND_HASH_CALLBACK              Callback,
    _In_opt_ PVOID                                      Argument,
    _In_reads_bytes_(XENVIF_VIF_HASH_KEY_SIZE) PUCHAR   Key
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashTypes(
    _In_ PXENVIF_FRONTEND                   Frontend,
    _In_opt_ XENVIF_FRONTEND_HASH_CALLBACK  Callback,
    _In_opt_ PVOID                          Argument,
    _In_ ULONG                              Types
    );

extern ULONG
FrontendGetQueue(
    IN  PXENVIF_FRONTEND                Frontend,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm,
    IN  ULONG                           Index
    );

#endif  // _XENVIF_FRONTEND_H
