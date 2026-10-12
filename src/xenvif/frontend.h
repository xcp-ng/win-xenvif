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
    FRONTEND_POISONED,
    FRONTEND_ENABLED
} XENVIF_FRONTEND_STATE, *PXENVIF_FRONTEND_STATE;

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
FrontendInitialize(
    _In_ PXENVIF_PDO            Pdo,
    _Outptr_ PXENVIF_FRONTEND   *Frontend
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
FrontendTeardown(
    _Out_ PXENVIF_FRONTEND  Frontend
    );

extern VOID
FrontendEjectFailed(
    _Out_ PXENVIF_FRONTEND  Frontend
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetState(
    _Out_ PXENVIF_FRONTEND      Frontend,
    _In_ XENVIF_FRONTEND_STATE  State
    );

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendResume(
    _Out_ PXENVIF_FRONTEND  Frontend
    );

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
FrontendSuspend(
    _Out_ PXENVIF_FRONTEND  Frontend
    );

extern PXENVIF_PDO
FrontendGetPdo(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern PCHAR
FrontendGetPrefix(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern PCHAR
FrontendGetPath(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern PCHAR
FrontendGetBackendPath(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern USHORT
FrontendGetBackendDomain(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern ULONG
FrontendGetMaxQueues(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern ULONG
FrontendGetNumQueues(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern BOOLEAN
FrontendIsSplit(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern BOOLEAN
FrontendIsSplit(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern PCHAR
FrontendFormatPath(
    _In_ PXENVIF_FRONTEND   Frontend,
    _In_ ULONG              Index
    );

extern VOID
FrontendFreePath(
    _In_ PXENVIF_FRONTEND   Frontend,
    _In_ PSTR               Path
    );

#include "mac.h"

extern PXENVIF_MAC
FrontendGetMac(
    _In_ PXENVIF_FRONTEND   Frontend
    );

#include "receiver.h"

extern PXENVIF_RECEIVER
FrontendGetReceiver(
    _In_ PXENVIF_FRONTEND   Frontend
    );

#include "transmitter.h"

extern PXENVIF_TRANSMITTER
FrontendGetTransmitter(
    _In_ PXENVIF_FRONTEND   Frontend
    );

#include "controller.h"

extern PXENVIF_CONTROLLER
FrontendGetController(
    _In_ PXENVIF_FRONTEND   Frontend
    );

extern VOID
FrontendQueryStatistic(
    _In_ PXENVIF_FRONTEND       Frontend,
    _In_ XENVIF_VIF_STATISTIC   Index,
    _Out_ PULONGLONG            Value
    );

extern VOID
FrontendIncrementStatistic(
    _In_ PXENVIF_FRONTEND       Frontend,
    _In_ XENVIF_VIF_STATISTIC   Index,
    _In_ ULONGLONG              Delta
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetMulticastAddresses(
    _In_ PXENVIF_FRONTEND               Frontend,
    _In_reads_(Count) PETHERNET_ADDRESS Address,
    _In_ ULONG                          Count
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetFilterLevel(
    _In_ PXENVIF_FRONTEND           Frontend,
    _In_ ETHERNET_ADDRESS_TYPE      Type,
    _In_ XENVIF_MAC_FILTER_LEVEL    Level
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
FrontendAdvertiseIpAddresses(
    _Out_ PXENVIF_FRONTEND  Frontend
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashAlgorithm(
    _Out_ PXENVIF_FRONTEND              Frontend,
    _In_ XENVIF_PACKET_HASH_ALGORITHM   Algorithm
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendQueryHashTypes(
    _Out_ PXENVIF_FRONTEND  Frontend,
    _Out_ PULONG            Types
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashMapping(
    _Out_ PXENVIF_FRONTEND  Frontend,
    _In_ PULONG             Mapping,
    _In_ ULONG              Order
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashKey(
    _Out_ PXENVIF_FRONTEND  Frontend,
    _In_ PUCHAR             Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern NTSTATUS
FrontendSetHashTypes(
    _Out_ PXENVIF_FRONTEND  Frontend,
    _In_ ULONG              Types
    );

extern ULONG
FrontendGetQueue(
    _In_ PXENVIF_FRONTEND               Frontend,
    _In_ XENVIF_PACKET_HASH_ALGORITHM   Algorithm,
    _In_ ULONG                          Index
    );

#endif  // _XENVIF_FRONTEND_H
