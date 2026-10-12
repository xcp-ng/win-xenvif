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

#ifndef _XENVIF_RECEIVER_H
#define _XENVIF_RECEIVER_H

#include <ntddk.h>
#include <ifdef.h>
#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_RECEIVER XENVIF_RECEIVER, *PXENVIF_RECEIVER;

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
ReceiverInitialize(
    _In_ PXENVIF_FRONTEND       Frontend,
    _Outptr_ PXENVIF_RECEIVER   *Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ReceiverConnect(
    _In_ PXENVIF_RECEIVER   Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ReceiverStoreWrite(
    _In_ PXENVIF_RECEIVER           Receiver,
    _In_ PXENBUS_STORE_TRANSACTION  Transaction
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ReceiverEnable(
    _In_ PXENVIF_RECEIVER   Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverDisable(
    _In_ PXENVIF_RECEIVER   Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverDisconnect(
    _Out_ PXENVIF_RECEIVER  Receiver
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
ReceiverTeardown(
    _Inout_ PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_max_(APC_LEVEL)
extern VOID
ReceiverWaitForPackets(
    _Out_ PXENVIF_RECEIVER  Receiver
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
ReceiverQueryRingSize(
    _In_ PXENVIF_RECEIVER   Receiver,
    _Out_ PULONG            Size
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
ReceiverSetOffloadOptions(
    _In_ PXENVIF_RECEIVER           Receiver,
    _In_ XENVIF_VIF_OFFLOAD_OPTIONS Options
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
ReceiverSetBackfillSize(
    _In_ PXENVIF_RECEIVER   Receiver,
    _In_ ULONG              Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverReturnPacket(
    _Out_ PXENVIF_RECEIVER  Receiver,
    _In_ PVOID              Cookie
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverTrigger(
    _In_ PXENVIF_RECEIVER   Receiver,
    _In_ ULONG              Index
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverSend(
    _In_ PXENVIF_RECEIVER   Receiver,
    _In_ ULONG              Index
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ReceiverSetHashAlgorithm(
    _In_ PXENVIF_RECEIVER               Receiver,
    _In_ XENVIF_PACKET_HASH_ALGORITHM   Algorithm
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ReceiverQueryHashCapabilities(
    _In_ PXENVIF_RECEIVER   Receiver,
    _Out_ PULONG            Types
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ReceiverUpdateHashParameters(
    _In_ PXENVIF_RECEIVER   Receiver,
    _In_ ULONG              Types,
    _In_ PUCHAR             Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ReceiverUpdateHashMapping(
    _In_ PXENVIF_RECEIVER   Receiver,
    _In_ PPROCESSOR_NUMBER  ProcessorMapping,
    _In_ ULONG              Order
    );

#endif  // _XENVIF_RECEIVER_H
