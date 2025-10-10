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
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_RECEIVER    *Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ReceiverConnect(
    IN  PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ReceiverStoreWrite(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ReceiverEnable(
    IN  PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverDisable(
    IN  PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverDisconnect(
    IN  PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
ReceiverTeardown(
    IN  PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_max_(APC_LEVEL)
extern VOID
ReceiverWaitForPackets(
    IN  PXENVIF_RECEIVER    Receiver
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverQueryRingSize(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PULONG              Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverSetOffloadOptions(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverSetBackfillSize(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverReturnPacket(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  PVOID               Cookie
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverTrigger(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Index
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ReceiverSend(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Index
    );

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ReceiverSetHashAlgorithm(
    IN  PXENVIF_RECEIVER                Receiver,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    );

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ReceiverQueryHashCapabilities(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PULONG              Types
    );

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ReceiverUpdateHashParameters(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  ULONG               Types,
    IN  PUCHAR              Key
    );

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ReceiverUpdateHashMapping(
    IN  PXENVIF_RECEIVER    Receiver,
    IN  PPROCESSOR_NUMBER   ProcessorMapping,
    IN  ULONG               Order
    );

#endif  // _XENVIF_RECEIVER_H
