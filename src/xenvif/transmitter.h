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

#ifndef _XENVIF_TRANSMITTER_H
#define _XENVIF_TRANSMITTER_H

#include <ntddk.h>
#include <netioapi.h>

#include <vif_interface.h>
#include <tcpip.h>

#include "frontend.h"

typedef struct _XENVIF_TRANSMITTER XENVIF_TRANSMITTER, *PXENVIF_TRANSMITTER;

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
TransmitterInitialize(
    _In_ PXENVIF_FRONTEND           Frontend,
    _Outptr_ PXENVIF_TRANSMITTER    *Transmitter
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
TransmitterConnect(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
TransmitterStoreWrite(
    _In_ PXENVIF_TRANSMITTER        Transmitter,
    _In_ PXENBUS_STORE_TRANSACTION  Transaction
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
TransmitterEnable(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
TransmitterDisable(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
TransmitterDisconnect(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

extern BOOLEAN
TransmitterIsPoisoned(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
TransmitterTeardown(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

extern VOID
TransmitterNotify(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _In_ ULONG                  Index
    );

_IRQL_requires_max_(APC_LEVEL)
extern VOID
TransmitterAbortPackets(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
TransmitterQueueArp(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _In_ PIPV4_ADDRESS          Address
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
TransmitterQueueNeighbourAdvertisement(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _In_ PIPV6_ADDRESS          Address
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
TransmitterQueueMulticastControl(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _In_ PETHERNET_ADDRESS      Address,
    _In_ BOOLEAN                Add
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
TransmitterQueryRingSize(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _Out_ PULONG                Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
TransmitterQueuePacket(
    _In_ PXENVIF_TRANSMITTER        Transmitter,
    _In_ PMDL                       Mdl,
    _In_ ULONG                      Offset,
    _In_ ULONG                      Length,
    _In_ XENVIF_VIF_OFFLOAD_OPTIONS OffloadOptions,
    _In_ USHORT                     MaximumSegmentSize,
    _In_ USHORT                     TagControlInformation,
    _In_ PXENVIF_PACKET_HASH        Hash,
    _In_ BOOLEAN                    More,
    _In_ PVOID                      Cookie
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
TransmitterQueryOffloadOptions(
    _In_ PXENVIF_TRANSMITTER            Transmitter,
    _Out_ PXENVIF_VIF_OFFLOAD_OPTIONS   Options
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
extern VOID
TransmitterQueryLargePacketSize(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _In_ UCHAR                  Version,
    _Out_ PULONG                Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
BOOLEAN
TransmitterHasMulticastControl(
    _In_ PXENVIF_TRANSMITTER    Transmitter
    );

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
TransmitterRequestMulticastControl(
    _In_ PXENVIF_TRANSMITTER    Transmitter,
    _In_ BOOLEAN                Enabled
    );

#endif  // _XENVIF_TRANSMITTER_H
