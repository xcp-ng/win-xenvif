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

#ifndef _XENVIF_MAC_H
#define _XENVIF_MAC_H

#include <ntddk.h>
#include <ethernet.h>
#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_MAC XENVIF_MAC, *PXENVIF_MAC;

extern NTSTATUS
MacInitialize(
    _In_ PXENVIF_FRONTEND   Frontend,
    _Outptr_ PXENVIF_MAC    *Mac
    );

extern NTSTATUS
MacConnect(
    _Out_ PXENVIF_MAC   Mac
    );

extern NTSTATUS
MacEnable(
    _Out_ PXENVIF_MAC   Mac
    );

extern VOID
MacDisable(
    _Out_ PXENVIF_MAC   Mac
    );

extern VOID
MacDisconnect(
    _Out_ PXENVIF_MAC   Mac
    );

extern VOID
MacTeardown(
    _Out_ PXENVIF_MAC   Mac
    );

extern VOID
MacQueryMaximumFrameSize(
    _In_ PXENVIF_MAC    Mac,
    _Out_ PULONG        Size
    );

extern VOID
MacQueryPermanentAddress(
    _In_ PXENVIF_MAC        Mac,
    _Out_ PETHERNET_ADDRESS Address
    );

extern VOID
MacQueryCurrentAddress(
    _In_ PXENVIF_MAC        Mac,
    _Out_ PETHERNET_ADDRESS Address
    );

extern VOID
MacQueryBroadcastAddress(
    _In_ PXENVIF_MAC        Mac,
    _Out_ PETHERNET_ADDRESS Address
    );

extern NTSTATUS
MacDumpAddressTable(
    _Out_ PXENVIF_MAC   Mac
    );

extern NTSTATUS
MacAddMulticastAddress(
    _Out_ PXENVIF_MAC       Mac,
    _In_ PETHERNET_ADDRESS  Address
    );

extern NTSTATUS
MacRemoveMulticastAddress(
    _Out_ PXENVIF_MAC       Mac,
    _In_ PETHERNET_ADDRESS  Address
    );

extern NTSTATUS
MacQueryMulticastAddresses(
    _Out_ PXENVIF_MAC               Mac,
    _Inout_opt_ PETHERNET_ADDRESS   Address,
    _Inout_ PULONG                  Count
    );

extern NTSTATUS
MacSetFilterLevel(
    _Out_ PXENVIF_MAC               Mac,
    _In_ ETHERNET_ADDRESS_TYPE      Type,
    _In_ XENVIF_MAC_FILTER_LEVEL    Level
    );

extern NTSTATUS
MacQueryFilterLevel(
    _Out_ PXENVIF_MAC               Mac,
    _In_ ETHERNET_ADDRESS_TYPE      Type,
    _Out_ PXENVIF_MAC_FILTER_LEVEL  Level
    );

extern VOID
MacQueryState(
    _In_ PXENVIF_MAC                        Mac,
    _Out_opt_ PNET_IF_MEDIA_CONNECT_STATE   MediaConnectState,
    _Out_opt_ PULONG64                      LinkSpeed,
    _Out_opt_ PNET_IF_MEDIA_DUPLEX_STATE    MediaDuplexState
    );

extern BOOLEAN
MacApplyFilters(
    _Out_ PXENVIF_MAC       Mac,
    _In_ PETHERNET_ADDRESS  DestinationAddress
    );

#endif  // _XENVIF_MAC_H
