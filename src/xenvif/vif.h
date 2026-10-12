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

#ifndef _XENVIF_VIF_H
#define _XENVIF_VIF_H

#include <ntddk.h>
#include <vif_interface.h>

#include "thread.h"

typedef struct _XENVIF_VIF_CONTEXT  XENVIF_VIF_CONTEXT, *PXENVIF_VIF_CONTEXT;

#include "fdo.h"

extern NTSTATUS
VifInitialize(
    _In_ PXENVIF_PDO                Pdo,
    _Outptr_ PXENVIF_VIF_CONTEXT    *Context
    );

extern NTSTATUS
VifGetInterface(
    _In_ PXENVIF_VIF_CONTEXT    Context,
    _In_ ULONG                  Version,
    _Inout_ PINTERFACE          Interface,
    _In_ ULONG                  Size
    );

extern VOID
VifTeardown(
    _Out_ PXENVIF_VIF_CONTEXT   Context
    );

// CALLBACKS

extern VOID
VifReceiverQueuePacket(
    _In_ PXENVIF_VIF_CONTEXT            Context,
    _In_ ULONG                          Index,
    _In_ PMDL                           Mdl,
    _In_ ULONG                          Offset,
    _In_ ULONG                          Length,
    _In_ XENVIF_PACKET_CHECKSUM_FLAGS   Flags,
    _In_ USHORT                         MaximumSegmentSize,
    _In_ USHORT                         TagControlInformation,
    _In_ PXENVIF_PACKET_INFO            Info,
    _In_ PXENVIF_PACKET_HASH            Hash,
    _In_ BOOLEAN                        More,
    _In_ PVOID                          Cookie,
    _Out_ PBOOLEAN                      Pause
    );

extern VOID
VifTransmitterReturnPacket(
    _In_ PXENVIF_VIF_CONTEXT                        Context,
    _In_ PVOID                                      Cookie,
    _In_ PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO Completion
    );

extern PXENVIF_THREAD
VifGetMacThread(
    _In_ PXENVIF_VIF_CONTEXT    Context
    );

#endif  // _XENVIF_VIF_H
