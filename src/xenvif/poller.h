/* Copyright (c) Citrix Systems Inc.
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

#ifndef _XENVIF_POLLER_H
#define _XENVIF_POLLER_H

#include <ntddk.h>

#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_POLLER XENVIF_POLLER, *PXENVIF_POLLER;

typedef enum _XENVIF_POLLER_EVENT_TYPE {
    XENVIF_POLLER_EVENT_RECEIVE,
    XENVIF_POLLER_EVENT_TRANSMIT,
    XENVIF_POLLER_EVENT_TYPE_COUNT
} XENVIF_POLLER_EVENT_TYPE, *PXENVIF_POLLER_EVENT_TYPE;

extern NTSTATUS
PollerInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_POLLER      *Poller
    );

extern NTSTATUS
PollerConnect(
    IN  PXENVIF_POLLER  Poller
    );

extern NTSTATUS
PollerStoreWrite(
    IN  PXENVIF_POLLER              Poller,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    );

extern NTSTATUS
PollerEnable(
    IN  PXENVIF_POLLER  Poller
    );

extern NTSTATUS
PollerSend(
    IN  PXENVIF_POLLER              Poller,
    IN  ULONG                       Index,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    );

extern NTSTATUS
PollerTrigger(
    IN  PXENVIF_POLLER              Poller,
    IN  ULONG                       Index,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    );

extern VOID
PollerDisable(
    IN  PXENVIF_POLLER  Poller
    );

extern VOID
PollerDisconnect(
    IN  PXENVIF_POLLER  Poller
    );

extern VOID
PollerTeardown(
    IN  PXENVIF_POLLER  Poller
    );

#endif  // _XENVIF_POLLER_H
