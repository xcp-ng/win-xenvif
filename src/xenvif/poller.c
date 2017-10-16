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
 *     following disclaimer in the documetation and/or other
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

#include <ntddk.h>
#include <procgrp.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xen.h>

#include <debug_interface.h>
#include <store_interface.h>
#include <evtchn_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "poller.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MAXNAMELEN  128

struct _XENVIF_POLLER {
    PXENVIF_FRONTEND        Frontend;
    XENBUS_DEBUG_INTERFACE  DebugInterface;
    PXENBUS_DEBUG_CALLBACK  DebugCallback;
};

#define XENVIF_POLLER_TAG  'LLOP'

static FORCEINLINE PVOID
__PollerAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_POLLER_TAG);
}

static FORCEINLINE VOID
__PollerFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_POLLER_TAG);
}

static VOID
PollerDebugCallback(
    IN  PVOID   Argument,
    IN  BOOLEAN Crashing
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Crashing);
}

NTSTATUS
PollerInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_POLLER      *Poller
    )
{
    NTSTATUS                status;

    *Poller = __PollerAllocate(sizeof (XENVIF_POLLER));

    status = STATUS_NO_MEMORY;
    if (*Poller == NULL)
        goto fail1;

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Poller)->DebugInterface);

    (*Poller)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
PollerConnect(
    IN  PXENVIF_POLLER  Poller
    )
{
    NTSTATUS            status;

    Trace("====>\n");

    status = XENBUS_DEBUG(Acquire, &Poller->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
                          &Poller->DebugInterface,
                          __MODULE__ "|POLLER",
                          PollerDebugCallback,
                          Poller,
                          &Poller->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Poller->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
PollerStoreWrite(
    IN  PXENVIF_POLLER              Poller,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    UNREFERENCED_PARAMETER(Poller);
    UNREFERENCED_PARAMETER(Transaction);

    Trace("<===>\n");

    return STATUS_SUCCESS;
}

NTSTATUS
PollerEnable(
    IN  PXENVIF_POLLER      Poller
    )
{
    UNREFERENCED_PARAMETER(Poller);

    Trace("<===>\n");

    return STATUS_SUCCESS;
}

VOID
PollerDisable(
    IN  PXENVIF_POLLER      Poller
    )
{
    UNREFERENCED_PARAMETER(Poller);

    Trace("<===>\n");
}

VOID
PollerDisconnect(
    IN  PXENVIF_POLLER  Poller
    )
{
    Trace("====>\n");

    XENBUS_DEBUG(Deregister,
                 &Poller->DebugInterface,
                 Poller->DebugCallback);
    Poller->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Poller->DebugInterface);

    Trace("<====\n");
}

VOID
PollerTeardown(
    IN  PXENVIF_POLLER  Poller
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    RtlZeroMemory(&Poller->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    ASSERT(IsZeroMemory(Poller, sizeof (XENVIF_POLLER)));
    __PollerFree(Poller);
}
