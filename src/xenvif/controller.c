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
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <evtchn_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "controller.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

extern ULONG
NTAPI
RtlRandomEx (
    __inout PULONG Seed
    );

#define MAXNAMELEN  128

typedef enum _XENVIF_CONTROLLER_REQUEST_STATE {
    XENVIF_CONTROLLER_REQUEST_FREE = 0,
    XENVIF_CONTROLLER_REQUEST_BUSY,
    XENVIF_CONTROLLER_REQUEST_RESPONDED
} XENVIF_CONTROLLER_REQUEST_STATE;

typedef struct _XENVIF_CONTROLLER_SET_HASH_MAPPING {
    PMDL                    Mdl;
    PXENBUS_GNTTAB_ENTRY    Entry;
} XENVIF_CONTROLLER_SET_HASH_MAPPING, *PXENVIF_CONTROLLER_SET_HASH_MAPPING;

typedef struct _XENVIF_CONTROLLER_SET_HASH_KEY {
    PMDL                    Mdl;
    PXENBUS_GNTTAB_ENTRY    Entry;
} XENVIF_CONTROLLER_SET_HASH_KEY, *PXENVIF_CONTROLLER_SET_HASH_KEY;

typedef union {
    XENVIF_CONTROLLER_SET_HASH_MAPPING  SetHashMapping;
    XENVIF_CONTROLLER_SET_HASH_KEY      SetHashKey;
} XENVIF_CONTROLLER_PENDING_REQUEST;

typedef struct _XENVIF_CONTROLLER_REQUEST_DATA {
    XENVIF_CONTROLLER_REQUEST_STATE     State;
    // Busy
    USHORT                              RequestId;
    struct xen_netif_ctrl_request       Request;
    // Responded
    struct xen_netif_ctrl_response      Response;
    // Not free
    XENVIF_CONTROLLER_PENDING_REQUEST   Pending;
    XENVIF_CONTROLLER_REQUEST_CALLBACK  Callback;
    PVOID                               Argument;
} XENVIF_CONTROLLER_REQUEST_DATA, *PXENVIF_CONTROLLER_REQUEST_DATA;

struct _XENVIF_CONTROLLER {
    PXENVIF_FRONTEND                    Frontend;
    KSPIN_LOCK                          Lock;
    PXENBUS_GNTTAB_CACHE                GnttabCache;
    PMDL                                Mdl;
    xen_netif_ctrl_front_ring_t         Front;
    xen_netif_ctrl_sring_t              *Shared;
    PXENBUS_GNTTAB_ENTRY                Entry;
    PXENBUS_EVTCHN_CHANNEL              Channel;
    KDPC                                EvtchnDpc;
    ULONG                               Events;
    BOOLEAN                             Connected;
    PXENVIF_THREAD                      RequestThread;
    XENVIF_CONTROLLER_REQUEST_DATA      RequestData;
    XENBUS_GNTTAB_INTERFACE             GnttabInterface;
    XENBUS_EVTCHN_INTERFACE             EvtchnInterface;
    XENBUS_STORE_INTERFACE              StoreInterface;
    XENBUS_DEBUG_INTERFACE              DebugInterface;
    PXENBUS_DEBUG_CALLBACK              DebugCallback;
};

#define XENVIF_CONTROLLER_TAG  'TNOC'

static FORCEINLINE PVOID
__ControllerAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_CONTROLLER_TAG);
}

static FORCEINLINE VOID
__ControllerFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_CONTROLLER_TAG);
}

static FORCEINLINE VOID
_IRQL_requires_min_(DISPATCH_LEVEL)
__ControllerAcquireLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    ASSERT3U(KeGetCurrentIrql(), >=, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Controller->Lock);
}

static FORCEINLINE VOID
_IRQL_requires_min_(DISPATCH_LEVEL)
__ControllerReleaseLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
#pragma prefast(suppress:26110) // Caller failing to hold lock
    KeReleaseSpinLockFromDpcLevel(&Controller->Lock);
}

_IRQL_requires_min_(DISPATCH_LEVEL)
static VOID
ControllerAcquireLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    __ControllerAcquireLock(Controller);
}

_IRQL_requires_min_(DISPATCH_LEVEL)
static VOID
ControllerReleaseLock(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    __ControllerReleaseLock(Controller);
}

_IRQL_requires_min_(DISPATCH_LEVEL)
static FORCEINLINE VOID
__ControllerSend(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    (VOID) XENBUS_EVTCHN(Send,
                         &Controller->EvtchnInterface,
                         Controller->Channel);
}

VOID
ControllerPoll(
    IN  PXENVIF_CONTROLLER          Controller
    )
{
    RING_IDX                        rsp_prod;
    RING_IDX                        rsp_cons;
    struct xen_netif_ctrl_response  *rsp;

    KeMemoryBarrier();

    rsp_prod = Controller->Shared->rsp_prod;
    rsp_cons = Controller->Front.rsp_cons;

    KeMemoryBarrier();

    if (rsp_cons == rsp_prod)
        return;

    rsp = RING_GET_RESPONSE(&Controller->Front, rsp_cons);
    rsp_cons++;

    Controller->RequestData.Response = *rsp;

    KeMemoryBarrier();

    Controller->Front.rsp_cons = rsp_cons;
    Controller->Shared->rsp_event = rsp_cons + 1;
}

_IRQL_requires_min_(DISPATCH_LEVEL)
_Requires_lock_held_(Controller->Lock)
static NTSTATUS
ControllerPutRequest(
    IN  PXENVIF_CONTROLLER          Controller,
    IN  USHORT                      Type,
    IN  ULONG                       Data0,
    IN  ULONG                       Data1,
    IN  ULONG                       Data2
    )
{
    RING_IDX                        req_prod;
    struct xen_netif_ctrl_request   *req;
    BOOLEAN                         Notify;
    NTSTATUS                        status;

    status = STATUS_NOT_SUPPORTED;
    if (!Controller->Connected)
        goto fail1;

    ASSERT(Controller->RequestData.State == XENVIF_CONTROLLER_REQUEST_FREE);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (RING_FULL(&Controller->Front))
        goto fail2;

    Controller->RequestData.State = XENVIF_CONTROLLER_REQUEST_BUSY;

    Controller->RequestData.Request.type = Type;

    Controller->RequestData.Request.id = Controller->RequestData.RequestId++;
    if (Controller->RequestData.Request.id == 0) // Make sure we skip zero
        Controller->RequestData.Request.id =
            Controller->RequestData.RequestId++;

    Controller->RequestData.Request.data[0] = Data0;
    Controller->RequestData.Request.data[1] = Data1;
    Controller->RequestData.Request.data[2] = Data2;

    req_prod = Controller->Front.req_prod_pvt;

    req = RING_GET_REQUEST(&Controller->Front, req_prod);
    req_prod++;

    *req = Controller->RequestData.Request;

    KeMemoryBarrier();

    Controller->Front.req_prod_pvt = req_prod;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Controller->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __ControllerSend(Controller);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENVIF_CONTROLLER_POLL_PERIOD 100 // ms

_IRQL_requires_(DISPATCH_LEVEL)
_Requires_lock_held_(Controller->Lock)
static NTSTATUS
ControllerGetResponse(
    IN  PXENVIF_CONTROLLER          Controller,
    OUT PULONG                      Data OPTIONAL
    )
{
    NTSTATUS                        status;

    ASSERT(Controller->RequestData.State == XENVIF_CONTROLLER_REQUEST_BUSY);

    ControllerPoll(Controller);
    KeMemoryBarrier();

    if (Controller->RequestData.Response.id !=
        Controller->RequestData.Request.id)
        return STATUS_PENDING;

    ASSERT3U(Controller->RequestData.Response.type, ==,
             Controller->RequestData.Request.type);

    switch (Controller->RequestData.Response.status) {
    case XEN_NETIF_CTRL_STATUS_SUCCESS:
        status = STATUS_SUCCESS;
        break;

    case XEN_NETIF_CTRL_STATUS_NOT_SUPPORTED:
        status = STATUS_NOT_SUPPORTED;
        break;

    case XEN_NETIF_CTRL_STATUS_INVALID_PARAMETER:
        status = STATUS_INVALID_PARAMETER;
        break;

    case XEN_NETIF_CTRL_STATUS_BUFFER_OVERFLOW:
        status = STATUS_BUFFER_OVERFLOW;
        break;

    default:
        status = STATUS_UNSUCCESSFUL;
        break;
    }

    if (NT_SUCCESS(status) && Data != NULL)
        *Data = Controller->RequestData.Response.data;

    RtlZeroMemory(&Controller->RequestData.Request,
                  sizeof (struct xen_netif_ctrl_request));
    RtlZeroMemory(&Controller->RequestData.Response,
                  sizeof (struct xen_netif_ctrl_response));

    Controller->RequestData.State = XENVIF_CONTROLLER_REQUEST_RESPONDED;

    return status;
}

KSERVICE_ROUTINE    ControllerEvtchnCallback;

_Use_decl_annotations_
BOOLEAN
ControllerEvtchnCallback(
    IN  PKINTERRUPT             InterruptObject,
    IN  PVOID                   Argument
    )
{
    PXENVIF_CONTROLLER          Controller = Argument;
    BOOLEAN                     Queued;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Controller != NULL);

    ControllerAcquireLock(Controller);

    Controller->Events++;

    KeInsertQueueDpc(&Controller->EvtchnDpc, NULL, NULL);

    ControllerReleaseLock(Controller);

    return TRUE;
}

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
ControllerEvtchnDpc(
    _In_ PKDPC          Dpc,
    _In_opt_ PVOID      DeferredContext,
    _In_opt_ PVOID      SystemArgument1,
    _In_opt_ PVOID      SystemArgument2
    )
{
    PXENVIF_CONTROLLER  Controller = DeferredContext;
    LONG                Previous;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ASSERT(Controller != NULL);

    ControllerAcquireLock(Controller);

    if (Controller->RequestData.State != XENVIF_CONTROLLER_REQUEST_BUSY)
    {
        Trace("Controller DPC executed while request is not busy (%d)!\n",
              Controller->RequestData.State);
        goto out_unlock;
    }

    ThreadWake(Controller->RequestThread);

out_unlock:
    ControllerReleaseLock(Controller);
}

static NTSTATUS
ControllerRequest(
    _In_ PXENVIF_THREAD Self,
    _In_ PVOID          Context
    )
{
    PXENVIF_CONTROLLER  Controller = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        KIRQL                               Irql;
        NTSTATUS                            status;
        ULONG                               Data;
        XENVIF_CONTROLLER_REQUEST_CALLBACK  Callback;
        PVOID                               Argument;

        KeWaitForSingleObject(Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeAcquireSpinLock(&Controller->Lock, &Irql);

        switch (Controller->RequestData.State) {
        case XENVIF_CONTROLLER_REQUEST_BUSY:
            status = ControllerGetResponse(Controller, &Data);

            if (status == STATUS_PENDING)
                goto out_unlock;

            ASSERT3U(Controller->RequestData.State, ==,
                     XENVIF_CONTROLLER_REQUEST_RESPONDED);

            Callback = Controller->RequestData.Callback;
            Argument = Controller->RequestData.Argument;

            RtlZeroMemory(&Controller->RequestData.Pending,
                  sizeof (XENVIF_CONTROLLER_PENDING_REQUEST));

            Controller->RequestData.Callback = NULL;
            Controller->RequestData.Argument = NULL;
            Controller->RequestData.State = XENVIF_CONTROLLER_REQUEST_FREE;

            break;
        default:
            break;
        }

out_unlock:
        KeReleaseSpinLock(&Controller->Lock, Irql);

        if (Callback)
            Callback(Argument, status, NT_SUCCESS(status) ? Data : 0);
    }

    return STATUS_SUCCESS;
}

static VOID
ControllerDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Crashing);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ControllerInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_CONTROLLER  *Controller
    )
{
    LARGE_INTEGER           Now;
    ULONG                   Seed;
    NTSTATUS                status;

    *Controller = __ControllerAllocate(sizeof (XENVIF_CONTROLLER));

    status = STATUS_NO_MEMORY;
    if (*Controller == NULL)
        goto fail1;

    KeInitializeDpc(&(*Controller)->EvtchnDpc, ControllerEvtchnDpc, *Controller);

    (*Controller)->RequestThread = ThreadCreate(ControllerRequest,
                                                *Controller,
                                                &(*Controller)->RequestThread);
    if ((*Controller)->RequestThread == NULL)
        goto fail2;

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Controller)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Controller)->StoreInterface);

    FdoGetGnttabInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Controller)->GnttabInterface);

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Controller)->EvtchnInterface);

    KeInitializeSpinLock(&(*Controller)->Lock);

    KeQuerySystemTime(&Now);
    Seed = Now.LowPart;

    (*Controller)->RequestData.RequestId = (USHORT)RtlRandomEx(&Seed);

    (*Controller)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __ControllerFree(*Controller);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerConnect(
    IN  PXENVIF_CONTROLLER      Controller
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    BOOLEAN                     Feature;
    PFN_NUMBER                  Pfn;
    CHAR                        Name[MAXNAMELEN];
    ULONG                       Index;
    NTSTATUS                    status;

    Trace("====>\n");

    Frontend = Controller->Frontend;

    status = XENBUS_DEBUG(Acquire, &Controller->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Controller->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &Controller->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Controller->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_STORE(Read,
                          &Controller->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-ctrl-ring",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Feature = FALSE;
    } else {
        Feature = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Controller->StoreInterface,
                     Buffer);
    }

    if (!Feature)
        goto done;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_controller",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_GNTTAB(CreateCache,
                           &Controller->GnttabInterface,
                           Name,
                           0,
                           0,
                           ControllerAcquireLock,
                           ControllerReleaseLock,
                           Controller,
                           &Controller->GnttabCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    Controller->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Controller->Mdl == NULL)
        goto fail7;

    ASSERT(Controller->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Controller->Shared = Controller->Mdl->MappedSystemVa;
    ASSERT(Controller->Shared != NULL);

    SHARED_RING_INIT(Controller->Shared);
    FRONT_RING_INIT(&Controller->Front, Controller->Shared, PAGE_SIZE);
    ASSERT3P(Controller->Front.sring, ==, Controller->Shared);

    Pfn = MmGetMdlPfnArray(Controller->Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Controller->GnttabInterface,
                           Controller->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Controller->Entry);
    if (!NT_SUCCESS(status))
        goto fail8;

    Controller->Channel = XENBUS_EVTCHN(Open,
                                        &Controller->EvtchnInterface,
                                        XENBUS_EVTCHN_TYPE_UNBOUND,
                                        ControllerEvtchnCallback,
                                        Controller,
                                        FrontendGetBackendDomain(Frontend),
                                        FALSE);

    status = STATUS_UNSUCCESSFUL;
    if (Controller->Channel == NULL)
        goto fail9;

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Controller->EvtchnInterface,
                         Controller->Channel,
                         FALSE,
                         TRUE);

    status = XENBUS_DEBUG(Register,
                          &Controller->DebugInterface,
                          __MODULE__ "|CONTROLLER",
                          ControllerDebugCallback,
                          Controller,
                          &Controller->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail10;

    __ControllerAcquireLock(Controller);

    Controller->Connected = TRUE;

    __ControllerReleaseLock(Controller);

done:
    Trace("<====\n");
    return STATUS_SUCCESS;

fail10:
    Error("fail10\n");

    XENBUS_EVTCHN(Close,
                  &Controller->EvtchnInterface,
                  Controller->Channel);
    Controller->Channel = NULL;

    Controller->Events = 0;

fail9:
    Error("fail9\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Controller->Entry);
    Controller->Entry = NULL;

fail8:
    Error("fail8\n");

    RtlZeroMemory(&Controller->Front,
                  sizeof (struct xen_netif_ctrl_front_ring));
    RtlZeroMemory(Controller->Shared, PAGE_SIZE);

    Controller->Shared = NULL;
    __FreePage(Controller->Mdl);
    Controller->Mdl = NULL;

fail7:
    Error("fail7\n");

    XENBUS_GNTTAB(DestroyCache,
                  &Controller->GnttabInterface,
                  Controller->GnttabCache);
    Controller->GnttabCache = NULL;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    XENBUS_GNTTAB(Release, &Controller->GnttabInterface);

fail4:
    Error("fail4\n");

    XENBUS_EVTCHN(Release, &Controller->EvtchnInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Controller->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Controller->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerStoreWrite(
    IN  PXENVIF_CONTROLLER          Controller,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Port;
    NTSTATUS                        status;

    if (!Controller->Connected)
        goto done;

    Frontend = Controller->Frontend;

    status = XENBUS_STORE(Printf,
                          &Controller->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "ctrl-ring-ref",
                          "%u",
                          XENBUS_GNTTAB(GetReference,
                                        &Controller->GnttabInterface,
                                        Controller->Entry));
    if (!NT_SUCCESS(status))
        goto fail1;

    Port = XENBUS_EVTCHN(GetPort,
                         &Controller->EvtchnInterface,
                         Controller->Channel);

    status = XENBUS_STORE(Printf,
                          &Controller->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "event-channel-ctrl",
                          "%u",
                          Port);
    if (!NT_SUCCESS(status))
        goto fail2;

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
ControllerEnable(
    IN  PXENVIF_CONTROLLER      Controller
    )
{
    UNREFERENCED_PARAMETER(Controller);

    Trace("<===>\n");
}

VOID
ControllerDisable(
    IN  PXENVIF_CONTROLLER      Controller
    )
{
    UNREFERENCED_PARAMETER(Controller);

    Trace("<===>\n");
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ControllerDisconnect(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    Trace("====>\n");

    __ControllerAcquireLock(Controller);

    if (!Controller->Connected) {
        __ControllerReleaseLock(Controller);
        goto done;
    }

    Controller->Connected = FALSE;

    __ControllerReleaseLock(Controller);

    XENBUS_DEBUG(Deregister,
                 &Controller->DebugInterface,
                 Controller->DebugCallback);
    Controller->DebugCallback = NULL;

    XENBUS_EVTCHN(Close,
                  &Controller->EvtchnInterface,
                  Controller->Channel);
    Controller->Channel = NULL;

    Controller->Events = 0;

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Controller->Entry);
    Controller->Entry = NULL;

    RtlZeroMemory(&Controller->Front,
                  sizeof (struct xen_netif_ctrl_front_ring));
    RtlZeroMemory(Controller->Shared, PAGE_SIZE);

    Controller->Shared = NULL;
    __FreePage(Controller->Mdl);
    Controller->Mdl = NULL;

    XENBUS_GNTTAB(DestroyCache,
                  &Controller->GnttabInterface,
                  Controller->GnttabCache);
    Controller->GnttabCache = NULL;

done:
    XENBUS_GNTTAB(Release, &Controller->GnttabInterface);

    XENBUS_EVTCHN(Release, &Controller->EvtchnInterface);

    XENBUS_STORE(Release, &Controller->StoreInterface);

    XENBUS_DEBUG(Release, &Controller->DebugInterface);

    Trace("<====\n");
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ControllerTeardown(
    IN  PXENVIF_CONTROLLER  Controller
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    ThreadAlert(Controller->RequestThread);
    ThreadJoin(Controller->RequestThread);
    Controller->RequestThread = NULL;

    Controller->Frontend = NULL;

    Controller->RequestData.RequestId = 0;

    RtlZeroMemory(&Controller->Lock,
                  sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Controller->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&Controller->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Controller->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Controller->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Controller->EvtchnDpc, sizeof (KDPC));

    ASSERT(IsZeroMemory(Controller, sizeof (XENVIF_CONTROLLER)));
    __ControllerFree(Controller);
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerSetHashAlgorithm(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument,
    _In_ ULONG                                  Algorithm
    )
{
    PXENVIF_FRONTEND                            Frontend;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_ALGORITHM,
                                  Algorithm,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_PENDING;

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerGetHashFlags(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument
    )
{
    PXENVIF_FRONTEND                            Frontend;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_GET_HASH_FLAGS,
                                  0,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_PENDING;

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ControllerEndGetHashFlags(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _Out_ PULONG                                Flags
    )
{
    PXENVIF_FRONTEND                            Frontend;
    PXENVIF_CONTROLLER_SET_HASH_KEY             Pending;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;
    Pending = &Controller->RequestData.Pending.SetHashMapping;

    __ControllerAcquireLock(Controller);

    ASSERT3U(Controller->RequestData.State, ==,
             XENVIF_CONTROLLER_REQUEST_RESPONDED);
    ASSERT3U(Controller->RequestData.Request.type, ==,
             XEN_NETIF_CTRL_TYPE_SET_HASH_KEY);

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Pending->Entry);

    __FreePage(Pending->Mdl);

    __ControllerReleaseLock(Controller);
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerSetHashFlags(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument,
    _In_ ULONG                                  Flags
    )
{
    PXENVIF_FRONTEND                            Frontend;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_FLAGS,
                                  Flags,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_PENDING;

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerSetHashKey(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument,
    _In_reads_bytes_(Size) PUCHAR               Key,
    _In_ ULONG                                  Size
    )
{
    PXENVIF_FRONTEND                            Frontend;
    PXENVIF_CONTROLLER_SET_HASH_KEY             Pending;
    PUCHAR                                      Buffer;
    PFN_NUMBER                                  Pfn;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    Pending->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Pending->Mdl == NULL)
        goto fail1;

    ASSERT(Pending->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Buffer = Pending->Mdl->MappedSystemVa;
    ASSERT(Buffer != NULL);

    RtlCopyMemory(Buffer, Key, Size);

    Pfn = MmGetMdlPfnArray(Pending->Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Controller->GnttabInterface,
                           Controller->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Pending->Entry);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_KEY,
                                  XENBUS_GNTTAB(GetReference,
                                                &Controller->GnttabInterface,
                                                Pending->Entry),
                                  Size,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail3;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Pending->Entry);
    Pending->Entry = NULL;

fail2:
    Error("fail2\n");

    __FreePage(Pending->Mdl);
    Pending->Mdl = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ControllerEndSetHashKey(
    _In_ PXENVIF_CONTROLLER                     Controller
    )
{
    PXENVIF_FRONTEND                            Frontend;
    PXENVIF_CONTROLLER_SET_HASH_KEY             Pending;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;
    Pending = &Controller->RequestData.Pending.SetHashMapping;

    __ControllerAcquireLock(Controller);

    ASSERT3U(Controller->RequestData.State, ==,
             XENVIF_CONTROLLER_REQUEST_RESPONDED);
    ASSERT3U(Controller->RequestData.Request.type, ==,
             XEN_NETIF_CTRL_TYPE_SET_HASH_KEY);

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Pending->Entry);

    __FreePage(Pending->Mdl);

    __ControllerReleaseLock(Controller);
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerGetHashMappingSize(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument,
    _Out_ PULONG                                Size
    )
{
    PXENVIF_FRONTEND                            Frontend;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_GET_HASH_MAPPING_SIZE,
                                  0,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_PENDING;

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerSetHashMappingSize(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument,
    _In_ ULONG                                  Size
    )
{
    PXENVIF_FRONTEND                            Frontend;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;

    __ControllerAcquireLock(Controller);

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING_SIZE,
                                  Size,
                                  0,
                                  0);
    if (!NT_SUCCESS(status))
        goto fail1;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_PENDING;

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
ControllerSetHashMapping(
    _In_ PXENVIF_CONTROLLER                     Controller,
    _In_opt_ XENVIF_CONTROLLER_REQUEST_CALLBACK Callback,
    _In_opt_ PVOID                              Argument,
    _In_reads_(Size) PULONG                     Mapping,
    _In_ ULONG                                  Size,
    _In_ ULONG                                  Offset
    )
{
    PXENVIF_FRONTEND                            Frontend;
    PXENVIF_CONTROLLER_SET_HASH_MAPPING         Pending;
    PUCHAR                                      Buffer;
    PFN_NUMBER                                  Pfn;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;
    Pending = &Controller->RequestData.Pending.SetHashMapping;

    __ControllerAcquireLock(Controller);

    status = STATUS_INVALID_PARAMETER;
    if (Size * sizeof (ULONG) > PAGE_SIZE)
        goto fail1;

    Pending->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Pending->Mdl == NULL)
        goto fail2;

    ASSERT(Pending->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
    Buffer = Pending->Mdl->MappedSystemVa;
    ASSERT(Buffer != NULL);

    RtlCopyMemory(Buffer, Mapping, Size * sizeof (ULONG));

    Pfn = MmGetMdlPfnArray(Pending->Mdl)[0];

    status = XENBUS_GNTTAB(PermitForeignAccess,
                           &Controller->GnttabInterface,
                           Controller->GnttabCache,
                           TRUE,
                           FrontendGetBackendDomain(Frontend),
                           Pfn,
                           FALSE,
                           &Pending->Entry);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ControllerPutRequest(Controller,
                                  XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING,
                                  XENBUS_GNTTAB(GetReference,
                                                &Controller->GnttabInterface,
                                                Pending->Entry),
                                  Size,
                                  Offset);
    if (!NT_SUCCESS(status))
        goto fail4;

    Controller->RequestData.Callback = Callback;
    Controller->RequestData.Argument = Argument;

    __ControllerReleaseLock(Controller);

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Pending->Entry);
    Pending->Entry = NULL;

fail3:
    Error("fail3\n");

    __FreePage(Pending->Mdl);
    Pending->Mdl = NULL;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    __ControllerReleaseLock(Controller);

    return status;
}

_IRQL_requires_(DISPATCH_LEVEL)
VOID
ControllerEndSetHashMapping(
    _In_ PXENVIF_CONTROLLER                     Controller
    )
{
    PXENVIF_FRONTEND                            Frontend;
    PXENVIF_CONTROLLER_SET_HASH_MAPPING         Pending;
    NTSTATUS                                    status;

    Frontend = Controller->Frontend;
    Pending = &Controller->RequestData.Pending.SetHashMapping;

    __ControllerAcquireLock(Controller);

    ASSERT3U(Controller->RequestData.State, ==,
             XENVIF_CONTROLLER_REQUEST_RESPONDED);
    ASSERT3U(Controller->RequestData.Request.type, ==,
             XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING);

    (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                         &Controller->GnttabInterface,
                         Controller->GnttabCache,
                         TRUE,
                         Pending->Entry);

    __FreePage(Pending->Mdl);

    __ControllerReleaseLock(Controller);
}
