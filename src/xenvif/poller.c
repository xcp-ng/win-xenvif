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
#include "transmitter.h"
#include "receiver.h"
#include "poller.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define MAXNAMELEN  128

typedef struct _XENVIF_POLLER_INSTANCE XENVIF_POLLER_INSTANCE, *PXENVIF_POLLER_INSTANCE;

typedef enum _XENVIF_POLLER_CHANNEL_TYPE {
    XENVIF_POLLER_CHANNEL_RECEIVER,
    XENVIF_POLLER_CHANNEL_TRANSMITTER,
    XENVIF_POLLER_CHANNEL_COMBINED,
    XENVIF_POLLER_CHANNEL_TYPE_COUNT
} XENVIF_POLLER_CHANNEL_TYPE, *PXENVIF_POLLER_CHANNEL_TYPE;

#define XENVIF_POLLER_CHANNEL_INVALID XENVIF_POLLER_CHANNEL_TYPE_COUNT

typedef struct _XENVIF_POLLER_CHANNEL {
    PXENVIF_POLLER_INSTANCE     Instance;
    XENVIF_POLLER_CHANNEL_TYPE  Type;
    const CHAR                  *Node;
    PXENBUS_EVTCHN_CHANNEL      Channel;
    ULONG                       Events;
} XENVIF_POLLER_CHANNEL, *PXENVIF_POLLER_CHANNEL;

struct _XENVIF_POLLER_INSTANCE {
    PXENVIF_POLLER          Poller;
    ULONG                   Index;
    PCHAR                   Path;
    KSPIN_LOCK              Lock;
    KDPC                    Dpc;
    ULONG                   Dpcs;
    KTIMER                  Timer;
    KDPC                    TimerDpc;
    PXENVIF_POLLER_CHANNEL  Channel[XENVIF_POLLER_CHANNEL_TYPE_COUNT];
    BOOLEAN                 Enabled;
    LONG                    Pending;
};

struct _XENVIF_POLLER {
    PXENVIF_FRONTEND        Frontend;
    PXENVIF_POLLER_INSTANCE *Instance;
    BOOLEAN                 Split;
    XENBUS_STORE_INTERFACE  StoreInterface;
    XENBUS_EVTCHN_INTERFACE EvtchnInterface;
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

static NTSTATUS
PollerChannelInitialize(
    IN  PXENVIF_POLLER_INSTANCE Instance,
    IN  ULONG                   Type,
    OUT PXENVIF_POLLER_CHANNEL  *Channel
    )
{
    NTSTATUS                    status;

    *Channel = __PollerAllocate(sizeof (XENVIF_POLLER_CHANNEL));

    status = STATUS_NO_MEMORY;
    if (*Channel == NULL)
        goto fail1;

    (*Channel)->Instance = Instance;
    (*Channel)->Type = Type;

    switch (Type) {
    case XENVIF_POLLER_CHANNEL_RECEIVER:
        (*Channel)->Node = "event-channel-rx";
        break;

    case XENVIF_POLLER_CHANNEL_TRANSMITTER:
        (*Channel)->Node = "event-channel-tx";
        break;

    case XENVIF_POLLER_CHANNEL_COMBINED:
        (*Channel)->Node = "event-channel";
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
PollerChannelSetPending(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;

    Instance = Channel->Instance;

    switch (Channel->Type)
    {
    case XENVIF_POLLER_CHANNEL_RECEIVER:
        (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                        XENVIF_POLLER_EVENT_RECEIVE);
        break;

    case XENVIF_POLLER_CHANNEL_TRANSMITTER:
        (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                        XENVIF_POLLER_EVENT_TRANSMIT);
        break;

    case XENVIF_POLLER_CHANNEL_COMBINED:
        (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                        XENVIF_POLLER_EVENT_RECEIVE);
        (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                        XENVIF_POLLER_EVENT_TRANSMIT);
        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

static FORCEINLINE BOOLEAN
__BitTest(
    IN  PLONG   Mask,
    IN  LONG    Bit
    )
{
    return (*Mask & (1L << Bit)) ? TRUE : FALSE;
}

static BOOLEAN
PollerChannelTestPending(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;

    Instance = Channel->Instance;

    switch (Channel->Type)
    {
    case XENVIF_POLLER_CHANNEL_RECEIVER:
        if (__BitTest(&Instance->Pending, XENVIF_POLLER_EVENT_RECEIVE))
            return TRUE;

        break;

    case XENVIF_POLLER_CHANNEL_TRANSMITTER:
        if (__BitTest(&Instance->Pending, XENVIF_POLLER_EVENT_TRANSMIT))
            return TRUE;

        break;

    case XENVIF_POLLER_CHANNEL_COMBINED:
        if (__BitTest(&Instance->Pending, XENVIF_POLLER_EVENT_RECEIVE) ||
            __BitTest(&Instance->Pending, XENVIF_POLLER_EVENT_TRANSMIT))
            return TRUE;

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    return FALSE;
}

KSERVICE_ROUTINE    PollerChannelEvtchnCallback;

BOOLEAN
PollerChannelEvtchnCallback(
    IN  PKINTERRUPT         InterruptObject,
    IN  PVOID               Argument
    )
{
    PXENVIF_POLLER_CHANNEL  Channel = Argument;
    PXENVIF_POLLER_INSTANCE Instance;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Channel != NULL);
    Instance = Channel->Instance;

    Channel->Events++;

    PollerChannelSetPending(Channel);

    if (KeInsertQueueDpc(&Instance->Dpc, NULL, NULL))
        Instance->Dpcs++;

    return TRUE;
}

static FORCEINLINE BOOLEAN
__PollerIsSplit(
    IN  PXENVIF_POLLER  Poller
    )
{
    return Poller->Split;
}

static NTSTATUS
PollerChannelConnect(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;
    PXENVIF_POLLER              Poller;
    PXENVIF_FRONTEND            Frontend;
    PROCESSOR_NUMBER            ProcNumber;
    NTSTATUS                    status;

    Instance = Channel->Instance;
    Poller = Instance->Poller;
    Frontend = Poller->Frontend;

    switch (Channel->Type)
    {
    case XENVIF_POLLER_CHANNEL_RECEIVER:
    case XENVIF_POLLER_CHANNEL_TRANSMITTER:
        if (!__PollerIsSplit(Poller))
            goto done;

        break;

    case XENVIF_POLLER_CHANNEL_COMBINED:
        if (__PollerIsSplit(Poller))
            goto done;

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Channel->Channel = XENBUS_EVTCHN(Open,
                                     &Poller->EvtchnInterface,
                                     XENBUS_EVTCHN_TYPE_UNBOUND,
                                     PollerChannelEvtchnCallback,
                                     Channel,
                                     FrontendGetBackendDomain(Frontend),
                                     TRUE);

    status = STATUS_UNSUCCESSFUL;
    if (Channel->Channel == NULL)
        goto fail1;

    status = KeGetProcessorNumberFromIndex(Instance->Index, &ProcNumber);
    ASSERT(NT_SUCCESS(status));

    (VOID) XENBUS_EVTCHN(Bind,
                         &Poller->EvtchnInterface,
                         Channel->Channel,
                         ProcNumber.Group,
                         ProcNumber.Number);

    (VOID) XENBUS_EVTCHN(Unmask,
                         &Poller->EvtchnInterface,
                         Channel->Channel,
                         FALSE,
                         TRUE);

done:
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
PollerChannelStoreWrite(
    IN  PXENVIF_POLLER_CHANNEL      Channel,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_POLLER_INSTANCE         Instance;
    PXENVIF_POLLER                  Poller;
    ULONG                           Port;
    NTSTATUS                        status;

    Instance = Channel->Instance;
    Poller = Instance->Poller;

    if (Channel->Channel == NULL)
        goto done;

    Port = XENBUS_EVTCHN(GetPort,
                         &Poller->EvtchnInterface,
                         Channel->Channel);

    status = XENBUS_STORE(Printf,
                          &Poller->StoreInterface,
                          Transaction,
                          Instance->Path,
                          (PCHAR)Channel->Node,
                          "%u",
                          Port);
    if (!NT_SUCCESS(status))
        goto fail1;

done:
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
PollerChannelUnmask(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;
    PXENVIF_POLLER              Poller;
    BOOLEAN                     Pending;

    Instance = Channel->Instance;
    Poller = Instance->Poller;

    if (Channel->Channel == NULL)
        return;

    if (PollerChannelTestPending(Channel))
        return;

    Pending = XENBUS_EVTCHN(Unmask,
                            &Poller->EvtchnInterface,
                            Channel->Channel,
                            FALSE,
                            FALSE);
    if (Pending)
        PollerChannelSetPending(Channel);
}

static VOID
PollerChannelSend(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;
    PXENVIF_POLLER              Poller;

    Instance = Channel->Instance;
    Poller = Instance->Poller;

    XENBUS_EVTCHN(Send,
                  &Poller->EvtchnInterface,
                  Channel->Channel);
}

static VOID
PollerChannelDebugCallback(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;
    PXENVIF_POLLER              Poller;

    Instance = Channel->Instance;
    Poller = Instance->Poller;

    if (Channel->Channel == NULL)
        return;

    XENBUS_DEBUG(Printf,
                 &Poller->DebugInterface,
                 "[%s]: Events = %lu\n",
                 Channel->Node,
                 Channel->Events);
}

static VOID
PollerChannelDisconnect(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    PXENVIF_POLLER_INSTANCE     Instance;
    PXENVIF_POLLER              Poller;

    Instance = Channel->Instance;
    Poller = Instance->Poller;

    if (Channel->Channel == NULL)
        return;

    Channel->Events = 0;

    XENBUS_EVTCHN(Close,
                  &Poller->EvtchnInterface,
                  Channel->Channel);
    Channel->Channel = NULL;
}

static VOID
PollerChannelTeardown(
    IN  PXENVIF_POLLER_CHANNEL  Channel
    )
{
    Channel->Node = NULL;

    Channel->Type = 0;
    Channel->Instance = NULL;

    ASSERT(IsZeroMemory(Channel, sizeof (XENVIF_POLLER_CHANNEL)));
    __PollerFree(Channel);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
PollerInstanceUnmask(
    IN  PXENVIF_POLLER_INSTANCE     Instance,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    )
{
    PXENVIF_POLLER                  Poller;
    XENVIF_POLLER_CHANNEL_TYPE      Type;
    PXENVIF_POLLER_CHANNEL          Channel;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Poller = Instance->Poller;

    KeAcquireSpinLockAtDpcLevel(&Instance->Lock);

    if (!Instance->Enabled)
        goto done;

    if (!__PollerIsSplit(Poller)) {
        Type = XENVIF_POLLER_CHANNEL_COMBINED;
    } else {
        switch (Event) {
        case XENVIF_POLLER_EVENT_RECEIVE:
            Type = XENVIF_POLLER_CHANNEL_RECEIVER;
            break;

        case XENVIF_POLLER_EVENT_TRANSMIT:
            Type = XENVIF_POLLER_CHANNEL_TRANSMITTER;
            break;

        default:
            Type = XENVIF_POLLER_CHANNEL_INVALID;
            break;
        }
    }

    ASSERT(Type != XENVIF_POLLER_CHANNEL_INVALID);

    Channel = Instance->Channel[Type];

    PollerChannelUnmask(Channel);

done:
    KeReleaseSpinLockFromDpcLevel(&Instance->Lock);
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
PollerInstanceDefer(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    LARGE_INTEGER               Delay;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Instance->Lock);

    if (!Instance->Enabled)
        goto done;

    Delay.QuadPart = TIME_RELATIVE(TIME_US(100));
    KeSetTimer(&Instance->Timer, Delay, &Instance->TimerDpc);

done:
    KeReleaseSpinLockFromDpcLevel(&Instance->Lock);
}

static FORCEINLINE BOOLEAN
PollerInstanceDpcTimeout(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    KDPC_WATCHDOG_INFORMATION   Watchdog;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Instance);

    RtlZeroMemory(&Watchdog, sizeof (Watchdog));

    status = KeQueryDpcWatchdogInformation(&Watchdog);
    ASSERT(NT_SUCCESS(status));

    if (Watchdog.DpcTimeLimit == 0 ||
        Watchdog.DpcWatchdogLimit == 0)
        return FALSE;

    if (Watchdog.DpcTimeCount > (Watchdog.DpcTimeLimit / 2) &&
        Watchdog.DpcWatchdogCount > (Watchdog.DpcWatchdogLimit / 2))
        return FALSE;

    return TRUE;
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
static VOID
PollerInstanceDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENVIF_POLLER_INSTANCE Instance = Context;
    PXENVIF_POLLER          Poller;
    PXENVIF_FRONTEND        Frontend;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Instance != NULL);

    Poller = Instance->Poller;
    Frontend = Poller->Frontend;

    for (;;) {
        BOOLEAN NeedReceiverPoll;
        BOOLEAN NeedTransmitterPoll;

        NeedReceiverPoll =
            (InterlockedBitTestAndReset(&Instance->Pending,
                                        XENVIF_POLLER_EVENT_RECEIVE) != 0) ?
            TRUE :
            FALSE;

        NeedTransmitterPoll =
            (InterlockedBitTestAndReset(&Instance->Pending,
                                        XENVIF_POLLER_EVENT_TRANSMIT) != 0) ?
            TRUE :
            FALSE;

        if (!NeedReceiverPoll && !NeedTransmitterPoll)
            break;

        if (NeedReceiverPoll)
        {
            BOOLEAN Retry = ReceiverPoll(FrontendGetReceiver(Frontend),
                                         Instance->Index);

            if (!Retry) {
                PollerInstanceUnmask(Instance, XENVIF_POLLER_EVENT_RECEIVE);
            } else {
                (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                                XENVIF_POLLER_EVENT_RECEIVE);
            }
        }

        if (NeedTransmitterPoll)
        {
            BOOLEAN Retry = TransmitterPoll(FrontendGetTransmitter(Frontend),
                                            Instance->Index);

            if (!Retry) {
                PollerInstanceUnmask(Instance, XENVIF_POLLER_EVENT_TRANSMIT);
            } else {
                (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                                XENVIF_POLLER_EVENT_TRANSMIT);
            }
        }

        if (PollerInstanceDpcTimeout(Instance)) {
            PollerInstanceDefer(Instance);
            break;
        }
    }
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
static VOID
PollerInstanceTimerDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENVIF_POLLER_INSTANCE Instance = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Instance != NULL);

    KeAcquireSpinLockAtDpcLevel(&Instance->Lock);

    if (!Instance->Enabled)
        goto done;

    if (KeInsertQueueDpc(&Instance->Dpc, NULL, NULL))
        Instance->Dpcs++;

done:
    KeReleaseSpinLockFromDpcLevel(&Instance->Lock);
}

static NTSTATUS
PollerInstanceInitialize(
    IN  PXENVIF_POLLER          Poller,
    IN  LONG                    Index,
    OUT PXENVIF_POLLER_INSTANCE *Instance
    )
{
    PXENVIF_FRONTEND            Frontend;
    LONG                        Type;
    NTSTATUS                    status;

    Frontend = Poller->Frontend;

    *Instance = __PollerAllocate(sizeof (XENVIF_POLLER_INSTANCE));

    status = STATUS_NO_MEMORY;
    if (*Instance == NULL)
        goto fail1;

    (*Instance)->Poller = Poller;
    (*Instance)->Index = Index;

    for (Type = 0; Type < XENVIF_POLLER_CHANNEL_TYPE_COUNT; Type++)
    {
        PXENVIF_POLLER_CHANNEL Channel;

        status = PollerChannelInitialize(*Instance, Type, &Channel);
        if (!NT_SUCCESS(status))
            goto fail2;

        (*Instance)->Channel[Type] = Channel;
    }

    (*Instance)->Path = FrontendFormatPath(Frontend, Index);
    if ((*Instance)->Path == NULL)
        goto fail3;

    KeInitializeSpinLock(&(*Instance)->Lock);

    KeInitializeDpc(&(*Instance)->Dpc, PollerInstanceDpc, *Instance);
    KeInitializeTimer(&(*Instance)->Timer);
    KeInitializeDpc(&(*Instance)->TimerDpc, PollerInstanceTimerDpc, *Instance);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    Type = XENVIF_POLLER_CHANNEL_TYPE_COUNT;

fail2:
    Error("fail2\n");

    while (--Type >= 0)
    {
        PXENVIF_POLLER_CHANNEL Channel = (*Instance)->Channel[Type];

        (*Instance)->Channel[Type] = NULL;
        PollerChannelTeardown(Channel);
    }

    (*Instance)->Index = 0;
    (*Instance)->Poller = NULL;

    ASSERT(IsZeroMemory(*Instance, sizeof (XENVIF_POLLER_INSTANCE)));
    __PollerFree(*Instance);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
PollerInstanceConnect(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    PROCESSOR_NUMBER            ProcNumber;
    LONG                        Type;
    NTSTATUS                    status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    status = KeGetProcessorNumberFromIndex(Instance->Index, &ProcNumber);
    ASSERT(NT_SUCCESS(status));

    KeSetTargetProcessorDpcEx(&Instance->Dpc, &ProcNumber);

    for (Type = 0; Type < XENVIF_POLLER_CHANNEL_TYPE_COUNT; Type++)
    {
        PXENVIF_POLLER_CHANNEL Channel = Instance->Channel[Type];

        status = PollerChannelConnect(Channel);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    while (--Type >= 0)
    {
        PXENVIF_POLLER_CHANNEL Channel = Instance->Channel[Type];

        PollerChannelDisconnect(Channel);
    }

    return status;
}

static NTSTATUS
PollerInstanceStoreWrite(
    IN  PXENVIF_POLLER_INSTANCE     Instance,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    ULONG                           Type;
    NTSTATUS                        status;

    for (Type = 0; Type < XENVIF_POLLER_CHANNEL_TYPE_COUNT; Type++)
    {
        PXENVIF_POLLER_CHANNEL Channel = Instance->Channel[Type];

        status = PollerChannelStoreWrite(Channel, Transaction);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
PollerInstanceEnable(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                    XENVIF_POLLER_EVENT_RECEIVE);
    (VOID) InterlockedBitTestAndSet(&Instance->Pending,
                                    XENVIF_POLLER_EVENT_TRANSMIT);

    KeAcquireSpinLockAtDpcLevel(&Instance->Lock);
    Instance->Enabled = TRUE;
    KeReleaseSpinLockFromDpcLevel(&Instance->Lock);

    (VOID) KeInsertQueueDpc(&Instance->Dpc, NULL, NULL);

    return STATUS_SUCCESS;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
PollerInstanceSend(
    IN  PXENVIF_POLLER_INSTANCE     Instance,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    )
{
    PXENVIF_POLLER                  Poller;
    XENVIF_POLLER_CHANNEL_TYPE      Type;
    PXENVIF_POLLER_CHANNEL          Channel;
    NTSTATUS                        status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Poller = Instance->Poller;

    KeAcquireSpinLockAtDpcLevel(&Instance->Lock);

    Type = XENVIF_POLLER_CHANNEL_INVALID;

    if (Instance->Enabled) {
        if (!__PollerIsSplit(Poller)) {
            Type = XENVIF_POLLER_CHANNEL_COMBINED;
        } else {
            switch (Event) {
            case XENVIF_POLLER_EVENT_RECEIVE:
                Type = XENVIF_POLLER_CHANNEL_RECEIVER;
                break;

            case XENVIF_POLLER_EVENT_TRANSMIT:
                Type = XENVIF_POLLER_CHANNEL_TRANSMITTER;
                break;

            default:
                ASSERT(FALSE);
                break;
            }
        }
    }

    KeReleaseSpinLockFromDpcLevel(&Instance->Lock);

    status = STATUS_UNSUCCESSFUL;
    if (Type == XENVIF_POLLER_CHANNEL_INVALID)
        goto fail1;

    Channel = Instance->Channel[Type];

    PollerChannelSend(Channel);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
PollerInstanceTrigger(
    IN  PXENVIF_POLLER_INSTANCE     Instance,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    )
{
    NTSTATUS                        status;

    status = STATUS_INVALID_PARAMETER;
    if (Event >= XENVIF_POLLER_EVENT_TYPE_COUNT)
        goto fail1;

    (VOID) InterlockedBitTestAndSet(&Instance->Pending, Event);

    if (KeInsertQueueDpc(&Instance->Dpc, NULL, NULL))
        Instance->Dpcs++;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
PollerInstanceDebugCallback(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    PXENVIF_POLLER              Poller;
    ULONG                       Type;

    Poller = Instance->Poller;

    XENBUS_DEBUG(Printf,
                 &Poller->DebugInterface,
                 "[%d]: Dpcs = %lu\n",
                 Instance->Index,
                 Instance->Dpcs);

    for (Type = 0; Type < XENVIF_POLLER_CHANNEL_TYPE_COUNT; Type++)
    {
        PXENVIF_POLLER_CHANNEL Channel = Instance->Channel[Type];

        PollerChannelDebugCallback(Channel);
    }
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
PollerInstanceDisable(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Instance->Lock);
    Instance->Enabled = FALSE;
    KeReleaseSpinLockFromDpcLevel(&Instance->Lock);

    //
    // No new timers can be scheduled once Enabled goes to FALSE.
    // Cancel any existing ones.
    //
    (VOID) KeCancelTimer(&Instance->Timer);
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
PollerInstanceDisconnect(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    LONG                        Type;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Instance->Dpcs = 0;
    Instance->Pending = 0;

    Type = XENVIF_POLLER_CHANNEL_TYPE_COUNT;

    while (--Type >= 0)
    {
        PXENVIF_POLLER_CHANNEL Channel = Instance->Channel[Type];

        PollerChannelDisconnect(Channel);
    }
}

static VOID
PollerInstanceTeardown(
    IN  PXENVIF_POLLER_INSTANCE Instance
    )
{
    PXENVIF_POLLER              Poller;
    PXENVIF_FRONTEND            Frontend;
    LONG                        Type;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    Poller = Instance->Poller;
    Frontend = Poller->Frontend;

    RtlZeroMemory(&Instance->TimerDpc, sizeof (KDPC));
    RtlZeroMemory(&Instance->Timer, sizeof (KTIMER));
    RtlZeroMemory(&Instance->Dpc, sizeof (KDPC));

    RtlZeroMemory(&Instance->Lock, sizeof (KSPIN_LOCK));

    FrontendFreePath(Frontend, Instance->Path);
    Instance->Path = NULL;

    Type = XENVIF_POLLER_CHANNEL_TYPE_COUNT;

    while (--Type >= 0)
    {
        PXENVIF_POLLER_CHANNEL Channel = Instance->Channel[Type];

        Instance->Channel[Type] = NULL;
        PollerChannelTeardown(Channel);
    }

    Instance->Index = 0;
    Instance->Poller = NULL;

    ASSERT(IsZeroMemory(Instance, sizeof (XENVIF_POLLER_INSTANCE)));
    __PollerFree(Instance);
}

static VOID
PollerDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_POLLER      Poller = Argument;
    PXENVIF_FRONTEND    Frontend;
    ULONG               NumQueues;
    ULONG               Index;

    UNREFERENCED_PARAMETER(Crashing);

    Frontend = Poller->Frontend;

    NumQueues = FrontendGetNumQueues(Frontend);

    for (Index = 0; Index < NumQueues; Index++) {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        PollerInstanceDebugCallback(Instance);
    }
}

static VOID
PollerSetSplit(
    IN  PXENVIF_POLLER  Poller
    )
{
    PXENVIF_FRONTEND    Frontend;
    PCHAR               Buffer;
    NTSTATUS            status;

    Frontend = Poller->Frontend;

    status = XENBUS_STORE(Read,
                          &Poller->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-split-event-channels",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Poller->Split = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Poller->StoreInterface,
                     Buffer);
    } else {
        Poller->Split = FALSE;
    }

    Info("%s: %s\n", FrontendGetPath(Frontend),
         (Poller->Split) ? "TRUE" : "FALSE");
}

NTSTATUS
PollerInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_POLLER      *Poller
    )
{
    LONG                    MaxQueues;
    LONG                    Index;
    NTSTATUS                status;

    *Poller = __PollerAllocate(sizeof (XENVIF_POLLER));

    status = STATUS_NO_MEMORY;
    if (*Poller == NULL)
        goto fail1;

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Poller)->EvtchnInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Poller)->StoreInterface);

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Poller)->DebugInterface);

    (*Poller)->Frontend = Frontend;

    MaxQueues = FrontendGetMaxQueues(Frontend);
    (*Poller)->Instance = __PollerAllocate(sizeof (PXENVIF_POLLER_INSTANCE) *
                                           MaxQueues);

    status = STATUS_NO_MEMORY;
    if ((*Poller)->Instance == NULL)
        goto fail2;

    for (Index = 0; Index < MaxQueues; Index++) {
        PXENVIF_POLLER_INSTANCE Instance;

        status = PollerInstanceInitialize(*Poller, Index, &Instance);
        if (!NT_SUCCESS(status))
            goto fail3;

        (*Poller)->Instance[Index] = Instance;
    }

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    while (--Index >= 0)
    {
        PXENVIF_POLLER_INSTANCE Instance = (*Poller)->Instance[Index];

        (*Poller)->Instance[Index] = NULL;
        PollerInstanceTeardown(Instance);
    }

    ASSERT(IsZeroMemory((*Poller)->Instance,
                        sizeof (PXENVIF_POLLER_INSTANCE) * MaxQueues));
    __PollerFree((*Poller)->Instance);
    (*Poller)->Instance = NULL;

fail2:
    Error("fail2\n");

    (*Poller)->Frontend = NULL;

    RtlZeroMemory(&(*Poller)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&(*Poller)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Poller)->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
PollerConnect(
    IN  PXENVIF_POLLER  Poller
    )
{
    PXENVIF_FRONTEND    Frontend;
    LONG                NumQueues;
    LONG                Index;
    NTSTATUS            status;

    Trace("====>\n");

    Frontend = Poller->Frontend;

    status = XENBUS_EVTCHN(Acquire, &Poller->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Poller->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Acquire, &Poller->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    PollerSetSplit(Poller);

    NumQueues = FrontendGetNumQueues(Frontend);

    for (Index = 0; Index < NumQueues; Index++) {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        status = PollerInstanceConnect(Instance);
        if (!NT_SUCCESS(status))
            goto fail4;
    }

    status = XENBUS_DEBUG(Register,
                          &Poller->DebugInterface,
                          __MODULE__ "|POLLER",
                          PollerDebugCallback,
                          Poller,
                          &Poller->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    Index = NumQueues;

fail4:
    Error("fail4\n");

    while (--Index >= 0)
    {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        PollerInstanceDisconnect(Instance);
    }

    Poller->Split = FALSE;

    XENBUS_DEBUG(Release, &Poller->DebugInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Poller->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_EVTCHN(Release, &Poller->EvtchnInterface);

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
    PXENVIF_FRONTEND                Frontend;
    LONG                            NumQueues;
    LONG                            Index;
    NTSTATUS                        status;

    Trace("====>\n");

    Frontend = Poller->Frontend;

    NumQueues = FrontendGetNumQueues(Frontend);

    for (Index = 0; Index < NumQueues; Index++) {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        status = PollerInstanceStoreWrite(Instance, Transaction);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
PollerEnable(
    IN  PXENVIF_POLLER  Poller
    )
{
    PXENVIF_FRONTEND    Frontend;
    LONG                NumQueues;
    LONG                Index;
    NTSTATUS            status;

    Trace("====>\n");

    Frontend = Poller->Frontend;

    NumQueues = FrontendGetNumQueues(Frontend);

    for (Index = 0; Index < NumQueues; Index++) {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        status = PollerInstanceEnable(Instance);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    while (--Index >= 0)
    {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        PollerInstanceDisable(Instance);
    }

    return status;
}

NTSTATUS
PollerSend(
    IN  PXENVIF_POLLER              Poller,
    IN  ULONG                       Index,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    )
{
    PXENVIF_FRONTEND                Frontend;
    ULONG                           NumQueues;
    PXENVIF_POLLER_INSTANCE         Instance;
    NTSTATUS                        status;

    Frontend = Poller->Frontend;

    NumQueues = FrontendGetNumQueues(Frontend);

    status = STATUS_INVALID_PARAMETER;
    if (Index >= NumQueues)
        goto fail1;

    Instance = Poller->Instance[Index];

    status = PollerInstanceSend(Instance, Event);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
PollerTrigger(
    IN  PXENVIF_POLLER              Poller,
    IN  ULONG                       Index,
    IN  XENVIF_POLLER_EVENT_TYPE    Event
    )
{
    PXENVIF_FRONTEND                Frontend;
    ULONG                           NumQueues;
    PXENVIF_POLLER_INSTANCE         Instance;
    NTSTATUS                        status;

    Frontend = Poller->Frontend;

    NumQueues = FrontendGetNumQueues(Frontend);

    status = STATUS_INVALID_PARAMETER;
    if (Index >= NumQueues)
        goto fail1;

    Instance = Poller->Instance[Index];

    status = PollerInstanceTrigger(Instance, Event);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
PollerDisable(
    IN  PXENVIF_POLLER  Poller
    )
{
    PXENVIF_FRONTEND    Frontend;
    LONG                NumQueues;
    LONG                Index;

    Trace("====>\n");

    Frontend = Poller->Frontend;

    NumQueues = FrontendGetNumQueues(Frontend);
    Index = NumQueues;

    while (--Index >= 0)
    {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        PollerInstanceDisable(Instance);
    }

    Trace("<====\n");
}

VOID
PollerDisconnect(
    IN  PXENVIF_POLLER  Poller
    )
{
    PXENVIF_FRONTEND    Frontend;
    LONG                NumQueues;
    LONG                Index;

    Trace("====>\n");

    Frontend = Poller->Frontend;

    XENBUS_DEBUG(Deregister,
                 &Poller->DebugInterface,
                 Poller->DebugCallback);
    Poller->DebugCallback = NULL;

    NumQueues = FrontendGetNumQueues(Frontend);
    Index = NumQueues;

    while (--Index >= 0)
    {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        PollerInstanceDisconnect(Instance);
    }

    Poller->Split = FALSE;

    XENBUS_DEBUG(Release, &Poller->DebugInterface);

    XENBUS_STORE(Release, &Poller->StoreInterface);

    XENBUS_EVTCHN(Release, &Poller->EvtchnInterface);

    Trace("<====\n");
}

VOID
PollerTeardown(
    IN  PXENVIF_POLLER  Poller
    )
{
    PXENVIF_FRONTEND    Frontend;
    LONG                MaxQueues;
    LONG                Index;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Frontend = Poller->Frontend;

    MaxQueues = FrontendGetMaxQueues(Frontend);
    Index = MaxQueues;

    while (--Index >= 0)
    {
        PXENVIF_POLLER_INSTANCE Instance = Poller->Instance[Index];

        Poller->Instance[Index] = NULL;
        PollerInstanceTeardown(Instance);
    }

    ASSERT(IsZeroMemory(Poller->Instance,
                        sizeof (PXENVIF_POLLER_INSTANCE) * MaxQueues));
    __PollerFree(Poller->Instance);
    Poller->Instance = NULL;

    Poller->Frontend = NULL;

    RtlZeroMemory(&Poller->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Poller->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Poller->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    ASSERT(IsZeroMemory(Poller, sizeof (XENVIF_POLLER)));
    __PollerFree(Poller);
}
