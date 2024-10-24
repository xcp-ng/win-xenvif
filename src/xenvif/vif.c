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

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xen.h>

#include "pdo.h"
#include "parse.h"
#include "vif.h"
#include "mrsw.h"
#include "thread.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

struct _XENVIF_VIF_CONTEXT {
    PXENVIF_PDO                 Pdo;
    XENVIF_MRSW_LOCK            Lock;
    LONG                        References;
    PXENVIF_FRONTEND            Frontend;
    BOOLEAN                     Enabled;
    ULONG                       Version;
    XENVIF_VIF_CALLBACK         Callback;
    PVOID                       Argument;
    XENVIF_VIF_CALLBACK_V8      CallbackVersion8;
    PVOID                       ArgumentVersion8;
    XENVIF_VIF_CALLBACK_V9      CallbackVersion9;
    PVOID                       ArgumentVersion9;
    LONG                        Queued;
    PXENVIF_THREAD              MacThread;
    KEVENT                      MacEvent;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
};

#define XENVIF_VIF_TAG  'FIV'

static FORCEINLINE PVOID
__VifAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, XENVIF_VIF_TAG);
}

static FORCEINLINE VOID
__VifFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_VIF_TAG);
}

static NTSTATUS
VifMac(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           _Context
    )
{
    PXENVIF_VIF_CONTEXT Context = _Context;
    PKEVENT             Event;

    Trace("====>\n");

    Event = ThreadGetEvent(Self);

    for (;;) {
        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;

        if (Context->Enabled)
            Context->Callback(Context->Argument, XENVIF_MAC_STATE_CHANGE, NULL);

        KeSetEvent(&Context->MacEvent, IO_NO_INCREMENT, FALSE);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
VifSuspendCallbackLate(
    IN  PVOID           Argument
    )
{
    PXENVIF_VIF_CONTEXT Context = Argument;
    NTSTATUS            status;

    if (!Context->Enabled)
        return;

    status = FrontendSetState(Context->Frontend, FRONTEND_ENABLED);
    ASSERT(NT_SUCCESS(status));

    // We do this three times to make sure switches take note
    FrontendAdvertiseIpAddresses(Context->Frontend);
    FrontendAdvertiseIpAddresses(Context->Frontend);
    FrontendAdvertiseIpAddresses(Context->Frontend);
}

static NTSTATUS
VifEnable(
    IN  PINTERFACE          Interface,
    IN  XENVIF_VIF_CALLBACK Callback,
    IN  PVOID               Argument
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;
    BOOLEAN                 Exclusive;
    NTSTATUS                status;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);
    Exclusive = TRUE;

    if (Context->Enabled)
        goto done;

    Context->Callback = Callback;
    Context->Argument = Argument;

    Context->Enabled = TRUE;

    KeMemoryBarrier();

    status = XENBUS_SUSPEND(Acquire, &Context->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = FrontendSetState(Context->Frontend, FRONTEND_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_SUSPEND(Register,
                            &Context->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            VifSuspendCallbackLate,
                            Context,
                            &Context->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail3;

done:
    ASSERT(Exclusive);
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    (VOID) FrontendSetState(Context->Frontend, FRONTEND_CONNECTED);

    ReleaseMrswLockExclusive(&Context->Lock, Irql, TRUE);
    Exclusive = FALSE;

    ReceiverWaitForPackets(FrontendGetReceiver(Context->Frontend));
    TransmitterAbortPackets(FrontendGetTransmitter(Context->Frontend));

    Trace("waiting for mac thread..\n");

    KeClearEvent(&Context->MacEvent);
    ThreadWake(Context->MacThread);

    (VOID) KeWaitForSingleObject(&Context->MacEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("done\n");

fail2:
    Error("fail2\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Context->Enabled = FALSE;

    KeMemoryBarrier();

    Context->Argument = NULL;
    Context->Callback = NULL;

    if (Exclusive)
        ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
    else
        ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifCallbackVersion8(
    IN  PVOID                                       _Argument OPTIONAL,
    IN  XENVIF_VIF_CALLBACK_TYPE                    Type,
    IN  union _XENVIF_VIF_CALLBACK_PARAMETERS_V9   *Parameters
    )
{
    PXENVIF_VIF_CONTEXT                             Context = _Argument;
    XENVIF_VIF_CALLBACK_V8                          Callback = Context->CallbackVersion8;
    PVOID                                           Argument = Context->ArgumentVersion8;

    switch (Type) {
    case XENVIF_TRANSMITTER_RETURN_PACKET: {
        PVOID                                       Cookie = Parameters->TransmitterReturnPacket.Cookie;
        PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO  Completion = Parameters->TransmitterReturnPacket.Completion;

        Callback(Argument,
                 XENVIF_TRANSMITTER_RETURN_PACKET,
                 Cookie,
                 Completion);
        break;
    }
    case XENVIF_RECEIVER_QUEUE_PACKET: {
        ULONG                           Index = Parameters->ReceiverQueuePacket.Index;
        PMDL                            Mdl = Parameters->ReceiverQueuePacket.Mdl;
        ULONG                           Offset = Parameters->ReceiverQueuePacket.Offset;
        ULONG                           Length=  Parameters->ReceiverQueuePacket.Length;
        XENVIF_PACKET_CHECKSUM_FLAGS    Flags = Parameters->ReceiverQueuePacket.Flags;
        USHORT                          MaximumSegmentSize = Parameters->ReceiverQueuePacket.MaximumSegmentSize;
        USHORT                          TagControlInformation = Parameters->ReceiverQueuePacket.TagControlInformation;
        PXENVIF_PACKET_INFO             Info = Parameters->ReceiverQueuePacket.Info;
        PXENVIF_PACKET_HASH             Hash = Parameters->ReceiverQueuePacket.Hash;
        BOOLEAN                         More = Parameters->ReceiverQueuePacket.More;
        PVOID                           Cookie = Parameters->ReceiverQueuePacket.Cookie;

        Callback(Argument,
                 XENVIF_RECEIVER_QUEUE_PACKET,
                 Index,
                 Mdl,
                 Offset,
                 Length,
                 Flags,
                 MaximumSegmentSize,
                 TagControlInformation,
                 Info,
                 Hash,
                 More,
                 Cookie);
        break;
    }
    case XENVIF_MAC_STATE_CHANGE:
        Callback(Argument, XENVIF_MAC_STATE_CHANGE);
        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

static VOID
VifCallbackVersion9(
    IN  PVOID                                       _Argument OPTIONAL,
    IN  XENVIF_VIF_CALLBACK_TYPE                    Type,
    IN  PXENVIF_VIF_CALLBACK_PARAMETERS             Parameters
    )
{
#define XENVIF_RECEIVER_QUEUE_MAX 1024 // Chosen to match IN_NDIS_MAX in XENNET

    PXENVIF_VIF_CONTEXT                             Context = _Argument;
    XENVIF_VIF_CALLBACK_V9                          Callback = Context->CallbackVersion9;
    PVOID                                           Argument = Context->ArgumentVersion9;
    union _XENVIF_VIF_CALLBACK_PARAMETERS_V9        ParametersVersion9;

    switch (Type) {
    case XENVIF_TRANSMITTER_RETURN_PACKET:
        ParametersVersion9.TransmitterReturnPacket.Cookie = Parameters->TransmitterReturnPacket.Cookie;
        ParametersVersion9.TransmitterReturnPacket.Completion = Parameters->TransmitterReturnPacket.Completion;
        break;

    case XENVIF_RECEIVER_QUEUE_PACKET:
        ParametersVersion9.ReceiverQueuePacket.Index = Parameters->ReceiverQueuePacket.Index;
        ParametersVersion9.ReceiverQueuePacket.Mdl = Parameters->ReceiverQueuePacket.Mdl;
        ParametersVersion9.ReceiverQueuePacket.Offset = Parameters->ReceiverQueuePacket.Offset;
        ParametersVersion9.ReceiverQueuePacket.Length = Parameters->ReceiverQueuePacket.Length;
        ParametersVersion9.ReceiverQueuePacket.Flags = Parameters->ReceiverQueuePacket.Flags;
        ParametersVersion9.ReceiverQueuePacket.MaximumSegmentSize = Parameters->ReceiverQueuePacket.MaximumSegmentSize;
        ParametersVersion9.ReceiverQueuePacket.TagControlInformation = Parameters->ReceiverQueuePacket.TagControlInformation;
        ParametersVersion9.ReceiverQueuePacket.Info = Parameters->ReceiverQueuePacket.Info;
        ParametersVersion9.ReceiverQueuePacket.Hash = Parameters->ReceiverQueuePacket.Hash;
        ParametersVersion9.ReceiverQueuePacket.More = Parameters->ReceiverQueuePacket.More;
        ParametersVersion9.ReceiverQueuePacket.Cookie = Parameters->ReceiverQueuePacket.Cookie;
        break;

    case XENVIF_MAC_STATE_CHANGE:
        // No parameters to translate
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Callback(Argument, Type, &ParametersVersion9);

    switch (Type) {
    case XENVIF_TRANSMITTER_RETURN_PACKET:
        break;

    case XENVIF_RECEIVER_QUEUE_PACKET: {
        LONG Queued;

        Queued = (Parameters->ReceiverQueuePacket.More) ?
            InterlockedIncrement(&Context->Queued) :
            InterlockedExchange(&Context->Queued, 0);

        //
        // Once the limit is hit XENNET will have started indicating 'low resources' to NDIS so we
        // should pause any further attempts to queue received packets.
        //
        if (Queued > XENVIF_RECEIVER_QUEUE_MAX) {
            Parameters->ReceiverQueuePacket.Pause = TRUE;
            (VOID) InterlockedExchange(&Context->Queued, 0);
        } else {
            Parameters->ReceiverQueuePacket.Pause = FALSE;
        }
        break;
    }
    case XENVIF_MAC_STATE_CHANGE:
        // No parameters to translate
        break;

    default:
        ASSERT(FALSE);
        break;
    }

#undef XENVIF_RECEIVER_QUEUE_MAX
}

static NTSTATUS
VifEnableVersion9(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_CALLBACK_V9      Callback,
    IN  PVOID                       Argument
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    KIRQL                           Irql;
    NTSTATUS                        status;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    Context->CallbackVersion9 = Callback;
    Context->ArgumentVersion9 = Argument;

    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    status = VifEnable(Interface, VifCallbackVersion9, Context);

    Trace("<====\n");

    return status;
}

static NTSTATUS
VifEnableVersion8(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_CALLBACK_V8      Callback,
    IN  PVOID                       Argument
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    KIRQL                           Irql;
    NTSTATUS                        status;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    Context->CallbackVersion8 = Callback;
    Context->ArgumentVersion8 = Argument;

    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    status = VifEnableVersion9(Interface, VifCallbackVersion8, Context);

    Trace("<====\n");

    return status;
}

static VOID
VifDisable(
    IN  PINTERFACE      Interface
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    KIRQL               Irql;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (!Context->Enabled) {
        ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
        goto done;
    }

    Context->Enabled = FALSE;

    KeMemoryBarrier();

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

    (VOID) FrontendSetState(Context->Frontend, FRONTEND_CONNECTED);

    ReleaseMrswLockExclusive(&Context->Lock, Irql, TRUE);

    ReceiverWaitForPackets(FrontendGetReceiver(Context->Frontend));
    TransmitterAbortPackets(FrontendGetTransmitter(Context->Frontend));

    Trace("waiting for mac thread..\n");

    KeClearEvent(&Context->MacEvent);
    ThreadWake(Context->MacThread);

    (VOID) KeWaitForSingleObject(&Context->MacEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("done\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

    Context->Argument = NULL;
    Context->Callback = NULL;

    Context->ArgumentVersion8 = NULL;
    Context->CallbackVersion8 = NULL;

    Context->ArgumentVersion9 = NULL;
    Context->CallbackVersion9 = NULL;

    ReleaseMrswLockShared(&Context->Lock);

done:
    Trace("<====\n");
}

static NTSTATUS
VifQueryStatistic(
    IN  PINTERFACE              Interface,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    NTSTATUS                    status;

    status = STATUS_INVALID_PARAMETER;
    if (Index >= XENVIF_VIF_STATISTIC_COUNT)
        goto done;
        
    AcquireMrswLockShared(&Context->Lock);

    FrontendQueryStatistic(Context->Frontend, Index, Value);

    ReleaseMrswLockShared(&Context->Lock);
    status = STATUS_SUCCESS;

done:
    return status;
}

static VOID
VifQueryRingCount(
    IN  PINTERFACE      Interface,
    OUT PULONG          Count
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    *Count = FrontendGetNumQueues(Context->Frontend);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifUpdateHashMapping(
    IN  PINTERFACE          Interface,
    IN  PPROCESSOR_NUMBER   Mapping,
    IN  ULONG               Order
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = ReceiverUpdateHashMapping(FrontendGetReceiver(Context->Frontend),
                                       Mapping,
                                       Order);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifReceiverReturnPacket(
    IN  PINTERFACE      Interface,
    IN  PVOID           Cookie
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverReturnPacket(FrontendGetReceiver(Context->Frontend),
                         Cookie);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifTransmitterQueuePacket(
    IN  PINTERFACE                  Interface,
    IN  PMDL                        Mdl,
    IN  ULONG                       Offset,
    IN  ULONG                       Length,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions,
    IN  USHORT                      MaximumSegmentSize,
    IN  USHORT                      TagControlInformation,
    IN  PXENVIF_PACKET_HASH         Hash,
    IN  BOOLEAN                     More,
    IN  PVOID                       Cookie
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = STATUS_UNSUCCESSFUL;
    if (!Context->Enabled)
        goto done;

    status = TransmitterQueuePacket(FrontendGetTransmitter(Context->Frontend),
                                    Mdl,
                                    Offset,
                                    Length,
                                    OffloadOptions,
                                    MaximumSegmentSize,
                                    TagControlInformation,
                                    Hash,
                                    More,
                                    Cookie);

done:
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifTransmitterQueryOffloadOptions(
    IN  PINTERFACE                  Interface,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryOffloadOptions(FrontendGetTransmitter(Context->Frontend),
                                   Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifTransmitterQueryLargePacketSize(
    IN  PINTERFACE      Interface,
    IN  UCHAR           Version,
    OUT PULONG          Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryLargePacketSize(FrontendGetTransmitter(Context->Frontend),
                                    Version,
                                    Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifReceiverSetOffloadOptions(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverSetOffloadOptions(FrontendGetReceiver(Context->Frontend),
                              Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifReceiverSetBackfillSize(
    IN  PINTERFACE      Interface,
    IN  ULONG           Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverSetBackfillSize(FrontendGetReceiver(Context->Frontend),
                            Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifReceiverSetHashAlgorithm(
    IN  PINTERFACE                      Interface,
    IN  XENVIF_PACKET_HASH_ALGORITHM    Algorithm
    )
{
    PXENVIF_VIF_CONTEXT                 Context = Interface->Context;
    NTSTATUS                            status;

    AcquireMrswLockShared(&Context->Lock);

    status = ReceiverSetHashAlgorithm(FrontendGetReceiver(Context->Frontend),
                                      Algorithm);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifReceiverQueryHashCapabilities(
    IN  PINTERFACE      Interface,
    ...
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    va_list             Arguments;
    PULONG              Types;
    NTSTATUS            status;

    AcquireMrswLockShared(&Context->Lock);

    va_start(Arguments, Interface);

    Types = va_arg(Arguments, PULONG);

    status = ReceiverQueryHashCapabilities(FrontendGetReceiver(Context->Frontend),
                                           Types);

    va_end(Arguments);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifReceiverUpdateHashParameters(
    IN  PINTERFACE      Interface,
    ...
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    va_list             Arguments;
    ULONG               Types;
    PUCHAR              Key;
    NTSTATUS            status;

    AcquireMrswLockShared(&Context->Lock);

    va_start(Arguments, Interface);

    Types = va_arg(Arguments, ULONG);
    Key = va_arg(Arguments, PUCHAR);

    status = ReceiverUpdateHashParameters(FrontendGetReceiver(Context->Frontend),
                                          Types,
                                          Key);

    va_end(Arguments);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifMacQueryState(
    IN  PINTERFACE                  Interface,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryState(FrontendGetMac(Context->Frontend),
                  MediaConnectState,
                  LinkSpeed,
                  MediaDuplexState);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryMaximumFrameSize(
    IN  PINTERFACE      Interface,
    OUT PULONG          Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryMaximumFrameSize(FrontendGetMac(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryPermanentAddress(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryPermanentAddress(FrontendGetMac(Context->Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryCurrentAddress(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryCurrentAddress(FrontendGetMac(Context->Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifMacQueryMulticastAddresses(
    IN      PINTERFACE          Interface,
    OUT     PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    NTSTATUS                    status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacQueryMulticastAddresses(FrontendGetMac(Context->Frontend),
                                        Address,
                                        Count);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacSetMulticastAddresses(
    IN  PINTERFACE          Interface,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    ULONG                   Index;
    NTSTATUS                status;

    status = STATUS_INVALID_PARAMETER;
    for (Index = 0; Index < Count; Index++) {
        if (!(Address[Index].Byte[0] & 0x01))
            goto done;
    }

    AcquireMrswLockShared(&Context->Lock);

    status = FrontendSetMulticastAddresses(Context->Frontend,
                                           Address,
                                           Count);

    ReleaseMrswLockShared(&Context->Lock);

done:
    return status;
}

static NTSTATUS
VifMacQueryFilterLevel(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacQueryFilterLevel(FrontendGetMac(Context->Frontend),
                                 Type,
                                 Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacSetFilterLevel(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    IN  XENVIF_MAC_FILTER_LEVEL     Level
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = FrontendSetFilterLevel(Context->Frontend, Type, Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifReceiverQueryRingSize(
    IN  PINTERFACE          Interface,
    OUT PULONG              Size
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverQueryRingSize(FrontendGetReceiver(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifTransmitterQueryRingSize(
    IN  PINTERFACE          Interface,
    OUT PULONG              Size
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryRingSize(FrontendGetTransmitter(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifAcquire(
    PINTERFACE              Interface
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    Context->Frontend = PdoGetFrontend(Context->Pdo);
    Context->Version = Interface->Version;

    Trace("<====\n");

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    return STATUS_SUCCESS;
}

VOID
VifRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    ASSERT(!Context->Enabled);

    Context->Version = 0;
    Context->Frontend = NULL;

    Trace("<====\n");

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
}

static struct _XENVIF_VIF_INTERFACE_V8 VifInterfaceVersion8 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V8), 8, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnableVersion8,
    VifDisable,
    VifQueryStatistic,
    VifQueryRingCount,
    VifUpdateHashMapping,
    VifReceiverReturnPacket,
    VifReceiverSetOffloadOptions,
    VifReceiverSetBackfillSize,
    VifReceiverQueryRingSize,
    VifReceiverSetHashAlgorithm,
    VifReceiverQueryHashCapabilities,
    VifReceiverUpdateHashParameters,
    VifTransmitterQueuePacket,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

static struct _XENVIF_VIF_INTERFACE_V9 VifInterfaceVersion9 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V9), 9, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnableVersion9,
    VifDisable,
    VifQueryStatistic,
    VifQueryRingCount,
    VifUpdateHashMapping,
    VifReceiverReturnPacket,
    VifReceiverSetOffloadOptions,
    VifReceiverSetBackfillSize,
    VifReceiverQueryRingSize,
    VifReceiverSetHashAlgorithm,
    VifReceiverQueryHashCapabilities,
    VifReceiverUpdateHashParameters,
    VifTransmitterQueuePacket,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

static struct _XENVIF_VIF_INTERFACE_V10 VifInterfaceVersion10 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V10), 10, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnable,
    VifDisable,
    VifQueryStatistic,
    VifQueryRingCount,
    VifUpdateHashMapping,
    VifReceiverReturnPacket,
    VifReceiverSetOffloadOptions,
    VifReceiverSetBackfillSize,
    VifReceiverQueryRingSize,
    VifReceiverSetHashAlgorithm,
    VifReceiverQueryHashCapabilities,
    VifReceiverUpdateHashParameters,
    VifTransmitterQueuePacket,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

NTSTATUS
VifInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_VIF_CONTEXT *Context
    )
{
    NTSTATUS                status;

    Trace("====>\n");

    *Context = __VifAllocate(sizeof (XENVIF_VIF_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    InitializeMrswLock(&(*Context)->Lock);

    FdoGetSuspendInterface(PdoGetFdo(Pdo),&(*Context)->SuspendInterface);

    KeInitializeEvent(&(*Context)->MacEvent, NotificationEvent, FALSE);

    status = ThreadCreate(VifMac,
                          *Context,
                          &(*Context)->MacThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Context)->Pdo = Pdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail3\n");

    RtlZeroMemory(&(*Context)->MacEvent, sizeof (KEVENT));

    RtlZeroMemory(&(*Context)->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&(*Context)->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(*Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(*Context);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
VifGetInterface(
    IN      PXENVIF_VIF_CONTEXT Context,
    IN      ULONG               Version,
    IN OUT  PINTERFACE          Interface,
    IN      ULONG               Size
    )
{
    NTSTATUS                    status;

    switch (Version) {
    case 8: {
        struct _XENVIF_VIF_INTERFACE_V8 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V8 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V8))
            break;

        *VifInterface = VifInterfaceVersion8;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    case 9: {
        struct _XENVIF_VIF_INTERFACE_V9 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V9 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V9))
            break;

        *VifInterface = VifInterfaceVersion9;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    case 10: {
        struct _XENVIF_VIF_INTERFACE_V10 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V10 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V10))
            break;

        *VifInterface = VifInterfaceVersion10;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    return status;
}   

VOID
VifTeardown(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    Trace("====>\n");

    Context->Queued = 0;

    Context->Pdo = NULL;
    Context->Version = 0;

    ThreadAlert(Context->MacThread);
    ThreadJoin(Context->MacThread);
    Context->MacThread = NULL;

    RtlZeroMemory(&Context->MacEvent, sizeof (KEVENT));

    RtlZeroMemory(&Context->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Context->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(Context);

    Trace("<====\n");
}

VOID
VifReceiverQueuePacket(
    IN  PXENVIF_VIF_CONTEXT             Context,
    IN  ULONG                           Index,
    IN  PMDL                            Mdl,
    IN  ULONG                           Offset,
    IN  ULONG                           Length,
    IN  XENVIF_PACKET_CHECKSUM_FLAGS    Flags,
    IN  USHORT                          MaximumSegmentSize,
    IN  USHORT                          TagControlInformation,
    IN  PXENVIF_PACKET_INFO             Info,
    IN  PXENVIF_PACKET_HASH             Hash,
    IN  BOOLEAN                         More,
    IN  PVOID                           Cookie,
    OUT PBOOLEAN                        Pause
    )
{
    KIRQL                               Irql;
    XENVIF_VIF_CALLBACK_PARAMETERS      Parameters;

    RtlZeroMemory(&Parameters, sizeof (XENVIF_VIF_CALLBACK_PARAMETERS));

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Parameters.ReceiverQueuePacket.Index = Index;
    Parameters.ReceiverQueuePacket.Mdl = Mdl;
    Parameters.ReceiverQueuePacket.Offset = Offset;
    Parameters.ReceiverQueuePacket.Length = Length;
    Parameters.ReceiverQueuePacket.Flags = Flags;
    Parameters.ReceiverQueuePacket.MaximumSegmentSize = MaximumSegmentSize;
    Parameters.ReceiverQueuePacket.TagControlInformation = TagControlInformation;
    Parameters.ReceiverQueuePacket.Info = Info;
    Parameters.ReceiverQueuePacket.Hash = Hash;
    Parameters.ReceiverQueuePacket.More = More;
    Parameters.ReceiverQueuePacket.Cookie = Cookie;

    Context->Callback(Context->Argument, XENVIF_RECEIVER_QUEUE_PACKET, &Parameters);

    *Pause = Parameters.ReceiverQueuePacket.Pause;

    KeLowerIrql(Irql);
}

VOID
VifTransmitterReturnPacket(
    IN  PXENVIF_VIF_CONTEXT                         Context,
    IN  PVOID                                       Cookie,
    IN  PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO  Completion
    )
{
    XENVIF_VIF_CALLBACK_PARAMETERS                  Parameters;

    RtlZeroMemory(&Parameters, sizeof (XENVIF_VIF_CALLBACK_PARAMETERS));

    Parameters.TransmitterReturnPacket.Cookie = Cookie;
    Parameters.TransmitterReturnPacket.Completion = Completion;

    Context->Callback(Context->Argument, XENVIF_TRANSMITTER_RETURN_PACKET, &Parameters);
}

PXENVIF_THREAD
VifGetMacThread(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    return Context->MacThread;
}
