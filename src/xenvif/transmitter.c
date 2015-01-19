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

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <netioapi.h>
#include <util.h>
#include <xen.h>
#include <debug_interface.h>
#include <store_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <range_set_interface.h>
#include <evtchn_interface.h>

#include "ethernet.h"
#include "tcpip.h"
#include "pdo.h"
#include "frontend.h"
#include "checksum.h"
#include "parse.h"
#include "transmitter.h"
#include "granter.h"
#include "mac.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"

#ifndef XEN_NETIF_GSO_TYPE_TCPV6
#define XEN_NETIF_GSO_TYPE_TCPV6    2
#endif

#define MAXNAMELEN  128

typedef struct _XENVIF_TRANSMITTER_BUFFER {
    PMDL        Mdl;
    PVOID       Context;
    ULONG       Reference;
} XENVIF_TRANSMITTER_BUFFER, *PXENVIF_TRANSMITTER_BUFFER;

typedef enum _XENVIF_TRANSMITTER_FRAGMENT_TYPE {
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID = 0,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER
} XENVIF_TRANSMITTER_FRAGMENT_TYPE, *PXENVIF_TRANSMITTER_FRAGMENT_TYPE;

typedef struct _XENVIF_TRANSMITTER_FRAGMENT {
    LIST_ENTRY                          ListEntry;
    USHORT                              Id;
    XENVIF_TRANSMITTER_FRAGMENT_TYPE    Type;
    PVOID                               Context;
    XENVIF_GRANTER_HANDLE               Handle;
    ULONG                               Offset;
    ULONG                               Length;
    BOOLEAN                             Extra;
} XENVIF_TRANSMITTER_FRAGMENT, *PXENVIF_TRANSMITTER_FRAGMENT;

#define XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID  0x03FF

typedef struct _XENVIF_TRANSMITTER_STATE {
    PXENVIF_TRANSMITTER_PACKET          Packet;
    XENVIF_TRANSMITTER_PACKET_SEND_INFO Send;
    PUCHAR                              StartVa;
    XENVIF_PACKET_INFO                  Info;
    XENVIF_PACKET_PAYLOAD               Payload;
    LIST_ENTRY                          List;
    ULONG                               Count;
} XENVIF_TRANSMITTER_STATE, *PXENVIF_TRANSMITTER_STATE;

#define XENVIF_TRANSMITTER_RING_SIZE   (__CONST_RING_SIZE(netif_tx, PAGE_SIZE))

typedef struct _XENVIF_TRANSMITTER_RING {
    PXENVIF_TRANSMITTER             Transmitter;
    ULONG                           Index;
    PCHAR                           Path;
    PXENBUS_CACHE                   BufferCache;
    PXENBUS_CACHE                   FragmentCache;
    PXENBUS_RANGE_SET               RangeSet;
    PMDL                            Mdl;
    netif_tx_front_ring_t           Front;
    netif_tx_sring_t                *Shared;
    XENVIF_GRANTER_HANDLE           Handle;
    PXENBUS_EVTCHN_CHANNEL          Channel;
    KDPC                            Dpc;
    ULONG                           Dpcs;
    ULONG                           Events;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;
    BOOLEAN                         Stopped;
    PVOID                           Lock;
    PKTHREAD                        LockThread;
    LIST_ENTRY                      Queued;
    XENVIF_TRANSMITTER_STATE        State;
    ULONG                           PacketsQueued;
    ULONG                           PacketsGranted;
    ULONG                           PacketsCopied;
    ULONG                           PacketsFaked;
    ULONG                           PacketsUnprepared;
    ULONG                           PacketsPrepared;
    PXENVIF_TRANSMITTER_FRAGMENT    Pending[XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID + 1];
    ULONG                           RequestsPosted;
    ULONG                           RequestsPushed;
    ULONG                           ResponsesProcessed;
    ULONG                           PacketsSent;
    LIST_ENTRY                      Completed;
    ULONG                           PacketsCompleted;
    PSOCKADDR_INET                  AddressTable;
    ULONG                           AddressCount;
    ULONG                           AddressIndex;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
    PXENVIF_THREAD                  WatchdogThread;
} XENVIF_TRANSMITTER_RING, *PXENVIF_TRANSMITTER_RING;

struct _XENVIF_TRANSMITTER {
    PXENVIF_FRONTEND            Frontend;
    XENBUS_CACHE_INTERFACE      CacheInterface;
    XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
    XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    PXENVIF_TRANSMITTER_RING    Rings[MAXIMUM_PROCESSORS];
    LONG_PTR                    Offset[XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT];
    BOOLEAN                     Split;
    ULONG                       DisableIpVersion4Gso;
    ULONG                       DisableIpVersion6Gso;
    ULONG                       AlwaysCopy;
    KSPIN_LOCK                  Lock;
    PXENBUS_CACHE               PacketCache;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define XENVIF_TRANSMITTER_TAG  'NART'
#define XENVIF_PACKET_CACHE_RESERVATION 32

static FORCEINLINE PVOID
__TransmitterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, XENVIF_TRANSMITTER_TAG);
}

static FORCEINLINE VOID
__TransmitterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_TRANSMITTER_TAG);
}

static VOID
TransmitterPacketAcquireLock(
    IN  PVOID           Argument
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;

    KeAcquireSpinLockAtDpcLevel(&Transmitter->Lock);
}

static VOID
TransmitterPacketReleaseLock(
    IN  PVOID                       Argument
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;

#pragma prefast(suppress:26110)
    KeReleaseSpinLockFromDpcLevel(&Transmitter->Lock);
}

static NTSTATUS
TransmitterPacketCtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);

    return STATUS_SUCCESS;
}

static VOID
TransmitterPacketDtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__TransmitterGetPacket(
    IN  PXENVIF_TRANSMITTER         Transmitter
    )
{
    return XENBUS_CACHE(Get,
                        &Transmitter->CacheInterface,
                        Transmitter->PacketCache,
                        FALSE);
}

static FORCEINLINE VOID
__TransmitterPutPacket(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    RtlZeroMemory(Packet, sizeof(XENVIF_TRANSMITTER_PACKET));

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Transmitter->PacketCache,
                 Packet,
                 FALSE);
}

static NTSTATUS
TransmitterBufferCtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_BUFFER  Buffer = Object;
    PMDL		                Mdl;
    PUCHAR		                MdlMappedSystemVa;
    NTSTATUS	                status;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
	goto fail1;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);
    RtlFillMemory(MdlMappedSystemVa, PAGE_SIZE, 0xAA);

    Mdl->ByteCount = 0;
    Buffer->Mdl = Mdl;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));

    return status;
}

static VOID
TransmitterBufferDtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_BUFFER  Buffer = Object;
    PMDL                        Mdl;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Buffer->Mdl;
    Buffer->Mdl = NULL;

    Mdl->ByteCount = PAGE_SIZE;

    __FreePage(Mdl);
    ExFreePool(Mdl);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_BUFFER
__TransmitterGetBuffer(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Buffer = XENBUS_CACHE(Get,
                          &Transmitter->CacheInterface,
                          Ring->BufferCache,
                          TRUE);

    ASSERT(IMPLY(Buffer != NULL, Buffer->Mdl->ByteCount == 0));

    return Buffer;
}

static FORCEINLINE VOID
__TransmitterPutBuffer(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_BUFFER  Buffer
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Buffer->Reference, ==, 0);
    ASSERT3P(Buffer->Context, ==, NULL);

    Buffer->Mdl->ByteCount = 0;

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->BufferCache,
                 Buffer,
                 TRUE);
}

static NTSTATUS
TransmitterFragmentCtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    PXENVIF_TRANSMITTER_RING        Ring = Argument;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment = Object;
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    LONGLONG                        Id;
    NTSTATUS	                    status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));

    status = XENBUS_RANGE_SET(Pop,
                              &Transmitter->RangeSetInterface,
                              Ring->RangeSet,
                              1,
                              &Id);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fragment->Id = (USHORT)Id;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));

    return status;
}

static VOID
TransmitterFragmentDtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    PXENVIF_TRANSMITTER_RING        Ring = Argument;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment = Object;
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    LONGLONG                        Id;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Id = Fragment->Id;
    Fragment->Id = 0;

    XENBUS_RANGE_SET(Put,
                     &Transmitter->RangeSetInterface,
                     Ring->RangeSet,
                     Id,
                     1);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_FRAGMENT
__TransmitterGetFragment(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    return XENBUS_CACHE(Get,
                        &Transmitter->CacheInterface,
                        Ring->FragmentCache,
                        TRUE);
}

static FORCEINLINE
__TransmitterPutFragment(
    IN  PXENVIF_TRANSMITTER_RING        Ring,
    IN  PXENVIF_TRANSMITTER_FRAGMENT    Fragment
    )
{
    PXENVIF_TRANSMITTER                 Transmitter;
    PXENVIF_FRONTEND                    Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Fragment->Length, ==, 0);
    ASSERT3U(Fragment->Offset, ==, 0);
    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID);
    ASSERT3P(Fragment->Context, ==, NULL);
    ASSERT(!Fragment->Extra);

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->FragmentCache,
                 Fragment,
                 TRUE);
}

static VOID
TransmitterRingDebugCallback(
    IN  PVOID                   Argument,
    IN  BOOLEAN                 Crashing
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Argument;
    PXENVIF_TRANSMITTER         Transmitter;

    UNREFERENCED_PARAMETER(Crashing);

    Transmitter = Ring->Transmitter;

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "0x%p [%s]\n",
                 Ring,
                 (Ring->Enabled) ? "ENABLED" : "DISABLED");

    // Dump front ring
    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                 Ring->Front.req_prod_pvt,
                 Ring->Front.rsp_cons,
                 Ring->Front.nr_ents,
                 Ring->Front.sring);

    // Dump shared ring
    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                 Ring->Shared->req_prod,
                 Ring->Shared->req_event,
                 Ring->Shared->rsp_prod,
                 Ring->Shared->rsp_event);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                 Ring->RequestsPosted,
                 Ring->RequestsPushed,
                 Ring->ResponsesProcessed);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "State:\n");

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "- Packet = %p\n",
                 Ring->State.Packet);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "- Count = %u\n",
                 Ring->State.Count);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "PacketsGranted = %u PacketsCopied = %u PacketsFaked = %u\n",
                 Ring->PacketsGranted,
                 Ring->PacketsCopied,
                 Ring->PacketsFaked);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "PacketsQueued = %u PacketsPrepared = %u PacketsUnprepared = %u PacketsSent = %u PacketsCompleted = %u\n",
                 Ring->PacketsQueued,
                 Ring->PacketsPrepared,
                 Ring->PacketsUnprepared,
                 Ring->PacketsSent,
                 Ring->PacketsCompleted);
}

static BOOLEAN
TransmitterRingPullup(
    IN      PVOID                   Argument,
    IN      PUCHAR                  DestinationVa,
    IN OUT  PXENVIF_PACKET_PAYLOAD  Payload,
    IN      ULONG                   Length
    )
{
    PMDL                            Mdl;
    ULONG                           Offset;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;

    if (Payload->Length < Length)
        goto fail1;

    Payload->Length -= Length;

    while (Length != 0) {
        PUCHAR  MdlMappedSystemVa;
        ULONG   MdlByteCount;
        ULONG   CopyLength;

        ASSERT(Mdl != NULL);

        MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ASSERT(MdlMappedSystemVa != NULL);

        MdlMappedSystemVa += Offset;

        MdlByteCount = Mdl->ByteCount - Offset;

        CopyLength = __min(MdlByteCount, Length);

        RtlCopyMemory(DestinationVa, MdlMappedSystemVa, CopyLength);
        DestinationVa += CopyLength;

        Offset += CopyLength;
        Length -= CopyLength;

        MdlByteCount -= CopyLength;
        if (MdlByteCount == 0) {
            Mdl = Mdl->Next;
            Offset = 0;
        }
    }

    Payload->Mdl = Mdl;
    Payload->Offset = Offset;

    return TRUE;

fail1:
    Error("fail1\n");

    return FALSE;
}

static FORCEINLINE NTSTATUS
__TransmitterRingCopyPayload(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    XENVIF_PACKET_PAYLOAD           Payload;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = State->Payload;

    ASSERT(Packet != NULL);
    ASSERT3U(Packet->Value, ==, 1);

    while (Payload.Length != 0) {
        PMDL        Mdl;
        ULONG       Length;
        PUCHAR      MdlMappedSystemVa;
        PFN_NUMBER  Pfn;

        Buffer = __TransmitterGetBuffer(Ring);

        status = STATUS_NO_MEMORY;
        if (Buffer == NULL)
            goto fail1;

        Buffer->Context = Packet;
        Packet->Value++;

        Mdl = Buffer->Mdl;

        Length = __min(Payload.Length, PAGE_SIZE);

        MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        TransmitterRingPullup(Ring, MdlMappedSystemVa, &Payload, Length);

        Mdl->ByteCount = Length;

        Fragment = __TransmitterGetFragment(Ring);

        status = STATUS_NO_MEMORY;
        if (Fragment == NULL)
            goto fail2;

        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
        Fragment->Context = Buffer;
        Buffer->Reference++;

        Pfn = MmGetMdlPfnArray(Mdl)[0];

        status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                     Pfn,
                                     TRUE,
                                     &Fragment->Handle);
        if (!NT_SUCCESS(status))
            goto fail3;

        Fragment->Offset = 0;
        Fragment->Length = Mdl->ByteCount;

        ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(&State->List, &Fragment->ListEntry);
        State->Count++;

        ASSERT3U(State->Count, <=, XEN_NETIF_NR_SLOTS_MIN);
    }

    Ring->PacketsCopied++;
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    ASSERT3P(Buffer->Context, ==, Packet);
    Buffer->Context = NULL;        

    Packet->Value--;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    while (Packet->Value != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Fragment->Handle);
        Fragment->Handle = NULL;

        ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
        Buffer = Fragment->Context;
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        ASSERT(Buffer->Reference != 0);
        --Buffer->Reference;

        __TransmitterPutFragment(Ring, Fragment);

        ASSERT3P(Buffer->Context, ==, Packet);
        Buffer->Context = NULL;        

        Packet->Value--;

        __TransmitterPutBuffer(Ring, Buffer);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingGrantPayload(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PMDL                            Mdl;
    ULONG                           Offset;
    ULONG                           Length;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;

    ASSERT(Packet != NULL);
    ASSERT3U(Packet->Value, ==, 1);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;
    Length = Payload->Length;

    while (Length != 0) {
        ULONG   MdlOffset;
        ULONG   MdlByteCount;
        ULONG   MdlLength;

        MdlOffset = Mdl->ByteOffset + Offset;
        MdlByteCount = Mdl->ByteCount - Offset;

        MdlLength = __min(MdlByteCount, Length);

        while (MdlLength != 0) {
            PFN_NUMBER          Pfn;
            ULONG               PageOffset;
            ULONG               PageLength;

            Fragment = __TransmitterGetFragment(Ring);

            status = STATUS_NO_MEMORY;
            if (Fragment == NULL)
                goto fail1;

            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET;
            Fragment->Context = Packet;
            Packet->Value++;

            Pfn = MmGetMdlPfnArray(Mdl)[MdlOffset / PAGE_SIZE];
            PageOffset = MdlOffset & (PAGE_SIZE - 1);
            PageLength = __min(MdlLength, PAGE_SIZE - PageOffset);

            status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                         Pfn,
                                         TRUE,
                                         &Fragment->Handle);
            if (!NT_SUCCESS(status))
                goto fail2;

            Fragment->Offset = PageOffset;
            Fragment->Length = PageLength;

            ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
            InsertTailList(&State->List, &Fragment->ListEntry);
            State->Count++;

            Fragment = NULL;

            // Bounce the packet if it is too highly fragmented
            status = STATUS_BUFFER_OVERFLOW;
            if (State->Count > XEN_NETIF_NR_SLOTS_MIN)
                goto fail3;

            MdlOffset += PageLength;

            ASSERT3U(MdlLength, >=, PageLength);
            MdlLength -= PageLength;

            ASSERT3U(Length, >=, PageLength);
            Length -= PageLength;
        }

        Mdl = Mdl->Next;
        Offset = 0;
    }

    Ring->PacketsGranted++;
    return STATUS_SUCCESS;

fail3:
fail2:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail2\n");

    if (Fragment != NULL) {
        ASSERT3P(Fragment->Context, ==, Packet);
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        Packet->Value--;

        __TransmitterPutFragment(Ring, Fragment);
    }

fail1:
    if (status != STATUS_BUFFER_OVERFLOW)
        Error("fail1 (%08x)\n", status);

    ASSERT3P(Fragment, ==, NULL);

    while (Packet->Value != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Fragment->Handle);
        Fragment->Handle = NULL;

        ASSERT3P(Fragment->Context, ==, Packet);
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        Packet->Value--;

        __TransmitterPutFragment(Ring, Fragment);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareHeader(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          StartVa;
    PFN_NUMBER                      Pfn;
    PETHERNET_HEADER                EthernetHeader;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;
    Info = &State->Info;

    ASSERT3U(Packet->Value, ==, 0);

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Buffer->Context = Packet;
    Packet->Value++;

    Mdl = Buffer->Mdl;

    StartVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);

    status = ParsePacket(StartVa, TransmitterRingPullup, Ring, Payload, Info);
    if (!NT_SUCCESS(status))
        goto fail2;

    State->StartVa = StartVa;

    Mdl->ByteCount = Info->Length;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail3;

    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Fragment->Context = Buffer;
 
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Fragment->Handle);
    if (!NT_SUCCESS(status))
        goto fail4;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount + Payload->Length;

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);        

    if (State->Send.OffloadOptions.OffloadTagManipulation) {
        ULONG   Offset;

        Offset = FIELD_OFFSET(ETHERNET_TAGGED_HEADER, Tag);

        RtlMoveMemory((PUCHAR)EthernetHeader + Offset + sizeof (ETHERNET_TAG),
                      (PUCHAR)EthernetHeader + Offset,
                      Mdl->ByteCount - Offset);

        // Insert the tag
        EthernetHeader->Tagged.Tag.ProtocolID = HTONS(ETHERTYPE_TPID);
        EthernetHeader->Tagged.Tag.ControlInformation = HTONS(State->Send.TagControlInformation);
        ASSERT(ETHERNET_HEADER_IS_TAGGED(EthernetHeader));

        Mdl->ByteCount += sizeof (ETHERNET_TAG);
        Fragment->Length += sizeof (ETHERNET_TAG);

        // Fix up the packet information
        Info->EthernetHeader.Length += sizeof (ETHERNET_TAG);
        Info->Length += sizeof (ETHERNET_TAG);

        if (Info->IpHeader.Length != 0)
            Info->IpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->IpOptions.Length != 0)
            Info->IpOptions.Offset += sizeof (ETHERNET_TAG);

        if (Info->UdpHeader.Length != 0)
            Info->UdpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->TcpHeader.Length != 0)
            Info->TcpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->TcpOptions.Length != 0)
            Info->TcpOptions.Offset += sizeof (ETHERNET_TAG);
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4LargePacket) {
        PIP_HEADER  IpHeader;
        PTCP_HEADER TcpHeader;
        ULONG       Length;

        ASSERT(!Info->IsAFragment);

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT(Info->TcpHeader.Length != 0);
        TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

        // Fix up the IP packet length
        Length = Info->IpHeader.Length +
                 Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 Payload->Length;

        ASSERT3U((USHORT)Length, ==, Length);

        ASSERT3U(IpHeader->Version, ==, 4);

        IpHeader->Version4.PacketLength = HTONS((USHORT)Length);

        // IP checksum calulcation must be offloaded for large packets
        State->Send.OffloadOptions.OffloadIpVersion4HeaderChecksum = 1;

        // TCP checksum calulcation must be offloaded for large packets
        TcpHeader->Checksum = ChecksumPseudoHeader(StartVa, Info);
        State->Send.OffloadOptions.OffloadIpVersion4TcpChecksum = 1;

        // If the MSS is such that the payload would constitute only a single fragment then
        // we no longer need trate the packet as a large packet.
        ASSERT3U(State->Send.MaximumSegmentSize, <=, Payload->Length);
        if (State->Send.MaximumSegmentSize == Payload->Length)
            State->Send.OffloadOptions.OffloadIpVersion4LargePacket = 0;
    }
    
    if (State->Send.OffloadOptions.OffloadIpVersion6LargePacket) {
        PIP_HEADER  IpHeader;
        PTCP_HEADER TcpHeader;
        ULONG       Length;

        ASSERT(!Info->IsAFragment);

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT(Info->TcpHeader.Length != 0);
        TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

        // Fix up the IP payload length
        Length = Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 Payload->Length;

        ASSERT3U((USHORT)Length, ==, Length);

        ASSERT3U(IpHeader->Version, ==, 6);

        IpHeader->Version6.PayloadLength = HTONS((USHORT)Length);

        // TCP checksum calulcation must be offloaded for large packets
        TcpHeader->Checksum = ChecksumPseudoHeader(StartVa, Info);
        State->Send.OffloadOptions.OffloadIpVersion6TcpChecksum = 1;

        // If the MSS is such that the payload would constitute only a single fragment then
        // we no longer need treat the packet as a large packet.
        ASSERT3U(State->Send.MaximumSegmentSize, <=, Payload->Length);
        if (State->Send.MaximumSegmentSize == Payload->Length)
            State->Send.OffloadOptions.OffloadIpVersion6LargePacket = 0;
    }

    // Non-GSO packets must not exceed MTU
    if (!State->Send.OffloadOptions.OffloadIpVersion4LargePacket &&
        !State->Send.OffloadOptions.OffloadIpVersion6LargePacket) {
        ULONG   MaximumFrameSize;

        MacQueryMaximumFrameSize(Mac, &MaximumFrameSize);
        
        if (Fragment->Length > MaximumFrameSize) {
            status = STATUS_INVALID_PARAMETER;
            goto fail5;
        }
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4HeaderChecksum) {
        PIP_HEADER  IpHeader;

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT3U(IpHeader->Version, ==, 4);
        IpHeader->Version4.Checksum = ChecksumIpVersion4Header(StartVa, Info);
    }

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    ASSERT(State->Count != 0);
    --State->Count;

    RemoveEntryList(&Fragment->ListEntry);
    RtlZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY));

    Fragment->Length = 0;
    Fragment->Offset = 0;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Fragment->Handle);
    Fragment->Handle = NULL;

fail4:
    Error("fail4\n");

    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail3:
    Error("fail3\n");

    Mdl->ByteCount = 0;

fail2:
    Error("fail2\n");

    Packet->Value--;
    Buffer->Context = NULL;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT3U(Packet->Value, ==, 0);

    return status;
}

static FORCEINLINE VOID
__TransmitterRingUnprepareFragments(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;

    while (State->Count != 0) {
        PLIST_ENTRY                     ListEntry;
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
        PXENVIF_TRANSMITTER_PACKET      Packet;

        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Fragment->Handle);
        Fragment->Handle = NULL;

        switch (Fragment->Type) {
        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER: {
            PXENVIF_TRANSMITTER_BUFFER  Buffer;

            Buffer = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            Packet = Buffer->Context;
            Buffer->Context = NULL;

            ASSERT(Buffer->Reference != 0);
            if (--Buffer->Reference == 0)
                __TransmitterPutBuffer(Ring, Buffer);

            break;
        }
        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET:
            Packet = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            break;

        default:
            Packet = NULL;
            ASSERT(FALSE);
        }

        __TransmitterPutFragment(Ring, Fragment);

        if (Packet != NULL)
            Packet->Value--;
    }
}

static FORCEINLINE NTSTATUS
__TransmitterRingPreparePacket(
    IN  PXENVIF_TRANSMITTER_RING        Ring,
    IN  PXENVIF_TRANSMITTER_PACKET      Packet
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Transmitter = Ring->Transmitter;

    State = &Ring->State;

    State->Packet = Packet;

    State->Send = Packet->Send;
    RtlZeroMemory(&Packet->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));

    Payload = &State->Payload;
    Payload->Mdl = Packet->Mdl;
    Payload->Offset = Packet->Offset;
    Payload->Length = Packet->Length;

    InitializeListHead(&State->List);
    ASSERT3U(State->Count, ==, 0);

    status = __TransmitterRingPrepareHeader(Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    ASSERT3U(State->Count, ==, Packet->Value);

    Info = &State->Info;

    // Is the packet too short?
    if (Info->Length + Payload->Length < ETHERNET_MIN) {
        ULONG   Trailer;
        BOOLEAN SingleFragment;

        Trailer = ETHERNET_MIN - Payload->Length - Info->Length;
        SingleFragment = (Payload->Length == 0) ? TRUE : FALSE;

        status = __TransmitterRingCopyPayload(Ring);

        if (NT_SUCCESS(status)) {
            PLIST_ENTRY                     ListEntry;
            PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
            PXENVIF_TRANSMITTER_BUFFER      Buffer;
            PMDL                            Mdl;
            PUCHAR                          MdlMappedSystemVa;

            // Add padding to the tail buffer
            ListEntry = State->List.Blink;
            Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

            ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
            Buffer = Fragment->Context;

            Mdl = Buffer->Mdl;

            ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE - Trailer);

            MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
            ASSERT(MdlMappedSystemVa != NULL);

            MdlMappedSystemVa += Mdl->ByteCount;

            RtlZeroMemory(MdlMappedSystemVa, Trailer);
            Mdl->ByteCount += Trailer;

            if (!SingleFragment) {
                ASSERT3P(State->List.Flink, !=, ListEntry);
                Fragment->Length += Trailer;
            }

            // Adjust length of header fragment
            ListEntry = State->List.Flink;
            Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

            Fragment->Length += Trailer;
            ASSERT3U(Fragment->Length, ==, ETHERNET_MIN);
        }
    } else {
        if (Transmitter->AlwaysCopy == 0)
            status = __TransmitterRingGrantPayload(Ring);

        if (Transmitter->AlwaysCopy != 0 ||
            (!NT_SUCCESS(status) && status == STATUS_BUFFER_OVERFLOW)) {
            ASSERT3U(State->Count, ==, Packet->Value);

            status = __TransmitterRingCopyPayload(Ring);
        }
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    ASSERT3U(State->Count, ==, Packet->Value);

    Ring->PacketsPrepared++;
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __TransmitterRingUnprepareFragments(Ring);

fail1:
    Error("fail1 (%08x)\n", status);

    State->StartVa = NULL;
    RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));

    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Send = State->Send;
    RtlZeroMemory(&State->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__TransmitterRingUnpreparePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;

    State = &Ring->State;
    Packet = State->Packet;

    // This has the side effect of freeing up resources associated with a pending
    // gratuitous ARP, which is why the call is not conditional on Packet being
    // non-NULL
    __TransmitterRingUnprepareFragments(Ring);
    RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));

    if (Packet == NULL)
        goto done;

    Ring->PacketsUnprepared++;

    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Send = State->Send;
    RtlZeroMemory(&State->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

done:
    return Packet;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareArp(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV4_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          MdlMappedSystemVa;
    PETHERNET_UNTAGGED_HEADER       EthernetHeader;
    PARP_HEADER                     ArpHeader;
    ETHERNET_ADDRESS                SenderHardwareAddress;
    IPV4_ADDRESS                    SenderProtocolAddress;
    ETHERNET_ADDRESS                TargetHardwareAddress;
    IPV4_ADDRESS                    TargetProtocolAddress;
    PFN_NUMBER                      Pfn;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Info("%u.%u.%u.%u\n",
         Address->Byte[0],
         Address->Byte[1],
         Address->Byte[2],
         Address->Byte[3]);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    SenderProtocolAddress = *Address;
    TargetProtocolAddress = *Address;
    MacQueryCurrentAddress(Mac, &SenderHardwareAddress);
    MacQueryBroadcastAddress(Mac, &TargetHardwareAddress);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)MdlMappedSystemVa;

    MacQueryBroadcastAddress(Mac, &EthernetHeader->DestinationAddress);
    MacQueryCurrentAddress(Mac, &EthernetHeader->SourceAddress);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_ARP);

    MdlMappedSystemVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    ArpHeader = (PARP_HEADER)MdlMappedSystemVa;

    ArpHeader->HardwareType = HTONS(HARDWARE_ETHER);
    ArpHeader->ProtocolType = HTONS(PROTOCOL_IPV4);
    ArpHeader->HardwareAddressLength = ETHERNET_ADDRESS_LENGTH;
    ArpHeader->ProtocolAddressLength = IPV4_ADDRESS_LENGTH;
    ArpHeader->Operation = HTONS(ARP_REQUEST);

    MdlMappedSystemVa += sizeof (ARP_HEADER);

    RtlCopyMemory(MdlMappedSystemVa, SenderHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, SenderProtocolAddress.Byte, IPV4_ADDRESS_LENGTH);
    MdlMappedSystemVa += IPV4_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, TargetHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, TargetProtocolAddress.Byte, IPV4_ADDRESS_LENGTH);
    MdlMappedSystemVa += IPV4_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(MdlMappedSystemVa - (PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority));

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Buffer;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Fragment->Handle);
    if (!NT_SUCCESS(status))
        goto fail3;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    Mdl->ByteCount = 0;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareNeighbourAdvertisement(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV6_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          MdlMappedSystemVa;
    PETHERNET_UNTAGGED_HEADER       EthernetHeader;
    PIPV6_HEADER                    IpHeader;
    PICMPV6_HEADER                  IcmpHeader;
    IPV6_ADDRESS                    TargetProtocolAddress;
    ETHERNET_ADDRESS                SenderHardwareAddress;
    USHORT                          PayloadLength;
    ULONG                           Accumulator;
    PFN_NUMBER                      Pfn;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Info("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
         HTONS(Address->Word[0]),
         HTONS(Address->Word[1]),
         HTONS(Address->Word[2]),
         HTONS(Address->Word[3]),
         HTONS(Address->Word[4]),
         HTONS(Address->Word[5]),
         HTONS(Address->Word[6]),
         HTONS(Address->Word[7]));

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    TargetProtocolAddress = *Address;
    MacQueryCurrentAddress(Mac, &SenderHardwareAddress);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)MdlMappedSystemVa;

    MacQueryBroadcastAddress(Mac, &EthernetHeader->DestinationAddress);
    MacQueryCurrentAddress(Mac, &EthernetHeader->SourceAddress);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_IPV6);

    MdlMappedSystemVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    IpHeader = (PIPV6_HEADER)MdlMappedSystemVa;
    RtlZeroMemory(IpHeader, sizeof (IPV6_HEADER));

    IpHeader->Version = 6;
    IpHeader->NextHeader = IPPROTO_ICMPV6;
    IpHeader->HopLimit = 255;

    RtlCopyMemory(IpHeader->SourceAddress.Byte, 
                  Address,
                  IPV6_ADDRESS_LENGTH);

    // Destination is all-nodes multicast address
    IpHeader->DestinationAddress.Byte[0] = 0xFF;
    IpHeader->DestinationAddress.Byte[1] = 0x02;
    IpHeader->DestinationAddress.Byte[15] = 0x02;

    PayloadLength = 0;
    MdlMappedSystemVa += sizeof (IPV6_HEADER);

    IcmpHeader = (PICMPV6_HEADER)MdlMappedSystemVa;

    IcmpHeader->Type = ICMPV6_TYPE_NA;
    IcmpHeader->Code = 0;
    IcmpHeader->Data = HTONL(0x02); // Override flag

    PayloadLength += sizeof (ICMPV6_HEADER);
    MdlMappedSystemVa += sizeof (ICMPV6_HEADER);

    RtlCopyMemory(MdlMappedSystemVa, TargetProtocolAddress.Byte, IPV6_ADDRESS_LENGTH);

    PayloadLength += IPV6_ADDRESS_LENGTH;
    MdlMappedSystemVa += IPV6_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, SenderHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);

    PayloadLength += ETHERNET_ADDRESS_LENGTH;
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(MdlMappedSystemVa - (PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority));

    // Fix up IP payload length and ICMPv6 checksum
    IpHeader->PayloadLength = HTONS(PayloadLength);

    Accumulator = ChecksumIpVersion6PseudoHeader(&IpHeader->SourceAddress,
                                                 &IpHeader->DestinationAddress,
                                                 PayloadLength,
                                                 IPPROTO_ICMPV6);
    AccumulateChecksum(&Accumulator, IcmpHeader, PayloadLength);

    IcmpHeader->Checksum = (USHORT)~Accumulator;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Buffer;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Fragment->Handle);
    if (!NT_SUCCESS(status))
        goto fail3;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    Mdl->ByteCount = 0;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPostFragments(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
#define RING_SLOTS_AVAILABLE(_Front, _req_prod, _rsp_cons)   \
        (RING_SIZE(_Front) - ((_req_prod) - (_rsp_cons)))

    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    RING_IDX                        req_prod;
    RING_IDX                        rsp_cons;
    ULONG                           Extra;
    ULONG                           PacketLength;
    BOOLEAN                         FirstRequest;
    netif_tx_request_t              *req;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;

    ASSERT(!IsListEmpty(&State->List));
    ASSERT(State->Count != 0);
    ASSERT3U(State->Count, <=, XEN_NETIF_NR_SLOTS_MIN);
    ASSERT(IMPLY(Packet != NULL, State->Count == Packet->Value));

    req_prod = Ring->Front.req_prod_pvt;
    rsp_cons = Ring->Front.rsp_cons;

    Extra = (State->Send.OffloadOptions.OffloadIpVersion4LargePacket ||
             State->Send.OffloadOptions.OffloadIpVersion6LargePacket) ?
            1 :
            0;

    ASSERT3U(State->Count + Extra, <=, RING_SIZE(&Ring->Front));

    status = STATUS_ALLOTTED_SPACE_EXCEEDED;
    if (State->Count + Extra > RING_SLOTS_AVAILABLE(&Ring->Front, req_prod, rsp_cons))
        goto fail1;

    req = NULL;

    FirstRequest = TRUE;
    PacketLength = 0;
    while (State->Count != 0) {
        PLIST_ENTRY                     ListEntry;
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;

        --State->Count;

        ListEntry = RemoveHeadList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        req = RING_GET_REQUEST(&Ring->Front, req_prod);
        req_prod++;
        Ring->RequestsPosted++;

        req->id = Fragment->Id;
        req->gref = GranterGetReference(FrontendGetGranter(Frontend),
                                        Fragment->Handle);
        req->offset = (USHORT)Fragment->Offset;
        req->size = (USHORT)Fragment->Length;
        req->flags = NETTXF_more_data;

        if (FirstRequest) {
            FirstRequest = FALSE;

            if (State->Send.OffloadOptions.OffloadIpVersion4TcpChecksum ||
                State->Send.OffloadOptions.OffloadIpVersion4UdpChecksum ||
                State->Send.OffloadOptions.OffloadIpVersion6TcpChecksum ||
                State->Send.OffloadOptions.OffloadIpVersion6UdpChecksum)
                req->flags |= NETTXF_csum_blank | NETTXF_data_validated;

            if (State->Send.OffloadOptions.OffloadIpVersion4LargePacket ||
                State->Send.OffloadOptions.OffloadIpVersion6LargePacket) {
                uint8_t                 type;
                uint16_t                size;
                struct netif_extra_info *extra;

                ASSERT(Extra != 0);
                Fragment->Extra = TRUE;

                ASSERT(!(State->Send.OffloadOptions.OffloadIpVersion4LargePacket &&
                         State->Send.OffloadOptions.OffloadIpVersion6LargePacket));
                type = (State->Send.OffloadOptions.OffloadIpVersion4LargePacket) ?
                       XEN_NETIF_GSO_TYPE_TCPV4 :
                       XEN_NETIF_GSO_TYPE_TCPV6;

                ASSERT(State->Send.MaximumSegmentSize != 0);
                size = State->Send.MaximumSegmentSize;

                ASSERT(req->flags & (NETTXF_csum_blank | NETTXF_data_validated));
                req->flags |= NETTXF_extra_info;

                extra = (struct netif_extra_info *)RING_GET_REQUEST(&Ring->Front, req_prod);
                req_prod++;
                Ring->RequestsPosted++;

                extra->type = XEN_NETIF_EXTRA_TYPE_GSO;
                extra->flags = 0;

                extra->u.gso.size = size;
                extra->u.gso.type = type;
                extra->u.gso.pad = 0;
                extra->u.gso.features = 0;
            }

            // The first fragment length is the length of the entire packet
            PacketLength = Fragment->Length;
        }

        // Store a copy of the request in case we need to fake a response ourselves
        ASSERT3U(req->id, <=, XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
        ASSERT3P(Ring->Pending[req->id], ==, NULL);
        Ring->Pending[req->id] = Fragment;
    }
    ASSERT(!FirstRequest);
    ASSERT(PacketLength != 0);

    ASSERT(req != NULL);
    req->flags &= ~NETTXF_more_data;

    Ring->Front.req_prod_pvt = req_prod;

    ASSERT3U(State->Count, ==, 0);
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    // Set the initial completion information
    if (Packet != NULL) {
        PUCHAR              StartVa;
        PXENVIF_PACKET_INFO Info;
        PETHERNET_HEADER    Header;

        StartVa = State->StartVa;
        Info = &State->Info;

        ASSERT(IsZeroMemory(&Packet->Completion, sizeof (XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO)));

        ASSERT(Info->EthernetHeader.Length != 0);
        Header = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);

        Packet->Completion.Type = GET_ETHERNET_ADDRESS_TYPE(&Header->Untagged.DestinationAddress);
        Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_PENDING;
        Packet->Completion.PacketLength = (USHORT)PacketLength;
        Packet->Completion.PayloadLength = (USHORT)Payload->Length;

        State->StartVa = NULL;
        RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));
        RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));
        RtlZeroMemory(&State->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));
        State->Packet = NULL;

        Ring->PacketsSent++;
    }

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return STATUS_SUCCESS;

fail1:
    return status;

#undef  RING_SLOTS_AVAILABLE
}

static FORCEINLINE VOID
__TransmitterRingFakeResponses(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    RING_IDX                        rsp_prod;
    USHORT                          id;
    ULONG                           Count;

    // This is only called when the backend went away. We need
    // to mimic the behavior of the backend and turn requests into
    // appropriate responses.

    KeMemoryBarrier();

    rsp_prod = Ring->Shared->rsp_prod;

    KeMemoryBarrier();

    Count = 0;
    for (id = 0; id <= XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID; id++) {
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
        netif_tx_response_t             *rsp;

        Fragment = Ring->Pending[id];
        Ring->Pending[id] = NULL;

        if (Fragment == NULL)
            continue;

        rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
        rsp_prod++;
        Count++;

        rsp->id = Fragment->Id;
        rsp->status = NETIF_RSP_DROPPED;

        if (Fragment->Extra) {
            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
            rsp_prod++;
            Count++;

            rsp->status = NETIF_RSP_NULL;
        }
    }

    KeMemoryBarrier();

    Ring->Shared->rsp_prod = rsp_prod;

    KeMemoryBarrier();

    ASSERT3U(Ring->Shared->rsp_prod, ==, Ring->Front.req_prod_pvt);

    if (Count != 0)
        Info("Faked %lu responses\n", Count);
}

static FORCEINLINE VOID
__TransmitterRingCompletePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENVIF_TRANSMITTER                 Transmitter;
    PXENVIF_FRONTEND                    Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(Packet->Completion.Status != XENVIF_TRANSMITTER_PACKET_PENDING);

    if (Packet->Completion.Status != XENVIF_TRANSMITTER_PACKET_OK) {
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_PACKETS_DROPPED,
                                   1);

        if (Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_ERROR)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BACKEND_ERRORS,
                                       1);
    } else {
        ULONG   Length;

        Length = (ULONG)Packet->Completion.PacketLength;

        switch (Packet->Completion.Type) {
        case ETHERNET_ADDRESS_UNICAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_UNICAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_UNICAST_OCTETS,
                                       Length);
            break;
            
        case ETHERNET_ADDRESS_MULTICAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                                       Length);
            break;

        case ETHERNET_ADDRESS_BROADCAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                                       Length);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    InsertTailList(&Ring->Completed, &Packet->ListEntry);
    Ring->PacketsCompleted++;
}

static DECLSPEC_NOINLINE VOID
TransmitterRingPoll(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
#define XENVIF_TRANSMITTER_BATCH(_Ring) (RING_SIZE(&(_Ring)->Front) / 4)

    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    for (;;) {
        RING_IDX    rsp_prod;
        RING_IDX    rsp_cons;
        ULONG       Delta;

        KeMemoryBarrier();

        rsp_prod = Ring->Shared->rsp_prod;
        rsp_cons = Ring->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod)
            break;

        while (rsp_cons != rsp_prod) {
            netif_tx_response_t             *rsp;
            uint16_t                        id;
            PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
            PXENVIF_TRANSMITTER_PACKET      Packet;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            rsp_cons++;
            Ring->ResponsesProcessed++;

            Ring->Stopped = FALSE;

            if (rsp->status == NETIF_RSP_NULL)
                continue;

            id = rsp->id;

            ASSERT3U(id, <=, XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
            Fragment = Ring->Pending[id];
            Ring->Pending[id] = NULL;

            ASSERT(Fragment != NULL);
            ASSERT3U(Fragment->Id, ==, id);

            switch (Fragment->Type) {
            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER: {
                PXENVIF_TRANSMITTER_BUFFER  Buffer;

                Buffer = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                Packet = Buffer->Context;
                Buffer->Context = NULL;

                ASSERT(Buffer->Reference != 0);
                if (--Buffer->Reference == 0)
                    __TransmitterPutBuffer(Ring, Buffer);

                break;
            }
            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET:
                Packet = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                break;

            default:
                Packet = NULL;
                ASSERT(FALSE);
            }

            Fragment->Length = 0;
            Fragment->Offset = 0;

            GranterRevokeAccess(FrontendGetGranter(Frontend),
                                Fragment->Handle);
            Fragment->Handle = NULL;

            Fragment->Extra = FALSE;
            __TransmitterPutFragment(Ring, Fragment);

            if (Packet == NULL) {
                RtlZeroMemory(rsp, sizeof (netif_tx_response_t));
                continue;
            }

            Packet->Value--;

            if (rsp->status != NETIF_RSP_OKAY &&
                Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_PENDING) {
                switch (rsp->status) {
                case NETIF_RSP_DROPPED:
                    Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;
                    break;

                case NETIF_RSP_ERROR:
                    Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_ERROR;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }
            }

            RtlZeroMemory(rsp, sizeof (netif_tx_response_t));

            if (Packet->Value != 0)
                continue;

            if (Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_PENDING)
                Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_OK;

            __TransmitterRingCompletePacket(Ring, Packet);
        }

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;

        Delta = Ring->Front.req_prod_pvt - rsp_cons;
        Delta = __min(Delta, XENVIF_TRANSMITTER_BATCH(Ring));
        Delta = __max(Delta, 1);

        Ring->Shared->rsp_event = rsp_cons + Delta;
    }

#undef XENVIF_TRANSMITTER_BATCH
}

static FORCEINLINE VOID
__TransmitterRingSend(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;

    Transmitter = Ring->Transmitter;

    if (!Ring->Connected)
        return;

    if (Transmitter->Split) {
        ASSERT(Ring->Channel != NULL);

        (VOID) XENBUS_EVTCHN(Send,
                             &Transmitter->EvtchnInterface,
                             Ring->Channel);
    } else {
        PXENVIF_FRONTEND        Frontend;

        ASSERT(Ring->Channel == NULL);
        Frontend = Transmitter->Frontend;

        ReceiverSend(FrontendGetReceiver(Frontend),
                     Ring->Index);
    }
}

static FORCEINLINE VOID
__TransmitterRingPushRequests(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    BOOLEAN                         Notify;

    if (Ring->RequestsPosted == Ring->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __TransmitterRingSend(Ring);

    Ring->RequestsPushed = Ring->RequestsPosted;
}

#define XENVIF_TRANSMITTER_ADVERTISEMENT_COUNT 3

#define XENVIF_TRANSMITTER_LOCK_BIT ((ULONG_PTR)1)

static FORCEINLINE ULONG
__TransmitterReversePacketList(
    IN  PXENVIF_TRANSMITTER_PACKET_V1   *Packet
    )
{
    PXENVIF_TRANSMITTER_PACKET_V1       HeadPacket;
    ULONG                               Count;

    HeadPacket = NULL;
    Count = 0;

    while (*Packet != NULL) {
        PXENVIF_TRANSMITTER_PACKET_V1   Next;

        ASSERT(((ULONG_PTR)*Packet & XENVIF_TRANSMITTER_LOCK_BIT) == 0);

        Next = (*Packet)->Next;

        (*Packet)->Next = HeadPacket;
        HeadPacket = *Packet;

        *Packet = Next;
        Count++;
    }

    *Packet = HeadPacket;

    return Count;
}

static DECLSPEC_NOINLINE VOID
TransmitterRingSwizzle(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    PLIST_ENTRY                     ListEntry;
    LIST_ENTRY                      List;
    ULONG                           Count;

    ASSERT3P(Ring->LockThread, ==, KeGetCurrentThread());

    InitializeListHead(&List);

    New = XENVIF_TRANSMITTER_LOCK_BIT;    
    Old = (ULONG_PTR)InterlockedExchangePointer(&Ring->Lock, (PVOID)New);

    ASSERT(Old & XENVIF_TRANSMITTER_LOCK_BIT);
    ListEntry = (PVOID)(Old & ~XENVIF_TRANSMITTER_LOCK_BIT);

    if (ListEntry == NULL)
        return;

    // Packets are held in the atomic packet list in reverse order
    // so that the most recent is always head of the list. This is
    // necessary to allow addition to the list to be done atomically.

    for (Count = 0; ListEntry != NULL; ++Count) {
        PLIST_ENTRY     NextEntry;

        NextEntry = ListEntry->Blink;
        ListEntry->Flink = ListEntry->Blink = ListEntry;

        InsertHeadList(&List, ListEntry);

        ListEntry = NextEntry;
    }

    ListEntry = List.Flink;
    if (!IsListEmpty(&List)) {
        RemoveEntryList(&List);
        AppendTailList(&Ring->Queued, ListEntry);
        Ring->PacketsQueued += Count;
    }
}

static DECLSPEC_NOINLINE VOID
TransmitterRingSchedule(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_STATE       State;

    if(!Ring->Enabled || Ring->Stopped)
        return;

    State = &Ring->State;

    for (;;) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_PACKET  Packet;
        NTSTATUS                    status;

        if (State->Count != 0) {
            status = __TransmitterRingPostFragments(Ring);
            if (!NT_SUCCESS(status)) {
                Ring->Stopped = TRUE;
                break;
            }
        }

        if (Ring->RequestsPosted - Ring->RequestsPushed >=
            RING_SIZE(&Ring->Front) / 4)
            __TransmitterRingPushRequests(Ring);

        ASSERT3U(State->Count, ==, 0);

        if (Ring->AddressIndex != 0) {
            ULONG   Index = (--Ring->AddressIndex) % Ring->AddressCount;

            switch (Ring->AddressTable[Index].si_family) {
            case AF_INET: {
                IPV4_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv4.sin_addr.s_addr,
                              IPV4_ADDRESS_LENGTH);

                (VOID) __TransmitterRingPrepareArp(Ring, &Address);

                break;
            }
            case AF_INET6: {
                IPV6_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                              IPV6_ADDRESS_LENGTH);

                (VOID) __TransmitterRingPrepareNeighbourAdvertisement(Ring, &Address);

                break;
            }
            default:
                ASSERT(FALSE);
            }

            continue;
        }

        ListEntry = RemoveHeadList(&Ring->Queued);
        if (ListEntry == &Ring->Queued)
            break;

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);
        Packet->ListEntry.Flink = Packet->ListEntry.Blink = NULL;
        Packet->Value = 0;

        status = __TransmitterRingPreparePacket(Ring, Packet);
        if (!NT_SUCCESS(status)) {
            PXENVIF_TRANSMITTER Transmitter;
            PXENVIF_FRONTEND    Frontend;

            Transmitter = Ring->Transmitter;
            Frontend = Transmitter->Frontend;

            ASSERT(status != STATUS_BUFFER_OVERFLOW);

            // Fake that we prapared and sent this packet
            Ring->PacketsPrepared++;
            Ring->PacketsSent++;
            Ring->PacketsFaked++;

            Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;

            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_FRONTEND_ERRORS,
                                       1);

            __TransmitterRingCompletePacket(Ring, Packet);
        }

        ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    }

    __TransmitterRingPushRequests(Ring);
}

static FORCEINLINE VOID
__TransmitterReturnPackets(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  PLIST_ENTRY         List
    )
{
    PXENVIF_FRONTEND        Frontend;
    PXENVIF_VIF_CONTEXT     VifContext;

    Frontend = Transmitter->Frontend;
    VifContext = PdoGetVifContext(FrontendGetPdo(Frontend));

    switch (VifGetVersion(VifContext)) {
    case 1: {
        PXENVIF_TRANSMITTER_PACKET_V1   HeadPacket;
        PXENVIF_TRANSMITTER_PACKET_V1   NextPacket;

        HeadPacket = NextPacket = NULL;

        while (!IsListEmpty(List)) {
            PLIST_ENTRY                 ListEntry;
            PXENVIF_TRANSMITTER_PACKET  Packet;

            ListEntry = RemoveTailList(List);
            ASSERT3P(ListEntry, !=, List);

            Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);
            Packet->ListEntry.Flink = Packet->ListEntry.Blink = NULL;

            HeadPacket = Packet->Cookie;
            HeadPacket->Next = NextPacket;
            NextPacket = HeadPacket;

            HeadPacket->Completion = Packet->Completion;

            __TransmitterPutPacket(Transmitter, Packet);
        }

        if (HeadPacket != NULL)
            VifTransmitterReturnPacketsVersion1(VifContext, HeadPacket);

        break;
    }
    case 2:
        if (!IsListEmpty(List))
            VifTransmitterReturnPackets(VifContext, List);

        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingTryAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    BOOLEAN                         Acquired;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeMemoryBarrier();

    Old = (ULONG_PTR)Ring->Lock & ~XENVIF_TRANSMITTER_LOCK_BIT;
    New = Old | XENVIF_TRANSMITTER_LOCK_BIT;

    Acquired = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (Acquired) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Acquired;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    for (;;) {
        if (__TransmitterRingTryAcquireLock(Ring))
            break;

        _mm_pause();
    }
}

static VOID
TransmitterRingAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingTryReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    BOOLEAN                         Released;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3P(KeGetCurrentThread(), ==, Ring->LockThread);

    Old = XENVIF_TRANSMITTER_LOCK_BIT;
    New = 0;

    Ring->LockThread = NULL;

    KeMemoryBarrier();

    Released = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (!Released) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Released;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    LIST_ENTRY                      List;

    InitializeListHead(&List);

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    // As lock holder it is our responsibility to drain the atomic
    // packet list into the transmit queue before we actually drop the
    // lock. This may, of course, take a few attempts as another
    // thread could be simuntaneously adding to the list.

    do {
        PLIST_ENTRY     ListEntry;

        TransmitterRingSwizzle(Ring);
        TransmitterRingSchedule(Ring);

        ListEntry = Ring->Completed.Flink;
        if (!IsListEmpty(&Ring->Completed)) {
            RemoveEntryList(&Ring->Completed);
            InitializeListHead(&Ring->Completed);
            AppendTailList(&List, ListEntry);
        }
    } while (!__TransmitterRingTryReleaseLock(Ring));

    if (!IsListEmpty(&List)) {
        PXENVIF_TRANSMITTER Transmitter;

        Transmitter = Ring->Transmitter;

        __TransmitterReturnPackets(Transmitter,
                                   &List);
    }
}

static DECLSPEC_NOINLINE VOID
TransmitterRingReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingNotify(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
    TransmitterRingPoll(Ring);
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE BOOLEAN
__TransmitterRingUnmask(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    BOOLEAN                         Pending;

    Transmitter = Ring->Transmitter;

    Pending = (Ring->Connected) ?
              XENBUS_EVTCHN(Unmask,
                            &Transmitter->EvtchnInterface,
                            Ring->Channel,
                            FALSE) :
              FALSE;

    return Pending;
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
static VOID
TransmitterRingDpc(
    IN  PKDPC                   Dpc,
    IN  PVOID                   Context,
    IN  PVOID                   Argument1,
    IN  PVOID                   Argument2
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Context;
    PXENVIF_TRANSMITTER         Transmitter;
    BOOLEAN                     Pending;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Ring != NULL);

    Transmitter = Ring->Transmitter;

    do {
        if (Ring->Enabled) {
            ASSERT(Transmitter->Split);
            __TransmitterRingNotify(Ring);
        }

        Pending = __TransmitterRingUnmask(Ring);
    } while (Pending);
}

KSERVICE_ROUTINE    TransmitterRingEvtchnCallback;

BOOLEAN
TransmitterRingEvtchnCallback(
    IN  PKINTERRUPT         InterruptObject,
    IN  PVOID               Argument
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Ring != NULL);

    Ring->Events++;

    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
        Ring->Dpcs++;

    return TRUE;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENVIF_TRANSMITTER_WATCHDOG_PERIOD  30

static NTSTATUS
TransmitterRingWatchdog(
    IN  PXENVIF_THREAD          Self,
    IN  PVOID                   Context
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Context;
    LARGE_INTEGER               Timeout;
    ULONG                       PacketsQueued;

    Trace("====>\n");

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENVIF_TRANSMITTER_WATCHDOG_PERIOD));
    PacketsQueued = 0;

    for (;;) { 
        PKEVENT Event;
        KIRQL   Irql;

        Event = ThreadGetEvent(Self);

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     &Timeout);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        __TransmitterRingAcquireLock(Ring);

        if (Ring->Enabled) {
            if (Ring->PacketsQueued == PacketsQueued &&
                Ring->PacketsCompleted != PacketsQueued) {
                PXENVIF_TRANSMITTER Transmitter;

                Transmitter = Ring->Transmitter;

                XENBUS_DEBUG(Trigger,
                             &Transmitter->DebugInterface,
                             Ring->DebugCallback);

                // Try to move things along
                __TransmitterRingSend(Ring);
                TransmitterRingPoll(Ring);
            }

            PacketsQueued = Ring->PacketsQueued;
        }

        __TransmitterRingReleaseLock(Ring);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TransmitterRingUpdateAddressTable(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PSOCKADDR_INET              Table,
    IN  ULONG                       Count
    )
{
    NTSTATUS                        status;

    __TransmitterRingAcquireLock(Ring);

    if (Ring->AddressCount != 0) {
        Ring->AddressCount = 0;

        ASSERT(Ring->AddressTable != NULL);
        __TransmitterFree(Ring->AddressTable);
        Ring->AddressTable = NULL;
    }

    if (Count == 0)
        goto done;

    Ring->AddressTable = __TransmitterAllocate(sizeof (SOCKADDR_INET) * Count);

    status = STATUS_NO_MEMORY;
    if (Ring->AddressTable == NULL)
        goto fail1;

    RtlCopyMemory(Ring->AddressTable, Table, sizeof (SOCKADDR_INET) * Count);
    Ring->AddressCount = Count;

    // Re-advertize if we were part way through
    if (Ring->AddressIndex != 0)
        Ring->AddressIndex = Ring->AddressCount * 3;

done:
    __TransmitterRingReleaseLock(Ring);

    return;

fail1:
    Error("fail1 (%08x)\n", status);

    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingAdvertiseAddresses(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
    Ring->AddressIndex = Ring->AddressCount * 3;
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE NTSTATUS
__TransmitterRingInitialize(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  ULONG                       Index,
    OUT PXENVIF_TRANSMITTER_RING    *Ring
    )
{
    PXENVIF_FRONTEND                Frontend;
    CHAR                            Name[MAXNAMELEN];
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    *Ring = __TransmitterAllocate(sizeof (XENVIF_TRANSMITTER_RING));

    status = STATUS_NO_MEMORY;
    if (*Ring == NULL)
        goto fail1;

    (*Ring)->Transmitter = Transmitter;
    (*Ring)->Index = Index;

    (*Ring)->Path = FrontendFormatPath(Frontend, Index);
    if ((*Ring)->Path == NULL)
        goto fail2;

    InitializeListHead(&(*Ring)->Queued);
    InitializeListHead(&(*Ring)->Completed);

    KeInitializeDpc(&(*Ring)->Dpc, TransmitterRingDpc, *Ring);

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_buffer",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail3;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_BUFFER),
                          0,
                          TransmitterBufferCtor,
                          TransmitterBufferDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          *Ring,
                          &(*Ring)->BufferCache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_req_id",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail5;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_RANGE_SET(Create,
                              &Transmitter->RangeSetInterface,
                              Name,
                              &(*Ring)->RangeSet);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_RANGE_SET(Put,
                              &Transmitter->RangeSetInterface,
                              (*Ring)->RangeSet,
                              1,
                              XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_fragment",
                                (*Ring)->Path);
    if (!NT_SUCCESS(status))
        goto fail8;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_FRAGMENT),
                          0,
                          TransmitterFragmentCtor,
                          TransmitterFragmentDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          (*Ring),
                          &(*Ring)->FragmentCache);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = ThreadCreate(TransmitterRingWatchdog,
                          *Ring,
                          &(*Ring)->WatchdogThread);
    if (!NT_SUCCESS(status))
        goto fail10;

    return STATUS_SUCCESS;

fail10:
    Error("fail10\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->FragmentCache);
    (*Ring)->FragmentCache = NULL;

fail9:
    Error("fail9\n");

fail8:
    Error("fail8\n");

    (VOID) XENBUS_RANGE_SET(Get,
                            &Transmitter->RangeSetInterface,
                            (*Ring)->RangeSet,
                            1,
                            XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);

fail7:
    Error("fail7\n");

    XENBUS_RANGE_SET(Destroy,
                     &Transmitter->RangeSetInterface,
                     (*Ring)->RangeSet);
    (*Ring)->RangeSet = NULL;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->BufferCache);
    (*Ring)->BufferCache = NULL;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    RtlZeroMemory(&(*Ring)->Dpc, sizeof (KDPC));

    RtlZeroMemory(&(*Ring)->Queued, sizeof (LIST_ENTRY));
    RtlZeroMemory(&(*Ring)->Completed, sizeof (LIST_ENTRY));

    FrontendFreePath(Frontend, (*Ring)->Path);
    (*Ring)->Path = NULL;

fail2:
    Error("fail2\n");

    (*Ring)->Index = 0;
    (*Ring)->Transmitter = NULL;

    ASSERT(IsZeroMemory(*Ring, sizeof (XENVIF_TRANSMITTER_RING)));
    __TransmitterFree(*Ring);
    *Ring = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingConnect(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PFN_NUMBER                      Pfn;
    BOOLEAN                         Pending;
    CHAR                            Name[MAXNAMELEN];
    NTSTATUS                        status;

    ASSERT(!Ring->Connected);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
        goto fail1;

    Ring->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Ring->Shared != NULL);

    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE);
    ASSERT3P(Ring->Front.sring, ==, Ring->Shared);

    Pfn = MmGetMdlPfnArray(Ring->Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 FALSE,
                                 &Ring->Handle);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                __MODULE__ "|TRANSMITTER[%u]",
                                Ring->Index);
    if (!NT_SUCCESS(status))
        goto fail3;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    if (Transmitter->Split) {
        Ring->Channel = XENBUS_EVTCHN(Open,
                                      &Transmitter->EvtchnInterface,
                                      XENBUS_EVTCHN_TYPE_UNBOUND,
                                      TransmitterRingEvtchnCallback,
                                      Ring,
                                      FrontendGetBackendDomain(Frontend),
                                      TRUE);

        status = STATUS_UNSUCCESSFUL;
        if (Ring->Channel == NULL)
            goto fail4;

        if (FrontendGetQueueCount(Frontend) > 1) {
            (VOID) XENBUS_EVTCHN(Bind,
                                 &Transmitter->EvtchnInterface,
                                 Ring->Channel,
                                 Ring->Index);

            KeSetTargetProcessorDpc(&Ring->Dpc,
                                    (CCHAR)Ring->Index);
        }

        Pending = XENBUS_EVTCHN(Unmask,
                                &Transmitter->EvtchnInterface,
                                Ring->Channel,
                                FALSE);

        if (Pending)
            XENBUS_EVTCHN(Trigger,
                          &Transmitter->EvtchnInterface,
                          Ring->Channel);
    }

    status = XENBUS_DEBUG(Register,
                          &Transmitter->DebugInterface,
                          Name,
                          TransmitterRingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    Ring->Connected = TRUE;

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    XENBUS_EVTCHN(Close,
                  &Transmitter->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;

    Ring->Events = 0;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Ring->Handle);
    Ring->Handle = NULL;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingStoreWrite(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Port;
    PCHAR                           Path;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Path = (FrontendGetQueueCount(Frontend) == 1 && Ring->Index == 0) ?
                    FrontendGetPath(Frontend) :
                    Ring->Path;

    status = XENBUS_STORE(Printf,
                          &Transmitter->StoreInterface,
                          Transaction,
                          Path,
                          "tx-ring-ref",
                          "%u",
                          GranterGetReference(FrontendGetGranter(Frontend),
                                              Ring->Handle));

    if (!NT_SUCCESS(status))
        goto fail1;

    if (!Transmitter->Split)
        goto done;

    Port = XENBUS_EVTCHN(GetPort,
                         &Transmitter->EvtchnInterface,
                         Ring->Channel);

    status = XENBUS_STORE(Printf,
                          &Transmitter->StoreInterface,
                          Transaction,
                          Path,
                          "event-channel-tx",
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

static FORCEINLINE NTSTATUS
__TransmitterRingEnable(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);
    Ring->Enabled = TRUE;

    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
        Ring->Dpcs++;

    __TransmitterRingReleaseLock(Ring);

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TransmitterRingDisable(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{    
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PCHAR                           Buffer;
    XenbusState                     State;
    ULONG                           Attempt;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    __TransmitterRingAcquireLock(Ring);

    ASSERT(Ring->Enabled);
    Ring->Enabled = FALSE;

    // Release any fragments associated with a pending packet
    Packet = __TransmitterRingUnpreparePacket(Ring);

    // Put any packet back on the head of the queue
    if (Packet != NULL) {
        InsertHeadList(&Ring->Queued, &Packet->ListEntry);
    }

    Ring->AddressIndex = 0;

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "state",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        State = XenbusStateUnknown;
    } else {
        State = (XenbusState)strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Attempt = 0;
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);
    while (Ring->ResponsesProcessed != Ring->RequestsPushed) {
        Attempt++;
        ASSERT(Attempt < 100);

        TransmitterRingPoll(Ring);

        if (State != XenbusStateConnected)
            __TransmitterRingFakeResponses(Ring);

        // We are waiting for a watch event at DISPATCH_LEVEL so
        // it is our responsibility to poll the store ring.
        XENBUS_STORE(Poll,
                     &Transmitter->StoreInterface);

        KeStallExecutionProcessor(1000);    // 1ms
    }

    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingDisconnect(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Transmitter->Split = FALSE;

    if (Ring->Channel != NULL) {
        XENBUS_EVTCHN(Close,
                      &Transmitter->EvtchnInterface,
                      Ring->Channel);
        Ring->Channel = NULL;

        Ring->Events = 0;
    }

    ASSERT3U(Ring->ResponsesProcessed, ==, Ring->RequestsPushed);
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);

    Ring->ResponsesProcessed = 0;
    Ring->RequestsPushed = 0;
    Ring->RequestsPosted = 0;

    XENBUS_DEBUG(Deregister,
                 &Transmitter->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Ring->Handle);
    Ring->Handle = NULL;

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

}

static FORCEINLINE VOID
__TransmitterRingTeardown(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Ring->Dpcs = 0;
    RtlZeroMemory(&Ring->Dpc, sizeof (KDPC));

    ASSERT3U(Ring->PacketsCompleted, ==, Ring->PacketsSent);
    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    Ring->PacketsCompleted = 0;
    Ring->PacketsSent = 0;
    Ring->PacketsCopied = 0;
    Ring->PacketsGranted = 0;
    Ring->PacketsFaked = 0;
    Ring->PacketsUnprepared = 0;
    Ring->PacketsPrepared = 0;
    Ring->PacketsQueued = 0;

    if (Ring->AddressCount != 0) {
        ASSERT(Ring->AddressTable != NULL);
        __TransmitterFree(Ring->AddressTable);
    }

    Ring->AddressTable = NULL;
    Ring->AddressCount = 0;

    ThreadAlert(Ring->WatchdogThread);
    ThreadJoin(Ring->WatchdogThread);
    Ring->WatchdogThread = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->FragmentCache);
    Ring->FragmentCache = NULL;

    (VOID) XENBUS_RANGE_SET(Get,
                            &Transmitter->RangeSetInterface,
                            Ring->RangeSet,
                            1,
                            XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);

    XENBUS_RANGE_SET(Destroy,
                     &Transmitter->RangeSetInterface,
                     Ring->RangeSet);
    Ring->RangeSet = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->BufferCache);
    Ring->BufferCache = NULL;

    ASSERT(IsListEmpty(&Ring->Queued));
    RtlZeroMemory(&Ring->Queued, sizeof (LIST_ENTRY));

    ASSERT(IsListEmpty(&Ring->Completed));
    RtlZeroMemory(&Ring->Completed, sizeof (LIST_ENTRY));

    FrontendFreePath(Frontend, Ring->Path);
    Ring->Path = NULL;

    Ring->Index = 0;
    Ring->Transmitter = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof (XENVIF_TRANSMITTER_RING)));
    __TransmitterFree(Ring);
}

static FORCEINLINE VOID
__TransmitterRingQueuePackets(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PLIST_ENTRY                 List
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       LockBit;
    ULONG_PTR                       New;

    do {
        Old = (ULONG_PTR)Ring->Lock;
        LockBit = Old & XENVIF_TRANSMITTER_LOCK_BIT;

        List->Flink->Blink = (PVOID)(Old & ~XENVIF_TRANSMITTER_LOCK_BIT);
        New = (ULONG_PTR)List->Blink;
        ASSERT((New & XENVIF_TRANSMITTER_LOCK_BIT) == 0);
        New |= LockBit;
    } while ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) != Old);

    // __TransmitterRingReleaseLock() drains the atomic packet list into the transmit queue therefore,
    // after adding to the list we need to attempt to grab and release the lock. If we can't
    // grab it then that's ok because whichever thread is holding it will have to call
    // __TransmitterRingReleaseLock() and will therefore drain the atomic packet list.

    if (__TransmitterRingTryAcquireLock(Ring))
        __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingAbortPackets(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);

    TransmitterRingSwizzle(Ring);

    while (!IsListEmpty(&Ring->Queued)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_PACKET  Packet;
        
        ListEntry = RemoveHeadList(&Ring->Queued);
        ASSERT3P(ListEntry, !=, &Ring->Queued);

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);
        Packet->ListEntry.Flink = Packet->ListEntry.Blink = NULL;

        // Fake that we prapared and sent this packet
        Ring->PacketsPrepared++;
        Ring->PacketsSent++;
        Ring->PacketsFaked++;

        Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;

        __TransmitterRingCompletePacket(Ring, Packet);
    }

    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    ASSERT3P((ULONG_PTR)Ring->Lock, ==, XENVIF_TRANSMITTER_LOCK_BIT);
    __TransmitterRingReleaseLock(Ring);
}

static VOID
TransmitterDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "OFFSETS: Offset @ %ld Length @ %ld Mdl @ %ld\n",
                 Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_OFFSET_OFFSET],
                 Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_LENGTH_OFFSET],
                 Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_MDL_OFFSET]);
}

NTSTATUS
TransmitterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_TRANSMITTER *Transmitter
    )
{
    HANDLE                  ParametersKey;
    ULONG                   Index;
    ULONG                   Count;
    NTSTATUS                status;

    Count = DriverGetMaximumQueueCount();
    *Transmitter = __TransmitterAllocate(sizeof (XENVIF_TRANSMITTER));

    status = STATUS_NO_MEMORY;
    if (*Transmitter == NULL)
        goto fail1;

    ParametersKey = DriverGetParametersKey();

    (*Transmitter)->DisableIpVersion4Gso = 0;
    (*Transmitter)->DisableIpVersion6Gso = 0;
    (*Transmitter)->AlwaysCopy = 0;
    (*Transmitter)->Split = FALSE;

    if (ParametersKey != NULL) {
        ULONG   TransmitterDisableIpVersion4Gso;
        ULONG   TransmitterDisableIpVersion6Gso;
        ULONG   TransmitterAlwaysCopy;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableIpVersion4Gso",
                                         &TransmitterDisableIpVersion4Gso);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableIpVersion4Gso = TransmitterDisableIpVersion4Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableIpVersion6Gso",
                                         &TransmitterDisableIpVersion6Gso);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableIpVersion6Gso = TransmitterDisableIpVersion6Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterAlwaysCopy",
                                         &TransmitterAlwaysCopy);
        if (NT_SUCCESS(status))
            (*Transmitter)->AlwaysCopy = TransmitterAlwaysCopy;
    }

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->StoreInterface);

    FdoGetRangeSetInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                            &(*Transmitter)->RangeSetInterface);

    FdoGetCacheInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->CacheInterface);

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Transmitter)->EvtchnInterface);

    (*Transmitter)->Frontend = Frontend;
    KeInitializeSpinLock(&(*Transmitter)->Lock);

    status = XENBUS_RANGE_SET(Acquire, &(*Transmitter)->RangeSetInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_CACHE(Acquire, &(*Transmitter)->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);
    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        status = __TransmitterRingInitialize(*Transmitter, Index, &Ring);
        if (!NT_SUCCESS(status))
            goto fail4;

        (*Transmitter)->Rings[Index] = Ring;
    }

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    for (Index = 0; Index < MAXIMUM_PROCESSORS; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = (*Transmitter)->Rings[Index];
        (*Transmitter)->Rings[Index] = NULL;

        if (Ring == NULL)
            continue; // ensure all rings are destroyed

        __TransmitterRingTeardown(Ring);
    }

    XENBUS_CACHE(Release, &(*Transmitter)->CacheInterface);

fail3:
    Error("fail3\n");

    XENBUS_RANGE_SET(Release, &(*Transmitter)->RangeSetInterface);

fail2:
    Error("fail2\n");

    (*Transmitter)->Frontend = NULL;

    RtlZeroMemory(&(*Transmitter)->Lock,
                  sizeof (KSPIN_LOCK));

    RtlZeroMemory(&(*Transmitter)->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    (*Transmitter)->DisableIpVersion4Gso = 0;
    (*Transmitter)->DisableIpVersion6Gso = 0;
    (*Transmitter)->AlwaysCopy = 0;
    
    ASSERT(IsZeroMemory(*Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(*Transmitter);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterConnect(
    IN  PXENVIF_TRANSMITTER     Transmitter
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    ULONG                       Index;
    ULONG                       Count;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    status = XENBUS_DEBUG(Acquire, &Transmitter->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Transmitter->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &Transmitter->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          "packet_cache",
                          sizeof (XENVIF_TRANSMITTER_PACKET),
                          XENVIF_PACKET_CACHE_RESERVATION,
                          TransmitterPacketCtor,
                          TransmitterPacketDtor,
                          TransmitterPacketAcquireLock,
                          TransmitterPacketReleaseLock,
                          Transmitter,
                          &Transmitter->PacketCache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-split-event-channels",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Transmitter->Split = FALSE;
    } else {
        Transmitter->Split = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Count = FrontendGetQueueCount(Frontend);
    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);

    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            break;

        status = __TransmitterRingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail5;
    }    

    status = XENBUS_DEBUG(Register,
                          &Transmitter->DebugInterface,
                          __MODULE__ "|TRANSMITTER",
                          TransmitterDebugCallback,
                          Transmitter,
                          &Transmitter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail6;

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    for (Index = 0; Index < MAXIMUM_PROCESSORS; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            continue; // ensure all rings are destroyed

        __TransmitterRingDisconnect(Ring);
    }

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Transmitter->PacketCache);
    Transmitter->PacketCache = NULL;

fail4:
    Error("fail4\n");

    XENBUS_EVTCHN(Release, &Transmitter->EvtchnInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Transmitter->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Transmitter->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterStoreWrite(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    NTSTATUS                        status;
    ULONG                           Index;
    ULONG                           Count;

    Count = FrontendGetQueueCount(Transmitter->Frontend);
    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);

    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            break;

        status = __TransmitterRingStoreWrite(Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto fail1;
    }    

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterEnable(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    ULONG                   Index;
    ULONG                   Count;

    Count = FrontendGetQueueCount(Transmitter->Frontend);
    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);

    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            break;

        __TransmitterRingEnable(Ring);
    }    

    return STATUS_SUCCESS;
}

VOID
TransmitterDisable(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    ULONG                   Index;
    ULONG                   Count;

    Count = FrontendGetQueueCount(Transmitter->Frontend);
    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);

    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            break;

        __TransmitterRingDisable(Ring);
    }
}

VOID
TransmitterDisconnect(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    ULONG                   Index;
    ULONG                   Count;

    Frontend = Transmitter->Frontend;

    Transmitter->Split = FALSE;

    XENBUS_DEBUG(Deregister,
                 &Transmitter->DebugInterface,
                 Transmitter->DebugCallback);
    Transmitter->DebugCallback = NULL;

    Count = FrontendGetQueueCount(Frontend);
    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);

    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            break;

        __TransmitterRingDisconnect(Ring);
    }

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Transmitter->PacketCache);
    Transmitter->PacketCache = NULL;

    XENBUS_STORE(Release, &Transmitter->StoreInterface);

    XENBUS_DEBUG(Release, &Transmitter->DebugInterface);

    XENBUS_EVTCHN(Release, &Transmitter->EvtchnInterface);
}

VOID
TransmitterTeardown(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    ULONG                   Index;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    RtlZeroMemory(Transmitter->Offset,
                  sizeof (LONG_PTR) *  XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT); 

    for (Index = 0; Index < MAXIMUM_PROCESSORS; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        Transmitter->Rings[Index] = NULL;

        if (Ring == NULL)
            continue; // ensure all rings are destroyed

        __TransmitterRingTeardown(Ring);
    }

    XENBUS_CACHE(Release, &Transmitter->CacheInterface);

    XENBUS_RANGE_SET(Release, &Transmitter->RangeSetInterface);

    Transmitter->Frontend = NULL;
    Transmitter->Split = FALSE;

    RtlZeroMemory(&Transmitter->Lock,
                  sizeof (KSPIN_LOCK));

    RtlZeroMemory(&Transmitter->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&Transmitter->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    RtlZeroMemory(&Transmitter->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Transmitter->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Transmitter->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    Transmitter->DisableIpVersion4Gso = 0;
    Transmitter->DisableIpVersion6Gso = 0;
    Transmitter->AlwaysCopy = 0;

    ASSERT(IsZeroMemory(Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(Transmitter);
}

VOID
TransmitterUpdateAddressTable(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  SOCKADDR_INET           Table[],
    IN  ULONG                   Count
    )
{
    KIRQL                       Irql;
    PXENVIF_TRANSMITTER_RING    Ring;

    // Make sure we don't suspend
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    // Use the first ring for address advertisment
    Ring = Transmitter->Rings[0];
    ASSERT3U(Ring, !=, NULL);

    __TransmitterRingUpdateAddressTable(Ring, Table, Count);

    KeLowerIrql(Irql);
}

VOID
TransmitterAdvertiseAddresses(
    IN  PXENVIF_TRANSMITTER     Transmitter
    )
{
    PXENVIF_TRANSMITTER_RING    Ring;

    // Use the first ring for address advertisment
    Ring = Transmitter->Rings[0];
    ASSERT3U(Ring, !=, NULL);

    __TransmitterRingAdvertiseAddresses(Ring);
}

NTSTATUS
TransmitterSetPacketOffset(
    IN  PXENVIF_TRANSMITTER                 Transmitter,
    IN  XENVIF_TRANSMITTER_PACKET_OFFSET    Type,
    IN  LONG_PTR                            Value
    )
{
    NTSTATUS                                status;

    status = STATUS_INVALID_PARAMETER;
    if (Type >= XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT)
        goto fail1;

    Transmitter->Offset[Type] = Value;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static BOOLEAN
__TransmitterGetPacketHeadersPullup(
    IN      PVOID                   Argument,
    IN      PUCHAR                  DestinationVa,
    IN OUT  PXENVIF_PACKET_PAYLOAD  Payload,
    IN      ULONG                   Length
    )
{
    PMDL                            Mdl;
    ULONG                           Offset;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;

    if (Payload->Length < Length)
        goto fail1;

    Payload->Length -= Length;

    while (Length != 0) {
        PUCHAR  MdlMappedSystemVa;
        ULONG   MdlByteCount;
        ULONG   CopyLength;

        ASSERT(Mdl != NULL);

        MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ASSERT(MdlMappedSystemVa != NULL);

        MdlMappedSystemVa += Offset;

        MdlByteCount = Mdl->ByteCount - Offset;

        CopyLength = __min(MdlByteCount, Length);

        RtlCopyMemory(DestinationVa, MdlMappedSystemVa, CopyLength);
        DestinationVa += CopyLength;

        Offset += CopyLength;
        Length -= CopyLength;

        MdlByteCount -= CopyLength;
        if (MdlByteCount == 0) {
            Mdl = Mdl->Next;
            Offset = 0;
        }
    }

    Payload->Mdl = Mdl;
    Payload->Offset = Offset;

    return TRUE;

fail1:
    Error("fail1\n");

    return FALSE;
}

NTSTATUS
TransmitterGetPacketHeaders(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet,
    OUT PVOID                       Headers,
    OUT PXENVIF_PACKET_INFO         Info
    )
{
    XENVIF_PACKET_PAYLOAD           Payload;
    NTSTATUS                        status;

    Payload.Mdl = Packet->Mdl;
    Payload.Offset = Packet->Offset;
    Payload.Length = Packet->Length;

    status = ParsePacket(Headers,
                         __TransmitterGetPacketHeadersPullup,
                         Transmitter,
                         &Payload,
                         Info);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
TransmitterQueuePacketsVersion1(
    IN  PXENVIF_TRANSMITTER             Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET_V1   HeadPacket
    )
{
#define OFFSET_EXISTS(_Transmitter, _Packet, _Type)                                         \
    ((_Transmitter)->Offset[XENVIF_TRANSMITTER_PACKET_ ## _Type ## _OFFSET] != 0)

#define OFFSET(_Transmitter, _Packet, _Type)                                                \
        ((OFFSET_EXISTS(_Transmitter, _Packet, _Type)) ?                                    \
         (PVOID)((PUCHAR)(_Packet) +                                                        \
                 (_Transmitter)->Offset[XENVIF_TRANSMITTER_PACKET_ ## _Type ## _OFFSET]) :  \
         NULL)

    LIST_ENTRY                          List;
    PXENVIF_FRONTEND                    Frontend;
    PXENVIF_VIF_CONTEXT                 VifContext;

    Frontend = Transmitter->Frontend;
    VifContext = PdoGetVifContext(FrontendGetPdo(Frontend));

    ASSERT3U(VifGetVersion(VifContext), ==, 1);

    InitializeListHead(&List);

    while (HeadPacket != NULL) {
        PXENVIF_TRANSMITTER_PACKET      Packet;

        Packet = __TransmitterGetPacket(Transmitter);
        if (Packet == NULL)
            break;

        Packet->Cookie = HeadPacket;
        Packet->Send = HeadPacket->Send;

        ASSERT(OFFSET_EXISTS(Transmitter, HeadPacket, MDL));
        Packet->Mdl = *(PMDL *)OFFSET(Transmitter, HeadPacket, MDL);

        if (OFFSET_EXISTS(Transmitter, HeadPacket, OFFSET))
            Packet->Offset = *(PULONG)OFFSET(Transmitter, HeadPacket, OFFSET);
        else
            Packet->Offset = 0;

        ASSERT(OFFSET_EXISTS(Transmitter, HeadPacket, LENGTH));
        Packet->Length = *(PULONG)OFFSET(Transmitter, HeadPacket, LENGTH);

        // Packets from legacy clients go to queue 0.
        Packet->Value = 0;

        InsertTailList(&List, &Packet->ListEntry);

        HeadPacket = HeadPacket->Next;
    }

    if (!IsListEmpty(&List))
        TransmitterQueuePackets(Transmitter, &List);

    if (HeadPacket != NULL)
        VifTransmitterReturnPacketsVersion1(VifContext,
                                            HeadPacket);

#undef OFFSET
#undef OFFSET_EXISTS
}

static FORCEINLINE ULONG
__GetQueue(
    IN  ULONG       QueueCount,
    IN  ULONG       HashValue
    )
{
    return HashValue % QueueCount;
}

VOID
TransmitterQueuePackets(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  PLIST_ENTRY         List
    )
{
    PXENVIF_TRANSMITTER_RING    Ring;
    PXENVIF_FRONTEND            Frontend;
    ULONG                       QueueCount;

    Frontend = Transmitter->Frontend;

    QueueCount = FrontendGetQueueCount(Frontend);

    if (QueueCount == 1) {
        Ring = Transmitter->Rings[0];
        ASSERT3P(Ring, !=, NULL);

        __TransmitterRingQueuePackets(Ring, List);
    } else {
        while (!IsListEmpty(List)) {
            PXENVIF_TRANSMITTER_PACKET  Packet;
            PLIST_ENTRY                 ListEntry;
            LIST_ENTRY                  ListHead;
            ULONG                       Queue;

            InitializeListHead(&ListHead);

            ListEntry = List->Flink;
            Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);
            Queue = __GetQueue(QueueCount, Packet->Value);

            (VOID) RemoveHeadList(List);
            InsertTailList(&ListHead, ListEntry);

            while (!IsListEmpty(List)) {
                ListEntry = List->Flink;
                Packet = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_PACKET, ListEntry);
                if (Queue != __GetQueue(QueueCount, Packet->Value))
                    break;

                (VOID) RemoveHeadList(List);
                InsertTailList(&ListHead, ListEntry);
            }

            Ring = Transmitter->Rings[Queue];
            ASSERT3P(Ring, !=, NULL);

            __TransmitterRingQueuePackets(Ring, &ListHead);
        }
    }
}

VOID
TransmitterAbortPackets(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    ULONG                   Index;
    ULONG                   Count;
    KIRQL                   Irql;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    Count = FrontendGetQueueCount(Transmitter->Frontend);
    ASSERT3U(Count, <=, MAXIMUM_PROCESSORS);

    for (Index = 0; Index < Count; ++Index) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = Transmitter->Rings[Index];
        if (Ring == NULL)
            break;

        __TransmitterRingAbortPackets(Ring);
    }    

    KeLowerIrql(Irql);
}

VOID
TransmitterQueryRingSize(
    IN  PXENVIF_TRANSMITTER Transmitter,
    OUT PULONG              Size
    )
{
    UNREFERENCED_PARAMETER(Transmitter);

    *Size = XENVIF_TRANSMITTER_RING_SIZE;
}

VOID
TransmitterRingNotify(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  ULONG               Index
    )
{
    PXENVIF_TRANSMITTER_RING    Ring;

    if (Index >= MAXIMUM_PROCESSORS)
        return;

    Ring = Transmitter->Rings[Index];
    if (Ring == NULL)
        return;

    __TransmitterRingNotify(Ring);
}

VOID
TransmitterQueryOffloadOptions(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_FRONTEND                Frontend;
    PCHAR                           Buffer;
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    Options->Value = 0;

    Options->OffloadTagManipulation = 1;

    if (Transmitter->DisableIpVersion4Gso == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv4",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion4LargePacket = 0;
    } else {
        Options->OffloadIpVersion4LargePacket = (USHORT)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    if (Transmitter->DisableIpVersion6Gso == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv6",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion6LargePacket = 0;
    } else {
        Options->OffloadIpVersion6LargePacket = (USHORT)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Options->OffloadIpVersion4HeaderChecksum = 1;

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-no-csum-offload",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion4TcpChecksum = 1;
        Options->OffloadIpVersion4UdpChecksum = 1;
    } else {
        BOOLEAN Flag;

        Flag = (BOOLEAN)strtol(Buffer, NULL, 2);

        Options->OffloadIpVersion4TcpChecksum = (Flag) ? 0 : 1;
        Options->OffloadIpVersion4UdpChecksum = (Flag) ? 0 : 1;

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-ipv6-csum-offload",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion6TcpChecksum = 0;
        Options->OffloadIpVersion6UdpChecksum = 0;
    } else {
        BOOLEAN Flag;

        Flag = (BOOLEAN)strtol(Buffer, NULL, 2);

        Options->OffloadIpVersion6TcpChecksum = (Flag) ? 1 : 0;
        Options->OffloadIpVersion6UdpChecksum = (Flag) ? 1 : 0;

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }
}

#define XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE  ((1 << (RTL_FIELD_SIZE(netif_tx_request_t, size) * 8)) - 1)

#define XENVIF_TRANSMITTER_MAXIMUM_TCPV4_PAYLOAD_SIZE   (XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE -  \
                                                         sizeof (ETHERNET_HEADER) -             \
                                                         MAXIMUM_IPV4_HEADER_LENGTH -           \
                                                         MAXIMUM_TCP_HEADER_LENGTH)

#define XENVIF_TRANSMITTER_MAXIMUM_TCPV6_PAYLOAD_SIZE   (XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE -  \
                                                         sizeof (ETHERNET_HEADER) -             \
                                                         MAXIMUM_IPV6_HEADER_LENGTH -           \
                                                         MAXIMUM_IPV6_OPTIONS_LENGTH -          \
                                                         MAXIMUM_TCP_HEADER_LENGTH)

VOID
TransmitterQueryLargePacketSize(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  UCHAR                   Version,
    OUT PULONG                  Size
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    ULONG                       OffloadIpLargePacket;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    if (Version == 4) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv4",
                              &Buffer);
    } else if (Version == 6) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv6",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        OffloadIpLargePacket = 0;
    } else {
        OffloadIpLargePacket = (ULONG)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    // The OffloadParity certification test requires that we have a single LSO size for IPv4 and IPv6 packets
    *Size = (OffloadIpLargePacket) ?
            __min(XENVIF_TRANSMITTER_MAXIMUM_TCPV4_PAYLOAD_SIZE,
                 XENVIF_TRANSMITTER_MAXIMUM_TCPV6_PAYLOAD_SIZE) :
            0;
}
