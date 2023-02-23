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
#include <stdarg.h>
#include <xen.h>

#include "bus.h"
#include "fdo.h"
#include "pdo.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

typedef struct _XENVIF_BUS_CONTEXT {
    LONG                    References;
    PXENVIF_PDO             Pdo;
    ULONG                   InterceptDmaAdapter;
} XENVIF_BUS_CONTEXT, *PXENVIF_BUS_CONTEXT;

#define BUS_TAG 'SUB'

static FORCEINLINE PVOID
__BusAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, BUS_TAG);
}

static FORCEINLINE VOID
__BusFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, BUS_TAG);
}

static VOID
BusReference(
    IN  PVOID           _Context
    )
{
    PXENVIF_BUS_CONTEXT Context = _Context;

    InterlockedIncrement(&Context->References);
}

static VOID
BusDereference(
    IN  PVOID           _Context
    )
{
    PXENVIF_BUS_CONTEXT Context = _Context;

    ASSERT(Context->References != 0);
    InterlockedDecrement(&Context->References);
}

static
__drv_functionClass(TRANSLATE_BUS_ADDRESS)
BOOLEAN
BusTranslateAddress(
    IN      PVOID               _Context,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    )
{
    PXENVIF_BUS_CONTEXT         Context = _Context;

    return PdoTranslateBusAddress(Context->Pdo,
                                  BusAddress,
                                  Length,
                                  AddressSpace,
                                  TranslatedAddress);
}

static
__drv_functionClass(GET_DMA_ADAPTER)
PDMA_ADAPTER
BusGetDmaAdapter(
    IN  PVOID               _Context,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    )
{
    PXENVIF_BUS_CONTEXT     Context = _Context;

    return PdoGetDmaAdapter(Context->Pdo,
                            DeviceDescriptor,
                            NumberOfMapRegisters);
}

static
__drv_functionClass(GET_SET_DEVICE_DATA)
ULONG
BusSetData(
    IN  PVOID           _Context,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    )
{
    PXENVIF_BUS_CONTEXT Context = _Context;

    return PdoSetBusData(Context->Pdo,
                         DataType,
                         Buffer,
                         Offset,
                         Length);
}

static
__drv_functionClass(GET_SET_DEVICE_DATA)
ULONG
BusGetData(
    IN  PVOID           _Context,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    )
{
    PXENVIF_BUS_CONTEXT Context = _Context;

    return PdoGetBusData(Context->Pdo,
                         DataType,
                         Buffer,
                         Offset,
                         Length);
}

NTSTATUS
BusInitialize(
    IN  PXENVIF_PDO             Pdo,
    OUT PBUS_INTERFACE_STANDARD Interface
    )
{
    PXENVIF_BUS_CONTEXT         Context;
    NTSTATUS                    status;

    Trace("====>\n");

    Context = __BusAllocate(sizeof (XENVIF_BUS_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (Context == NULL)
        goto fail1;

    Context->Pdo = Pdo;

    Interface->Size = sizeof (BUS_INTERFACE_STANDARD);
    Interface->Version = 1;
    Interface->Context = Context;
    Interface->InterfaceReference = BusReference;
    Interface->InterfaceDereference = BusDereference;
    Interface->TranslateBusAddress = BusTranslateAddress;
    Interface->GetDmaAdapter = BusGetDmaAdapter;
    Interface->SetBusData = BusSetData;
    Interface->GetBusData = BusGetData;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
BusTeardown(
    IN OUT  PBUS_INTERFACE_STANDARD Interface
    )
{
    PXENVIF_BUS_CONTEXT             Context = Interface->Context;

    Trace("====>\n");

    Context->Pdo = NULL;

    ASSERT(IsZeroMemory(Context, sizeof (XENVIF_BUS_CONTEXT)));
    __BusFree(Context);

    RtlZeroMemory(Interface, sizeof (BUS_INTERFACE_STANDARD));

    Trace("<====\n");
}
