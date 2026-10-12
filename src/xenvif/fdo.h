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

#ifndef _XENVIF_FDO_H
#define _XENVIF_FDO_H

#include <ntddk.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <evtchn_interface.h>
#include <store_interface.h>
#include <range_set_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <unplug_interface.h>

#include "driver.h"
#include "types.h"

extern PCHAR
FdoGetVendorName(
    _In_ PXENVIF_FDO    Fdo
    );

extern PCHAR
FdoGetName(
    _In_ PXENVIF_FDO    Fdo
    );

extern NTSTATUS
FdoAddPhysicalDeviceObject(
    _Out_ PXENVIF_FDO   Fdo,
    _In_ PXENVIF_PDO    Pdo
    );

extern VOID
FdoRemovePhysicalDeviceObject(
    _Out_ PXENVIF_FDO   Fdo,
    _In_ PXENVIF_PDO    Pdo
    );

extern VOID
FdoAcquireMutex(
    _In_ PXENVIF_FDO    Fdo
    );

extern VOID
FdoReleaseMutex(
    _Out_ PXENVIF_FDO   Fdo
    );

extern PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    _In_ PXENVIF_FDO    Fdo
    );

extern PDMA_ADAPTER
FdoGetDmaAdapter(
    _In_ PXENVIF_FDO            Fdo,
    _In_ PDEVICE_DESCRIPTION    DeviceDescriptor,
    _Out_ PULONG                NumberOfMapRegisters
    );

extern BOOLEAN
FdoTranslateBusAddress(
    _In_ PXENVIF_FDO         Fdo,
    _In_ PHYSICAL_ADDRESS    BusAddress,
    _In_ ULONG               Length,
    _Inout_ PULONG           AddressSpace,
    _Out_ PPHYSICAL_ADDRESS  TranslatedAddress
    );

extern ULONG
FdoSetBusData(
    _In_ PXENVIF_FDO                Fdo,
    _In_ ULONG                      DataType,
    _In_reads_bytes_(Length) PVOID  Buffer,
    _In_ ULONG                      Offset,
    _In_ ULONG                      Length
    );

extern ULONG
FdoGetBusData(
    _In_ PXENVIF_FDO                Fdo,
    _In_ ULONG                      DataType,
    _In_reads_bytes_(Length) PVOID  Buffer,
    _In_ ULONG                      Offset,
    _In_ ULONG                      Length
    );

extern NTSTATUS
FdoDelegateIrp(
    _In_ PXENVIF_FDO    Fdo,
    _In_ PIRP           Irp
    );

extern NTSTATUS
FdoDispatch(
    _Out_ PXENVIF_FDO   Fdo,
    _In_ PIRP           Irp
    );

#define DECLARE_FDO_GET_INTERFACE(_Interface, _Type)    \
extern VOID                                             \
FdoGet ## _Interface ## Interface(                      \
    IN  PXENVIF_FDO Fdo,                                \
    OUT _Type       _Interface ## Interface             \
    );

DECLARE_FDO_GET_INTERFACE(Debug, PXENBUS_DEBUG_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Suspend, PXENBUS_SUSPEND_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Evtchn, PXENBUS_EVTCHN_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Store, PXENBUS_STORE_INTERFACE)
DECLARE_FDO_GET_INTERFACE(RangeSet, PXENBUS_RANGE_SET_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Cache, PXENBUS_CACHE_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Gnttab, PXENBUS_GNTTAB_INTERFACE)
DECLARE_FDO_GET_INTERFACE(Unplug, PXENBUS_UNPLUG_INTERFACE)

extern NTSTATUS
FdoCreate(
    _In_ PDEVICE_OBJECT PhysicalDeviceObject
    );

extern VOID
FdoDestroy(
    _Out_ PXENVIF_FDO   Fdo
    );

#endif  // _XENVIF_FDO_H
