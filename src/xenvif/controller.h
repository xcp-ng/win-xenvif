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

#ifndef _XENVIF_CONTROLLER_H
#define _XENVIF_CONTROLLER_H

#include <ntddk.h>

#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_CONTROLLER XENVIF_CONTROLLER, *PXENVIF_CONTROLLER;

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
ControllerInitialize(
    _In_ PXENVIF_FRONTEND       Frontend,
    _Outptr_ PXENVIF_CONTROLLER *Controller
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerConnect(
    _Out_ PXENVIF_CONTROLLER    Controller
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerStoreWrite(
    _In_ PXENVIF_CONTROLLER         Controller,
    _In_ PXENBUS_STORE_TRANSACTION  Transaction
    );

extern VOID
ControllerEnable(
    _Out_ PXENVIF_CONTROLLER    Controller
    );

extern VOID
ControllerDisable(
    _Out_ PXENVIF_CONTROLLER    Controller
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern VOID
ControllerDisconnect(
    _Out_ PXENVIF_CONTROLLER    Controller
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
ControllerTeardown(
    _Out_ PXENVIF_CONTROLLER    Controller
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerSetHashAlgorithm(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _In_ ULONG                  Algorithm
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerGetHashFlags(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _Out_ PULONG                Flags
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerSetHashFlags(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _In_ ULONG                  Flags
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerSetHashKey(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _In_ PUCHAR                 Key,
    _In_ ULONG                  Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerGetHashMappingSize(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _Out_ PULONG                Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerSetHashMappingSize(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _In_ ULONG                  Size
    );

_IRQL_requires_(DISPATCH_LEVEL)
extern NTSTATUS
ControllerSetHashMapping(
    _Out_ PXENVIF_CONTROLLER    Controller,
    _In_ PULONG                 Mapping,
    _In_ ULONG                  Size,
    _In_ ULONG                  Offset
    );


#endif  // _XENVIF_CONTROLLER_H
