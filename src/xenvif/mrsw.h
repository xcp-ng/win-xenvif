/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
 * Copyright (c) Vates.
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

#ifndef _MRSW_H
#define _MRSW_H

#include <wdm.h>

#include "assert.h"
#include "util.h"

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
struct _MRSW_LOCK {
    KGUARDED_MUTEX                  Mutex;
    union {
        EX_RUNDOWN_REF              Rundown;
        PEX_RUNDOWN_REF_CACHE_AWARE RundownCacheAware;
    };
};
#pragma warning(pop)

typedef struct _MRSW_LOCK   MRSW_LOCK, *PMRSW_LOCK;
typedef struct _MRSW_LOCK   MRSW_CACHE_AWARE_LOCK, *PMRSW_CACHE_AWARE_LOCK;

static FORCEINLINE NTSTATUS
__MrswRundownInitialize(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware,
    _In_ ULONG                  Tag
    )
{
    if (CacheAware) {
        Lock->RundownCacheAware = ExAllocateCacheAwareRundownProtection(NonPagedPoolNx,
                                                                        Tag);
        if (!Lock->RundownCacheAware)
            return STATUS_NO_MEMORY;
    } else {
        ExInitializeRundownProtection(&Lock->Rundown);
    }

    return STATUS_SUCCESS;
}

static FORCEINLINE BOOLEAN
__MrswRundownAcquire(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    if (CacheAware)
        return ExAcquireRundownProtectionCacheAware(Lock->RundownCacheAware);
    else
        return ExAcquireRundownProtection(&Lock->Rundown);
}

static FORCEINLINE VOID
__MrswRundownRelease(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    if (CacheAware)
        ExReleaseRundownProtectionCacheAware(Lock->RundownCacheAware);
    else
        ExReleaseRundownProtection(&Lock->Rundown);
}

static FORCEINLINE VOID
__MrswRundownWait(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    if (CacheAware)
        ExWaitForRundownProtectionReleaseCacheAware(Lock->RundownCacheAware);
    else
        ExWaitForRundownProtectionRelease(&Lock->Rundown);
}

static FORCEINLINE VOID
__MrswRundownCompleted(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    if (CacheAware)
        ExRundownCompletedCacheAware(Lock->RundownCacheAware);
    else
        ExRundownCompleted(&Lock->Rundown);
}

static FORCEINLINE VOID
__MrswRundownReInitialize(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    if (CacheAware)
        ExReInitializeRundownProtectionCacheAware(Lock->RundownCacheAware);
    else
        ExReInitializeRundownProtection(&Lock->Rundown);
}

static FORCEINLINE VOID
__MrswRundownTeardown(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    if (CacheAware)
        ExFreeCacheAwareRundownProtection(Lock->RundownCacheAware);
    else
        RtlZeroMemory(&Lock->Rundown, sizeof(Lock->Rundown));
}

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE NTSTATUS
__InitializeMrswLock(
    _Out_ struct _MRSW_LOCK     *Lock,
    _In_ BOOLEAN                CacheAware,
    _In_ ULONG                  Tag
    )
{
    KeInitializeGuardedMutex(&Lock->Mutex);
    return __MrswRundownInitialize(Lock, CacheAware, Tag);
}
#define InitializeMrswLock(Lock, Tag) \
    __InitializeMrswLock(Lock, FALSE, Tag)
#define InitializeMrswCacheAwareLock(Lock, Tag) \
    __InitializeMrswLock(Lock, TRUE, Tag)

_Requires_lock_not_held_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE VOID
__TeardownMrswLock(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
#if DBG
    BUG_ON(!KeTryToAcquireGuardedMutex(&Lock->Mutex));
    BUG_ON(!__MrswRundownAcquire(Lock, CacheAware));
    KeReleaseGuardedMutex(&Lock->Mutex);
    __MrswRundownRelease(Lock, CacheAware);
#endif

    __MrswRundownTeardown(Lock, CacheAware);
    RtlZeroMemory(Lock, sizeof(MRSW_LOCK));
}
#define TeardownMrswLock(Lock) \
    __TeardownMrswLock(Lock, FALSE)
#define TeardownMrswCacheAwareLock(Lock) \
    __TeardownMrswLock(Lock, TRUE)

_Acquires_lock_(_Global_critical_region_)
_Requires_lock_not_held_(*Lock)
_Acquires_exclusive_lock_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE VOID
__AcquireMrswLockExclusive(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    ASSERT3U(KeGetCurrentIrql(), <=, APC_LEVEL);

    KeAcquireGuardedMutex(&Lock->Mutex);
    __MrswRundownWait(Lock, CacheAware);
    __MrswRundownCompleted(Lock, CacheAware);
}
#define AcquireMrswLockExclusive(Lock) \
    __AcquireMrswLockExclusive(Lock, FALSE)
#define AcquireMrswCacheAwareLockExclusive(Lock) \
    __AcquireMrswLockExclusive(Lock, TRUE)

_Releases_lock_(_Global_critical_region_)
_Requires_exclusive_lock_held_(*Lock)
_Releases_exclusive_lock_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE VOID
__ReleaseMrswLockExclusive(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    __MrswRundownReInitialize(Lock, CacheAware);
    KeReleaseGuardedMutex(&Lock->Mutex);
}
#define ReleaseMrswLockExclusive(Lock) \
    __ReleaseMrswLockExclusive(Lock, FALSE)
#define ReleaseMrswCacheAwareLockExclusive(Lock) \
    __ReleaseMrswLockExclusive(Lock, TRUE)

_Releases_lock_(_Global_critical_region_)
_Requires_exclusive_lock_held_(*Lock)
_Releases_exclusive_lock_(*Lock)
_Acquires_shared_lock_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE VOID
__DowngradeMrswLockExclusive(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    __MrswRundownReInitialize(Lock, CacheAware);
    BUG_ON(!__MrswRundownAcquire(Lock, CacheAware));
    KeReleaseGuardedMutex(&Lock->Mutex);
}
#define DowngradeMrswLockExclusive(Lock) \
    __DowngradeMrswLockExclusive(Lock, FALSE)
#define DowngradeMrswCacheAwareLockExclusive(Lock) \
    __DowngradeMrswLockExclusive(Lock, TRUE)

_When_(return, _Acquires_shared_lock_(*Lock))
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE BOOLEAN
__TryAcquireMrswLockShared(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
#if DBG
    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
#endif

    return __MrswRundownAcquire(Lock, CacheAware);
}
#define TryAcquireMrswLockShared(Lock) \
    __TryAcquireMrswLockShared(Lock, FALSE)
#define TryAcquireMrswCacheAwareLockShared(Lock) \
    __TryAcquireMrswLockShared(Lock, TRUE)

_Acquires_shared_lock_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE VOID
__SpinAcquireMrswLockShared(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
#if DBG
    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
#endif

    while (!__MrswRundownAcquire(Lock, CacheAware))
        YieldProcessor();
}
#define SpinAcquireMrswLockShared(Lock) \
    __SpinAcquireMrswLockShared(Lock, FALSE)
#define SpinAcquireMrswCacheAwareLockShared(Lock) \
    __SpinAcquireMrswLockShared(Lock, TRUE)

/*
 * Unlike SpinAcquireMrswLockShared, AcquireMrswLockShared will
 * sleep when the lock acquisition fails. Thus it cannot be used at
 * DISPATCH_LEVEL.
 */
_Acquires_shared_lock_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE VOID
__AcquireMrswLockShared(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
#if DBG
    ASSERT3U(KeGetCurrentIrql(), <=, APC_LEVEL);
#endif

    if (__MrswRundownAcquire(Lock, CacheAware))
        return;

    /*
     * Don't bother retrying, since it's most likely that another writer section
     * is cleaning up and not ending any time soon. Just jump straight into
     * sleep.
     */
    KeAcquireGuardedMutex(&Lock->Mutex);
    /*
     * Since we have the write mutex, we know that there are no writers. So this
     * acquire must succeed.
     */
    BUG_ON(!__MrswRundownAcquire(Lock, CacheAware));
    KeReleaseGuardedMutex(&Lock->Mutex);
}
#define AcquireMrswLockShared(Lock) \
    __AcquireMrswLockShared(Lock, FALSE)
#define AcquireMrswCacheAwareLockShared(Lock) \
    __AcquireMrswLockShared(Lock, TRUE)

_Requires_shared_lock_held_(*Lock)
_Releases_shared_lock_(*Lock)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE VOID
__ReleaseMrswLockShared(
    _Inout_ struct _MRSW_LOCK   *Lock,
    _In_ BOOLEAN                CacheAware
    )
{
    __MrswRundownRelease(Lock, CacheAware);
}
#define ReleaseMrswLockShared(Lock) \
    __ReleaseMrswLockShared(Lock, FALSE)
#define ReleaseMrswCacheAwareLockShared(Lock) \
    __ReleaseMrswLockShared(Lock, TRUE)

#endif  // _MRSW_H
