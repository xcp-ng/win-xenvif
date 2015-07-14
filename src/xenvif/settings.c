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

#include "registry.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define SETTINGS_TAG 'TTES'

static FORCEINLINE PVOID
__SettingsAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, SETTINGS_TAG);
}

static FORCEINLINE VOID
__SettingsFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, SETTINGS_TAG);
}

static NTSTATUS
SettingsCopyValue(
    IN  PVOID           Context,
    IN  HANDLE          SourceKey,
    IN  PANSI_STRING    Name,
    IN  ULONG           Type
    )
{
    HANDLE              DestinationKey = (HANDLE)Context;
    NTSTATUS            status;

    Trace("%Z\n", Name);

    switch (Type) {
    case REG_DWORD: {
        ULONG   Value;

        status = RegistryQueryDwordValue(SourceKey,
                                         Name->Buffer,
                                         &Value);
        if (NT_SUCCESS(status))
            (VOID) RegistryUpdateDwordValue(DestinationKey,
                                            Name->Buffer,
                                            Value);

        break;
    }
    case REG_SZ:
    case REG_MULTI_SZ: {
        PANSI_STRING    Value;

        status = RegistryQuerySzValue(SourceKey,
                                      Name->Buffer,
                                      &Value);
        if (NT_SUCCESS(status)) {
            (VOID) RegistryUpdateSzValue(DestinationKey,
                                         Name->Buffer,
                                         Value);
            RegistryFreeSzValue(Value);
        }

        break;
    }
    case REG_BINARY: {
        PVOID   Value;
        ULONG   Length;

        status = RegistryQueryBinaryValue(SourceKey,
                                          Name->Buffer,
                                          &Value,
                                          &Length);
        if (NT_SUCCESS(status)) {
            (VOID) RegistryUpdateBinaryValue(DestinationKey,
                                             Name->Buffer,
                                             Value,
                                             Length);
            RegistryFreeBinaryValue(Value);
        }

        break;
    }
    default:
        ASSERT(FALSE);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SettingsCopyInterface(
    IN  HANDLE  SettingsKey,
    IN  PCHAR   SaveKeyName,
    IN  PCHAR   InterfacesPath,
    IN  PCHAR   InterfacePrefix,
    IN  PCHAR   InterfaceName,
    IN  BOOLEAN Save
    )
{
    ULONG       Length;
    HANDLE      InterfacesKey;
    PCHAR       KeyName;
    HANDLE      Key;
    HANDLE      SaveKey;
    NTSTATUS    status;

    Trace("====>\n");

    status = RegistryOpenSubKey(NULL,
                                InterfacesPath,
                                KEY_ALL_ACCESS,
                                &InterfacesKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    Length = (ULONG)((strlen(InterfacePrefix) +
                      strlen(InterfaceName) +
                      1) * sizeof (CHAR));

    KeyName = __SettingsAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (KeyName == NULL)
        goto fail2;

    status = RtlStringCbPrintfA(KeyName,
                                Length,
                                "%s%s",
                                InterfacePrefix,
                                InterfaceName);
    ASSERT(NT_SUCCESS(status));

    Trace("%s %s\\%s\n",
          (Save) ? "FROM" : "TO",
          InterfacesPath,
          KeyName);

    status = (!Save) ?
        RegistryCreateSubKey(InterfacesKey,
                             KeyName,
                             REG_OPTION_NON_VOLATILE,
                             &Key) :
        RegistryOpenSubKey(InterfacesKey,
                           KeyName,
                           KEY_READ,
                           &Key);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = (Save) ?
        RegistryCreateSubKey(SettingsKey,
                             SaveKeyName,
                             REG_OPTION_NON_VOLATILE,
                             &SaveKey) :
        RegistryOpenSubKey(SettingsKey,
                           SaveKeyName,
                           KEY_READ,
                           &SaveKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = (Save) ?
        RegistryEnumerateValues(Key,
                                SettingsCopyValue,
                                (PVOID)SaveKey) :
        // Restore
        RegistryEnumerateValues(SaveKey,
                                SettingsCopyValue,
                                (PVOID)Key);
    if (!NT_SUCCESS(status))
        goto fail5;

    RegistryCloseKey(SaveKey);

    if (!Save)
        (VOID) RegistryDeleteSubKey(SettingsKey, SaveKeyName);

    RegistryCloseKey(Key);

    __SettingsFree(KeyName);

    RegistryCloseKey(InterfacesKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    RegistryCloseKey(SaveKey);

fail4:
    Error("fail4\n");

    RegistryCloseKey(Key);

fail3:
    Error("fail3\n");

    __SettingsFree(KeyName);

fail2:
    Error("fail2\n");

    RegistryCloseKey(InterfacesKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define IPV6_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a11-9b1a-11d4-9123-0050047759bc}\\10"

static VOID
SettingsCopyIpVersion6Addresses(
    IN  HANDLE  SettingsKey,
    IN  PCHAR   ValueName,
    IN  BOOLEAN Save
    )
{
    HANDLE      ValueKey;
    PVOID       Value;
    ULONG       Length;
    NTSTATUS    status;

    Trace("====>\n");

    status = RegistryOpenSubKey(NULL,
                                IPV6_PATH,
                                (Save) ? KEY_READ : KEY_ALL_ACCESS,
                                &ValueKey);
    if (!NT_SUCCESS(status)) {
        Info("NOT FOUND\n");
        goto done;
    }

    Trace("%s %s\\%s\n",
          (Save) ? "FROM" : "TO",
          IPV6_PATH,
          ValueName);

    if (Save) {
        status = RegistryQueryBinaryValue(ValueKey,
                                          ValueName,
                                          &Value,
                                          &Length);
        if (NT_SUCCESS(status))
            (VOID) RegistryUpdateBinaryValue(SettingsKey,
                                             "IpVersion6Addresses",
                                             Value,
                                             Length);
    } else { // Restore
        status = RegistryQueryBinaryValue(SettingsKey,
                                          "IpVersion6Addresses",
                                          &Value,
                                          &Length);
        if (NT_SUCCESS(status))
            (VOID) RegistryUpdateBinaryValue(ValueKey,
                                             ValueName,
                                             Value,
                                             Length);
    }

    RegistryCloseKey(ValueKey);

done:
    Trace("<====\n");
}

#define INTERFACES_PATH(_Name) "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ## #_Name ## "\\Parameters\\Interfaces\\"

static NTSTATUS
SettingsCopy(
     IN HANDLE      SettingsKey,
     IN LPGUID      InterfaceGuid,
     IN PNET_LUID   InterfaceLuid,
     IN BOOLEAN     Save
     )
{
    UNICODE_STRING  Unicode;
    ULONG           Length;
    PCHAR           GuidName;
    PCHAR           LuidName;
    NTSTATUS        status;

    Trace("====>\n");

    status = RtlStringFromGUID(InterfaceGuid, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail1;

    Length = (ULONG)(((Unicode.Length / sizeof (WCHAR)) +
                      1) * sizeof (CHAR));

    GuidName = __SettingsAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (GuidName == NULL)
        goto fail2;

    status = RtlStringCbPrintfA(GuidName,
                                Length,
                                "%wZ",
                                &Unicode);
    ASSERT(NT_SUCCESS(status));

    (VOID) SettingsCopyInterface(SettingsKey,
                                 "NetBT",
                                 INTERFACES_PATH(NetBT),
                                 "Tcpip_",
                                 GuidName,
                                 Save);

    (VOID) SettingsCopyInterface(SettingsKey,
                                 "Tcpip",
                                 INTERFACES_PATH(Tcpip),
                                 "",
                                 GuidName,
                                 Save);

    (VOID) SettingsCopyInterface(SettingsKey,
                                 "Tcpip6",
                                 INTERFACES_PATH(Tcpip6),
                                 "",
                                 GuidName,
                                 Save);

    Length = (ULONG)(((sizeof (NET_LUID) * 2) +
                      1) * sizeof (CHAR));

    LuidName = __SettingsAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (LuidName == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(LuidName,
                                Length,
                                "%016llX",
                                InterfaceLuid->Value);
    ASSERT(NT_SUCCESS(status));

    SettingsCopyIpVersion6Addresses(SettingsKey,
                                    LuidName,
                                    Save);

    __SettingsFree(LuidName);

    __SettingsFree(GuidName);

    RtlFreeUnicodeString(&Unicode);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    __SettingsFree(GuidName);

fail2:
    Error("fail2\n");

    RtlFreeUnicodeString(&Unicode);

fail1:
    Error("fail1\n", status);

    return status;
}

NTSTATUS
SettingsSave(
     IN HANDLE      SoftwareKey,
     IN PWCHAR      Alias,
     IN PWCHAR      Description,
     IN LPGUID      InterfaceGuid,
     IN PNET_LUID   InterfaceLuid
     )
{
    HANDLE          SettingsKey;
    NTSTATUS        status;

    Info("FROM %ws (%ws)\n", Alias, Description);

    status = RegistryCreateSubKey(SoftwareKey,
                                  "Settings",
                                  REG_OPTION_NON_VOLATILE,
                                  &SettingsKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = SettingsCopy(SettingsKey, InterfaceGuid, InterfaceLuid, TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    RegistryCloseKey(SettingsKey);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryCloseKey(SettingsKey);

fail1:
    Error("fail1\n", status);

    return status;
}

NTSTATUS
SettingsRestore(
     IN HANDLE      SoftwareKey,
     IN PWCHAR      Alias,
     IN PWCHAR      Description,
     IN LPGUID      InterfaceGuid,
     IN PNET_LUID   InterfaceLuid
     )
{
    HANDLE          SettingsKey;
    NTSTATUS        status;

    status = RegistryOpenSubKey(SoftwareKey,
                                "Settings",
                                KEY_ALL_ACCESS,
                                &SettingsKey);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND)
            goto done;

        goto fail1;
    }

    Info("TO %ws (%ws)\n", Alias, Description);

    status = SettingsCopy(SettingsKey, InterfaceGuid, InterfaceLuid, FALSE);
    if (!NT_SUCCESS(status))
        goto fail2;

    RegistryCloseKey(SettingsKey);

    (VOID) RegistryDeleteSubKey(SoftwareKey, "Settings");

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryCloseKey(SettingsKey);

fail1:
    Error("fail1\n", status);

    return status;
}
