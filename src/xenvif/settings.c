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

#include "registry.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"
#include "util.h"

#define SETTINGS_TAG 'TTES'

#define INTERFACES_PATH(_Name)      \
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ## #_Name ## "\\Parameters\\Interfaces\\"

#define IPV6_PATH   \
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a01-9b1a-11d4-9123-0050047759bc}\\10"

#define IPV4_PATH   \
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nsi\\{eb004a00-9b1a-11d4-9123-0050047759bc}\\10"

#define NETLUID_STRING_LENGTH 16

typedef struct _SETTINGS_COPY_IP_ADDRESS_PARAMETERS {
    CHAR        SrcPrefix[NETLUID_STRING_LENGTH + 1];
    CHAR        DstPrefix[NETLUID_STRING_LENGTH + 1];
} SETTINGS_COPY_IP_ADDRESS_PARAMETERS, *PSETTINGS_COPY_IP_ADDRESS_PARAMETERS;

static FORCEINLINE PVOID
__SettingsAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, SETTINGS_TAG);
}

static FORCEINLINE VOID
__SettingsFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, SETTINGS_TAG);
}

static FORCEINLINE NTSTATUS
__GuidToString(
    IN  LPGUID          Guid,
    OUT PANSI_STRING    Ansi
    )
{
    NTSTATUS            status;
    UNICODE_STRING      Unicode;

    status = RtlStringFromGUID(Guid, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlUnicodeStringToAnsiString(Ansi, &Unicode, TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlFreeUnicodeString(&Unicode);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsCopyIpAddressesValue(
    IN  PVOID                               Context,
    IN  HANDLE                              Key,
    IN  PANSI_STRING                        ValueName,
    IN  ULONG                               Type
    )
{
    PSETTINGS_COPY_IP_ADDRESS_PARAMETERS    Parameters = Context;
    PVOID                                   Value;
    ULONG                                   ValueLength;
    NTSTATUS                                status;

    UNREFERENCED_PARAMETER(Type);

    if (_strnicmp(ValueName->Buffer,
                  Parameters->SrcPrefix,
                  NETLUID_STRING_LENGTH) != 0)
        goto done;

    Trace("    -> %Z\n", ValueName);

    status = RegistryQueryBinaryValue(Key,
                                      ValueName->Buffer,
                                      &Value,
                                      &ValueLength);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryDeleteValue(Key,
                                 ValueName->Buffer);
    if (!NT_SUCCESS(status))
        goto fail2;

    ASSERT(NETLUID_STRING_LENGTH < ValueName->Length);
    memcpy(ValueName->Buffer, Parameters->DstPrefix, NETLUID_STRING_LENGTH);

    Trace("    <- %Z\n", ValueName);

    status = RegistryUpdateBinaryValue(Key,
                                       ValueName->Buffer,
                                       Value,
                                       ValueLength);
    if (!NT_SUCCESS(status))
        goto fail3;

    if (ValueLength != 0)
        RegistryFreeBinaryValue(Value);

done:
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    if (ValueLength != 0)
        RegistryFreeBinaryValue(Value);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsCopyIpAddresses(
    IN  ULONG                           Version,
    IN  PNET_LUID                       OldLuid,
    IN  PNET_LUID                       NewLuid
    )
{
    SETTINGS_COPY_IP_ADDRESS_PARAMETERS Parameters;
    HANDLE                              Key;
    NTSTATUS                            status;

    status = RtlStringCbPrintfA(Parameters.SrcPrefix,
                                sizeof(Parameters.SrcPrefix),
                                "%016llx",
                                _byteswap_uint64(OldLuid->Value));
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringCbPrintfA(Parameters.DstPrefix,
                                sizeof(Parameters.DstPrefix),
                                "%016llx",
                                _byteswap_uint64(NewLuid->Value));
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryOpenSubKey(NULL,
                                (Version == 4) ? IPV4_PATH : IPV6_PATH,
                                KEY_ALL_ACCESS,
                                &Key);
    if (!NT_SUCCESS(status))
        goto fail3;

    Info("IPv%u: %s -> %s\n",
         Version,
         Parameters.SrcPrefix,
         Parameters.DstPrefix);

    status = RegistryEnumerateValues(Key,
                                     SettingsCopyIpAddressesValue,
                                     &Parameters);
    if (!NT_SUCCESS(status))
        goto fail4;

    RegistryCloseKey(Key);

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    RegistryCloseKey(Key);

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsCopyInterfaceValue(
    IN  PVOID            Context,
    IN  HANDLE           SourceKey,
    IN  PANSI_STRING     ValueName,
    IN  ULONG            Type
    )
{
    HANDLE               DestinationKey = Context;
    NTSTATUS             status;

    Trace(" - %Z\n", ValueName);

    switch (Type) {
    case REG_DWORD: {
        ULONG   Value;

        status = RegistryQueryDwordValue(SourceKey,
                                         ValueName->Buffer,
                                         &Value);
        if (NT_SUCCESS(status))
            (VOID) RegistryUpdateDwordValue(DestinationKey,
                                            ValueName->Buffer,
                                            Value);

        break;
    }
    case REG_SZ:
    case REG_MULTI_SZ: {
        PANSI_STRING    Value;

        status = RegistryQuerySzValue(SourceKey,
                                      ValueName->Buffer,
                                      NULL,
                                      &Value);
        if (NT_SUCCESS(status)) {
            (VOID) RegistryUpdateSzValue(DestinationKey,
                                         ValueName->Buffer,
                                         Type,
                                         Value);
            RegistryFreeSzValue(Value);
        }

        break;
    }
    case REG_BINARY: {
        PVOID   Value;
        ULONG   Length;

        status = RegistryQueryBinaryValue(SourceKey,
                                          ValueName->Buffer,
                                          &Value,
                                          &Length);
        if (NT_SUCCESS(status)) {
            (VOID) RegistryUpdateBinaryValue(DestinationKey,
                                             ValueName->Buffer,
                                             Value,
                                             Length);
            if (Length != 0)
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
    IN  PCHAR           InterfacePath,
    IN  PCHAR           InterfacePrefix,
    IN  PANSI_STRING    OldGuid,
    IN  PANSI_STRING    NewGuid
    )
{
    HANDLE              OldKey;
    HANDLE              NewKey;
    PCHAR               OldKeyName;
    PCHAR               NewKeyName;
    ULONG               OldKeyLength;
    ULONG               NewKeyLength;
    NTSTATUS            status;

    OldKeyLength = (ULONG)(strlen(InterfacePath) +
                           strlen(InterfacePrefix) +
                           OldGuid->Length +
                           1) * sizeof(CHAR);
    NewKeyLength = (ULONG)(strlen(InterfacePath) +
                           strlen(InterfacePrefix) +
                           NewGuid->Length +
                           1) * sizeof(CHAR);

    status = STATUS_NO_MEMORY;
    OldKeyName = __SettingsAllocate(OldKeyLength);
    if (OldKeyName == NULL)
        goto fail1;

    NewKeyName = __SettingsAllocate(NewKeyLength);
    if (NewKeyName == NULL)
        goto fail2;

    status = RtlStringCbPrintfA(OldKeyName,
                                OldKeyLength,
                                "%s%s%Z",
                                InterfacePath,
                                InterfacePrefix,
                                OldGuid);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RtlStringCbPrintfA(NewKeyName,
                                NewKeyLength,
                                "%s%s%Z",
                                InterfacePath,
                                InterfacePrefix,
                                NewGuid);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RegistryOpenSubKey(NULL,
                                OldKeyName,
                                KEY_READ,
                                &OldKey);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = RegistryCreateSubKey(NULL,
                                  NewKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &NewKey);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = RegistryEnumerateValues(OldKey,
                                     SettingsCopyInterfaceValue,
                                     NewKey);
    if (!NT_SUCCESS(status))
        goto fail7;

    RegistryCloseKey(NewKey);
    RegistryCloseKey(OldKey);
    __SettingsFree(NewKeyName);
    __SettingsFree(OldKeyName);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    RegistryCloseKey(NewKey);

fail6:
    Error("fail6\n");

    RegistryCloseKey(OldKey);

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    __SettingsFree(NewKeyName);

fail2:
    Error("fail2\n");

    __SettingsFree(OldKeyName);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsStoreCurrent(
    IN  HANDLE          SubKey,
    IN  PANSI_STRING    Guid,
    IN  PNET_LUID       Luid
    )
{

    NTSTATUS            status;

    status = RegistryUpdateSzValue(SubKey,
                                   "NetCfgInstanceId",
                                   REG_SZ,
                                   Guid);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryUpdateBinaryValue(SubKey,
                                       "NetLuid",
                                       Luid,
                                       sizeof(NET_LUID));
    if (!NT_SUCCESS(status))
        goto fail2;

    (VOID) RegistryDeleteValue(SubKey,
                               "HasSettings");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsCopy(
    IN  PCHAR           SubKeyName,
    IN  PANSI_STRING    OldGuid,
    IN  PNET_LUID       OldLuid,
    IN  PANSI_STRING    NewGuid,
    IN  PNET_LUID       NewLuid
     )
{
    HANDLE              SettingsKey;
    HANDLE              SubKey;
    NTSTATUS            status;

    Trace("====>\n");
    Info("VIF/%s: FROM %Z\n", SubKeyName, OldGuid);
    Info("VIF/%s: TO   %Z\n", SubKeyName, NewGuid);

    (VOID) SettingsCopyInterface(INTERFACES_PATH(NetBT),
                                 "Tcpip_",
                                 OldGuid,
                                 NewGuid);

    (VOID) SettingsCopyInterface(INTERFACES_PATH(Tcpip),
                                 "",
                                 OldGuid,
                                 NewGuid);

    (VOID) SettingsCopyInterface(INTERFACES_PATH(Tcpip6),
                                 "",
                                 OldGuid,
                                 NewGuid);

    (VOID) SettingsCopyIpAddresses(4,
                                   OldLuid,
                                   NewLuid);

    (VOID) SettingsCopyIpAddresses(6,
                                   OldLuid,
                                   NewLuid);

    SettingsKey = DriverGetSettingsKey();

    status = RegistryCreateSubKey(SettingsKey,
                                  SubKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &SubKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = SettingsStoreCurrent(SubKey,
                                  NewGuid,
                                  NewLuid);
    if (!NT_SUCCESS(status))
        goto fail2;

    RegistryCloseKey(SubKey);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryCloseKey(SubKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
SettingsSave(
    IN  PCHAR       SubKeyName,
    IN  PWCHAR      Alias,
    IN  PWCHAR      Description,
    IN  LPGUID      InterfaceGuid,
    IN  PNET_LUID   InterfaceLuid
    )
{
    HANDLE          SettingsKey;
    HANDLE          SubKey;
    ANSI_STRING     Ansi;
    ULONG           HasSettings;
    NTSTATUS        status;

    Info("FROM %ws (%ws)\n", Alias, Description);

    status = __GuidToString(InterfaceGuid, &Ansi);
    if (!NT_SUCCESS(status))
        goto fail1;

    SettingsKey = DriverGetSettingsKey();

    status = RegistryCreateSubKey(SettingsKey,
                                  SubKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &SubKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    HasSettings = 0;
    status = RegistryQueryDwordValue(SubKey,
                                     "HasSettings",
                                     &HasSettings);
    if (!NT_SUCCESS(status))
        HasSettings = 0;
    if (HasSettings != 0)
        goto done;

    Info("FROM %Z\n", Ansi);
    Info("FROM %016llx\n", InterfaceLuid->Value);

    status = SettingsStoreCurrent(SubKey,
                                  &Ansi,
                                  InterfaceLuid);
    if (!NT_SUCCESS(status))
        goto fail3;

    RtlFreeAnsiString(&Ansi);

done:
    RegistryCloseKey(SubKey);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RegistryCloseKey(SubKey);

fail2:
    Error("fail2\n");

    RtlFreeAnsiString(&Ansi);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
SettingsRestore(
    IN  PCHAR       SubKeyName,
    IN  PWCHAR      Alias,
    IN  PWCHAR      Description,
    IN  LPGUID      InterfaceGuid,
    IN  PNET_LUID   InterfaceLuid
    )
{
    HANDLE          SettingsKey;
    HANDLE          SubKey;
    ANSI_STRING     Ansi;
    PANSI_STRING    NetCfgInstanceId;
    PNET_LUID       NetLuid;
    ULONG           NetLuidLength;
    NTSTATUS        status;

    SettingsKey = DriverGetSettingsKey();

    status = RegistryOpenSubKey(SettingsKey,
                                SubKeyName,
                                KEY_READ,
                                &SubKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryQuerySzValue(SubKey,
                                  "NetCfgInstanceId",
                                  NULL,
                                  &NetCfgInstanceId);
    if (!NT_SUCCESS(status))
        goto fail2;

    NetLuidLength = 0;
    status = RegistryQueryBinaryValue(SubKey,
                                      "NetLuid",
                                      &NetLuid,
                                      &NetLuidLength);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = __GuidToString(InterfaceGuid, &Ansi);
    if (!NT_SUCCESS(status))
        goto fail4;

    if (RtlCompareString(NetCfgInstanceId, &Ansi, TRUE) != 0) {
        Info("TO %ws (%ws)\n", Alias, Description);
        Info("TO %Z\n", Ansi);
        Info("TO %016llx\n", InterfaceLuid->Value);

        SettingsCopy(SubKeyName,
                     NetCfgInstanceId,
                     NetLuid,
                     &Ansi,
                     InterfaceLuid);
    } else {
        Info("%s: SettingsCopy not required for %ws\n",
             SubKeyName,
             Description);
    }

    RtlFreeAnsiString(&Ansi);

    if (NetLuidLength != 0)
        RegistryFreeBinaryValue(NetLuid);

    RegistryFreeSzValue(NetCfgInstanceId);

    RegistryCloseKey(SubKey);

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    if (NetLuidLength != 0)
        RegistryFreeBinaryValue(NetLuid);

fail3:
    Error("fail3\n");

    RegistryFreeSzValue(NetCfgInstanceId);

fail2:
    Error("fail2\n");

    RegistryCloseKey(SubKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
