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

#define INITGUID 1

#include <ntddk.h>
#include <ntstrsafe.h>
#include <devguid.h>

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
    return __AllocatePoolWithTag(NonPagedPool, Length, SETTINGS_TAG);
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
    IN  HANDLE  DestinationKey,
    IN  HANDLE  SourceKey,
    IN  PCHAR   ValueName,
    IN  ULONG   Type
    )
{
    NTSTATUS    status;

    Trace("%s\n", ValueName);

    switch (Type) {
    case REG_DWORD: {
        ULONG   Value;

        status = RegistryQueryDwordValue(SourceKey,
                                         ValueName,
                                         &Value);
        if (!NT_SUCCESS(status))
            goto fail1;

        (VOID) RegistryUpdateDwordValue(DestinationKey,
                                        ValueName,
                                        Value);

        break;
    }
    case REG_SZ:
    case REG_MULTI_SZ: {
        PANSI_STRING    Value;

        status = RegistryQuerySzValue(SourceKey,
                                      ValueName,
                                      NULL,
                                      &Value);
        if (!NT_SUCCESS(status))
            goto fail1;

        (VOID) RegistryUpdateSzValue(DestinationKey,
                                     ValueName,
                                     Type,
                                     Value);

        RegistryFreeSzValue(Value);

        break;
    }
    case REG_BINARY: {
        PVOID   Value;
        ULONG   Length;

        status = RegistryQueryBinaryValue(SourceKey,
                                          ValueName,
                                          &Value,
                                          &Length);
        if (!NT_SUCCESS(status))
            goto fail1;

        (VOID) RegistryUpdateBinaryValue(DestinationKey,
                                         ValueName,
                                         Value,
                                         Length);
        if (Length != 0)
            RegistryFreeBinaryValue(Value);

        break;
    }
    default:
        ASSERT(FALSE);
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

typedef struct _SETTINGS_COPY_SUBKEY_VALUE_PARAMETERS {
    HANDLE  DestinationKey;
} SETTINGS_COPY_SUBKEY_VALUE_PARAMETERS, *PSETTINGS_COPY_SUBKEY_VALUE_PARAMETERS;

static NTSTATUS
SettingsCopySubKeyValue(
    IN  PVOID                               Context,
    IN  HANDLE                              Key,
    IN  PANSI_STRING                        ValueName,
    IN  ULONG                               Type
    )
{
    PSETTINGS_COPY_SUBKEY_VALUE_PARAMETERS Parameters = Context;

    return SettingsCopyValue(Parameters->DestinationKey,
                             Key,
                             ValueName->Buffer,
                             Type);
}

static NTSTATUS
SettingsCopySubKey(
    IN  HANDLE                              DestinationKey,
    IN  HANDLE                              SourceKey,
    IN  PCHAR                               SubKeyName
    )
{
    SETTINGS_COPY_SUBKEY_VALUE_PARAMETERS   Parameters;
    HANDLE                                  DestinationSubKey;
    HANDLE                                  SourceSubKey;
    NTSTATUS                                status;

    status = RegistryCreateSubKey(DestinationKey,
                                  SubKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &DestinationSubKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenSubKey(SourceKey,
                                SubKeyName,
                                KEY_READ,
                                &SourceSubKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    RtlZeroMemory(&Parameters, sizeof (Parameters));

    Parameters.DestinationKey = DestinationSubKey;

    status = RegistryEnumerateValues(SourceSubKey,
                                     SettingsCopySubKeyValue,
                                     &Parameters);
    if (!NT_SUCCESS(status))
        goto fail3;

    RegistryCloseKey(SourceSubKey);

    RegistryCloseKey(DestinationSubKey);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RegistryCloseKey(SourceSubKey);

fail2:
    Error("fail2\n");

    RegistryCloseKey(DestinationSubKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define CLASS_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class"

static NTSTATUS
SettingsOpenNetKey(
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     NetKey
    )
{
    HANDLE          ClassKey;
    UNICODE_STRING  Unicode;
    ANSI_STRING     Ansi;
    NTSTATUS        status;

    status = RegistryOpenSubKey(NULL,
                                CLASS_PATH,
                                KEY_ALL_ACCESS,
                                &ClassKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringFromGUID(&GUID_DEVCLASS_NET, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlUnicodeStringToAnsiString(&Ansi, &Unicode, TRUE);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryOpenSubKey(ClassKey,
                                Ansi.Buffer,
                                DesiredAccess,
                                NetKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    RtlFreeAnsiString(&Ansi);

    RtlFreeUnicodeString(&Unicode);

    RegistryCloseKey(ClassKey);

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    RtlFreeAnsiString(&Ansi);

fail3:
    Error("fail3\n");

    RtlFreeUnicodeString(&Unicode);

fail2:
    Error("fail2\n");

    RegistryCloseKey(ClassKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

typedef struct _SETTINGS_MATCH_NET_CFG_INSTANCE_ID_PARAMETERS {
    ANSI_STRING NetCfgInstanceID;
    ANSI_STRING SubKeyName;
} SETTINGS_MATCH_NET_CFG_INSTANCE_ID_PARAMETERS, *PSETTINGS_MATCH_NET_CFG_INSTANCE_ID_PARAMETERS;

static NTSTATUS
SettingsMatchNetCfgInstanceID(
    IN  PVOID                                       Context,
    IN  HANDLE                                      Key,
    IN  PANSI_STRING                                SubKeyName
    )
{
    PSETTINGS_MATCH_NET_CFG_INSTANCE_ID_PARAMETERS  Parameters = Context;
    HANDLE                                          SubKey;
    ANSI_STRING                                     Ansi;
    ULONG                                           Type;
    PANSI_STRING                                    Value;
    NTSTATUS                                        status;

    Trace("====> (%Z)\n", SubKeyName);

    if (Parameters->SubKeyName.Length != 0)
        goto done;

    RtlInitAnsiString(&Ansi, "Properties");

    if (RtlCompareString(&Ansi, SubKeyName, TRUE) == 0)
        goto done;

    status = RegistryOpenSubKey(Key,
                                SubKeyName->Buffer,
                                KEY_READ,
                                &SubKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryQuerySzValue(SubKey,
                                  "NetCfgInstanceID",
                                  &Type,
                                  &Value);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Type != REG_SZ)
        goto fail3;

    if (RtlCompareString(&Parameters->NetCfgInstanceID,
                         &Value[0],
                         TRUE) == 0) {
        Parameters->SubKeyName.MaximumLength = SubKeyName->MaximumLength;
        Parameters->SubKeyName.Buffer = __SettingsAllocate(Parameters->SubKeyName.MaximumLength);

        status = STATUS_NO_MEMORY;
        if (Parameters->SubKeyName.Buffer == NULL)
            goto fail4;

        RtlCopyMemory(Parameters->SubKeyName.Buffer,
                      SubKeyName->Buffer,
                      SubKeyName->Length);

        Parameters->SubKeyName.Length = SubKeyName->Length;
    }

    RegistryFreeSzValue(Value);

    RegistryCloseKey(SubKey);

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    RegistryFreeSzValue(Value);

fail2:
    Error("fail2\n");

    RegistryCloseKey(SubKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsGetAliasNetInstance(
    IN  LPGUID                                      NetCfgInstanceID,
    OUT PANSI_STRING                                SubKeyName
    )
{
    HANDLE                                          NetKey;
    UNICODE_STRING                                  Unicode;
    ANSI_STRING                                     Ansi;
    SETTINGS_MATCH_NET_CFG_INSTANCE_ID_PARAMETERS   Parameters;
    NTSTATUS                                        status;

    status = SettingsOpenNetKey(KEY_READ, &NetKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringFromGUID(NetCfgInstanceID, &Unicode);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlUnicodeStringToAnsiString(&Ansi, &Unicode, TRUE);
    if (!NT_SUCCESS(status))
        goto fail3;

    RtlZeroMemory(&Parameters, sizeof (Parameters));

    Parameters.NetCfgInstanceID = Ansi;

    status = RegistryEnumerateSubKeys(NetKey,
                                      SettingsMatchNetCfgInstanceID,
                                      &Parameters);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = STATUS_UNSUCCESSFUL;
    if (Parameters.SubKeyName.Length == 0)
        goto fail5;

    Info("%Z\n", &Parameters.SubKeyName);

    *SubKeyName = Parameters.SubKeyName;

    RegistryCloseKey(NetKey);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    RtlFreeAnsiString(&Ansi);

fail3:
    Error("fail3\n");

    RtlFreeUnicodeString(&Unicode);

fail2:
    Error("fail2\n");

    RegistryCloseKey(NetKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
SettingsCopyLinkage(
    IN HANDLE       DestinationKey,
    IN HANDLE       SourceKey
    )
{
    NTSTATUS        status;

    Trace("====>\n");

    status = SettingsCopyValue(DestinationKey,
                               SourceKey,
                               "NetCfgInstanceID",
                               REG_SZ);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = SettingsCopyValue(DestinationKey,
                               SourceKey,
                               "NetLuidIndex",
                               REG_DWORD);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = SettingsCopySubKey(DestinationKey,
                                SourceKey,
                                "Linkage");
    if (!NT_SUCCESS(status))
        goto fail3;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
SettingsStealIdentity(
    IN HANDLE   SoftwareKey,
    IN PWCHAR   Alias,
    IN PWCHAR   Description,
    IN LPGUID   NetCfgInstanceID
    )
{
    ANSI_STRING SubKeyName;
    HANDLE      NetKey;
    HANDLE      SubKey;
    NTSTATUS    status;

    Info("%ws (%ws)\n", Alias, Description);

    status = SettingsGetAliasNetInstance(NetCfgInstanceID,
                                         &SubKeyName);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryUpdateSzValue(SoftwareKey,
                                   "AliasNetInstance",
                                   REG_SZ,
                                   &SubKeyName);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = SettingsOpenNetKey(KEY_READ, &NetKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryOpenSubKey(NetKey,
                                SubKeyName.Buffer,
                                KEY_READ,
                                &SubKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = SettingsCopyLinkage(SoftwareKey,
                                 SubKey);
    if (!NT_SUCCESS(status))
        goto fail5;

    RegistryCloseKey(SubKey);

    RegistryCloseKey(NetKey);

    __SettingsFree(SubKeyName.Buffer);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    RegistryCloseKey(SubKey);

fail4:
    Error("fail4\n");

    RegistryCloseKey(NetKey);

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    __SettingsFree(SubKeyName.Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
