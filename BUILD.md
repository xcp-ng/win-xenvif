Building the XenVif Package
===========================

## Prerequisites

- [Visual Studio 2019](https://visualstudio.microsoft.com/vs/older-downloads/)
- [Windows 10 SDK (10.0.18362.0)](https://developer.microsoft.com/fr-fr/windows/downloads/sdk-archive/)
- [Windows Driver Kit (WDK) for Windows 10, version 1903 (10.0.18362.0)](https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads)
- [Spectre mitigated libraries](https://docs.microsoft.com/en-us/cpp/build/reference/spectre?view=msvc-160) (Install the latest version via Visual Studio Installer under Individual components)

Note: Visual Studio 2019 and the WDK for Windows 10, version 1903 (10.0.18362.0) (and not above) are required to build the 32-bit version of the driver for Windows 8 and 10.
For building 64 bits drivers for Windows 10, 11 and above, you will need corresponding WDK for Windows 11.

## Setting PowerShell Execution Policy

Before running the build script, you may need to change the PowerShell execution policy to allow the execution of unsigned scripts. You can do this by opening a PowerShell prompt as an administrator and running the following command:

powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

## Building with Visual Studio

1. Open the Visual Studio 2019 Command Prompt. You can find this by searching for "Command Prompt" in the start menu, and it should be listed under Visual Studio 2019.

2. Navigate to the directory where your `build.ps1` script is located using the `cd` command.

3. Run the `build.ps1` script with the `powershell` command. For example: `powershell .\build.ps1`.

## Building with EWDK

If you cannot install Visual Studio 2019, you can use the EWDK to build the project. Follow the instructions provided by Microsoft to download and set up the EWDK.

1. Open the EWDK environment.

2. Navigate to the directory where your `build.ps1` script is located using the `cd` command.

3. Run the `build.ps1` script with the `powershell` command. For example: `powershell .\build.ps1`.

This will then prompt you for whether you want a 'free' (non-debug) or a
'checked' (debug) build and then proceed to build all x86 and x64 drivers.

NOTE: Because the EWDKs do not contain the 'dpinst' re-distributable driver
installer utility, this will not be included in the built driver package
by default. However, if you set the environment variable DPINST_REDIST to
point to a directory with x86 and x64 sub-directories containing 32- and
64-bit dpinst.exe binaries (respectively) then these will be copied into
the built packages, making installation more convenient.
