import os
import sys
import base64
import random
from collections import deque

os.environ["DOTNET_ROOT"] = r"/usr/share/dotnet/"
psHome = r"/opt/microsoft/powershell/7/"

########################### Init ###########################

from pythonnet import load

load("coreclr")
import clr
import System
from System import Environment

mmi = psHome + r"Microsoft.Management.Infrastructure.dll"
clr.AddReference(mmi)
from Microsoft.Management.Infrastructure import *

sma = psHome + r"System.Management.Automation.dll"
clr.AddReference(sma)
from System.Management.Automation import *
from System.Management.Automation.Language import Parser
from System.Management.Automation import PSParser

########################### Constants ###########################

GetMember_Alternate = {
    '[runtime.interopservices.marshal].getmembers()[3].name': '"PtrToStringAuto"',
    '[runtime.interopservices.marshal].getmembers()[5].name': '"PtrToStringAuto"',
    '[runtime.interopservices.marshal].getmembers()[2].name': '"PtrToStringUni"',
    '[runtime.interopservices.marshal].getmembers()[4].name': '"PtrToStringUni"',
    '[runtime.interopservices.marshal].getmembers()[0].name': '"PtrToStringAnsi"',
    '[runtime.interopservices.marshal].getmembers()[1].name': '"PtrToStringAnsi"'
}

Get_Variables = {
    "ConsoleFileName": None,
    "MaximumAliasCount": 4096,
    "MaximumDriveCount": 4096,
    "MaximumErrorCount": 256,
    "MaximumFunctionCount": 4096,
    "MaximumVariableCount": 4096,
    "PROFILE": "C:\\Users\\Administrator\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
}

ENV_VARIABLES = {
    "ALLUSERSPROFILE": r"C:\ProgramData",
    "APPDATA": r"C:\Users\Administrator\AppData\Roaming",
    "CommonProgramFiles": r"C:\Program Files\Common Files",
    "CommonProgramW6432": r"C:\Program Files\Common Files",
    "ComSpec": r"C:\Windows\system32\cmd.exe",
    "FPS_BROWSER_APP_PROFILE_STRING": r"Internet Explorer",
    "FPS_BROWSER_USER_PROFILE_STRING": r"Default",
    "HOMEDRIVE": r"C:",
    "HOMEPATH": r"\Users\Administrator",
    "LOCALAPPDATA": r"C:\Users\Administrator\AppData\Local",
    "OS": r"Windows_NT",
    "Path": r"C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\Git\cmd;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Users\Administrator\AppData\Local\Programs\Microsoft VS Code\bin",
    "PATHEXT": r".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL",
    "PROCESSOR_ARCHITECTURE": r"AMD64",
    "ProgramData": r"C:\ProgramData",
    "ProgramFiles": r"C:\Program Files",
    "ProgramW6432": r"C:\Program Files",
    "PUBLIC": r"C:\Users\Public",
    "SESSIONNAME": r"Console",
    "SystemDrive": r"C:",
    "SystemRoot": r"C:\Windows",
    "TEMP": r"C:\Users\ADMINI~1\AppData\Local\Temp",
    "TMP": r"C:\Users\ADMINI~1\AppData\Local\Temp",
    "USERNAME": r"Administrator",
    "USERPROFILE": r"C:\Users\Administrator",
    "windir": r"C:\Windows",
    "WXDRIVE_START_ARGS": r"--wxdrive-setting=0 --disable-gpu --disable-software-rasterizer --enable-features=NetworkServiceInProcess"
}

CoreSafeAliases = {
    "%": "ForEach-Object",
    "?": "Where-Object",
    "cd": "Set-Location",
    "chdir": "Set-Location",
    "clc": "Clear-Content",
    "clear": "Clear-Host",
    "clhy": "Clear-History",
    "cli": "Clear-Item",
    "clp": "Clear-ItemProperty",
    "cls": "Clear-Host",
    "clv": "Clear-Variable",
    "cnsn": "Connect-PSSession",
    "copy": "Copy-Item",
    "cpi": "Copy-Item",
    "cvpa": "Convert-Path",
    "dbp": "Disable-PSBreakpoint",
    "del": "Remove-Item",
    "dir": "Get-ChildItem",
    "dnsn": "Disconnect-PSSession",
    "ebp": "Enable-PSBreakpoint",
    "echo": "Write-Output",
    "epal": "Export-Alias",
    "epcsv": "Export-Csv",
    "erase": "Remove-Item",
    "etsn": "Enter-PSSession",
    "exsn": "Exit-PSSession",
    "fc": "Format-Custom",
    "fhx": "Format-Hex",
    "fl": "Format-List",
    "foreach": "ForEach-Object",
    "ft": "Format-Table",
    "fw": "Format-Wide",
    "gal": "Get-Alias",
    "gbp": "Get-PSBreakpoint",
    "gc": "Get-Content",
    "gci": "Get-ChildItem",
    "gcm": "Get-Command",
    "gcs": "Get-PSCallStack",
    "gdr": "Get-PSDrive",
    "ghy": "Get-History",
    "gi": "Get-Item",
    "gjb": "Get-Job",
    "gl": "Get-Location",
    "gm": "Get-Member",
    "gmo": "Get-Module",
    "gp": "Get-ItemProperty",
    "gps": "Get-Process",
    "gpv": "Get-ItemPropertyValue",
    "group": "Group-Object",
    "gsn": "Get-PSSession",
    "gtz": "Get-TimeZone",
    "gu": "Get-Unique",
    "gv": "Get-Variable",
    "h": "Get-History",
    "history": "Get-History",
    "icm": "Invoke-Command",
    "iex": "Invoke-Expression",
    "ihy": "Invoke-History",
    "ii": "Invoke-Item",
    "ipal": "Import-Alias",
    "ipcsv": "Import-Csv",
    "ipmo": "Import-Module",
    "irm": "Invoke-RestMethod",
    "iwr": "Invoke-WebRequest",
    "kill": "Stop-Process",
    "md": "mkdir",
    "measure": "Measure-Object",
    "mi": "Move-Item",
    "move": "Move-Item",
    "mp": "Move-ItemProperty",
    "nal": "New-Alias",
    "ndr": "New-PSDrive",
    "ni": "New-Item",
    "nmo": "New-Module",
    "nsn": "New-PSSession",
    "nv": "New-Variable",
    "oh": "Out-Host",
    "popd": "Pop-Location",
    "pushd": "Push-Location",
    "pwd": "Get-Location",
    "r": "Invoke-History",
    "rbp": "Remove-PSBreakpoint",
    "rcjb": "Receive-Job",
    "rcsn": "Receive-PSSession",
    "rd": "Remove-Item",
    "rdr": "Remove-PSDrive",
    "ren": "Rename-Item",
    "ri": "Remove-Item",
    "rjb": "Remove-Job",
    "rmo": "Remove-Module",
    "rni": "Rename-Item",
    "rnp": "Rename-ItemProperty",
    "rp": "Remove-ItemProperty",
    "rsn": "Remove-PSSession",
    "rv": "Remove-Variable",
    "rvpa": "Resolve-Path",
    "sajb": "Start-Job",
    "sal": "Set-Alias",
    "saps": "Start-Process",
    "sbp": "Set-PSBreakpoint",
    "sc": "Set-Content",
    "select": "Select-Object",
    "set": "Set-Variable",
    "si": "Set-Item",
    "sl": "Set-Location",
    "sls": "Select-String",
    "sp": "Set-ItemProperty",
    "spjb": "Stop-Job",
    "spps": "Stop-Process",
    "sv": "Set-Variable",
    "type": "Get-Content",
    "where": "Where-Object",
    "wjb": "Wait-Job",
}

OtherValidNames = {
    "Keyword": {
        "Begin": "Begin",
        "Break": "Break",
        "Catch": "Catch",
        "Class": "Class",
        "Classes": "Classes",
        "Continue": "Continue",
        "Data": "Data",
        "Define": "Define",
        "Do": "Do",
        "Do-Until": "Do-Until",
        "Do-While": "Do-While",
        "DynamicParam": "DynamicParam",
        "Else": "Else",
        "Elseif": "Elseif",
        "End": "End",
        "Enum": "Enum",
        "Exit": "Exit",
        "Filter": "Filter",
        "Finally": "Finally",
        "For": "For",
        "ForEach": "ForEach",
        "From": "From",
        "Function": "Function",
        "Hidden": "Hidden",
        "If": "If",
        "In": "In",
        "InlineScript": "InlineScript",
        "Param": "Param",
        "Process": "Process",
        "Return": "Return",
        "Static": "Static",
        "Switch": "Switch",
        "Throw": "Throw",
        "Trap": "Trap",
        "Try": "Try",
        "Until": "Until",
        "Using": "Using",
        "Var": "Var",
        "While": "While",
    },
    "Operator": {
        "-And": "-And",
        "-As": "-As",
        "-Band": "-Band",
        "-Bnot": "-Bnot",
        "-Bor": "-Bor",
        "-Bxor": "-Bxor",
        "-Contains": "-Contains",
        "-Creplace": "-Creplace",
        "-In": "-In",
        "-Is": "-Is",
        "-Isnot": "-Isnot",
        "-Join": "-Join",
        "-Like": "-Like",
        "-Match": "-Match",
        "-Not": "-Not",
        "-Notcontains": "-Notcontains",
        "-Notin": "-Notin",
        "-Notlike": "-Notlike",
        "-Notmatch": "-Notmatch",
        "-Or": "-Or",
        "-Replace": "-Replace",
        "-Shl": "-Shl",
        "-Shr": "-Shr",
        "-Split": "-Split",
        "-Xor": "-Xor",
        "-eq": "-eq",
        "-ge": "-ge",
        "-gt": "-gt",
        "-le": "-le",
        "-lt": "-lt",
        "-ne": "-ne",
    },
    "Type": {
        "[AliasAttribute]": "[AliasAttribute]",
        "[AllowEmptyCollectionAttribute]": "[AllowEmptyCollectionAttribute]",
        "[AllowEmptyStringAttribute]": "[AllowEmptyStringAttribute]",
        "[AllowNullAttribute]": "[AllowNullAttribute]",
        "[ArgumentCompleterAttribute]": "[ArgumentCompleterAttribute]",
        "[ArgumentCompletionsAttribute]": "[ArgumentCompletionsAttribute]",
        "[Array]": "[Array]",
        "[BigInteger]": "[BigInteger]",
        "[Boolean]": "[Boolean]",
        "[Byte]": "[Byte]",
        "[Char]": "[Char]",
        "[CimClass]": "[CimClass]",
        "[CimConverter]": "[CimConverter]",
        "[CimInstance]": "[CimInstance]",
        "[CimSession]": "[CimSession]",
        "[CimType]": "[CimType]",
        "[CmdletBindingAttribute]": "[CmdletBindingAttribute]",
        "[CultureInfo]": "[CultureInfo]",
        "[DateTime]": "[DateTime]",
        "[Decimal]": "[Decimal]",
        "[Deserialized.Microsoft.PowerShell.Commands.Internal.Format.FormatInfoData]": "[Deserialized.Microsoft.PowerShell.Commands.Internal.Format.FormatInfoData]",
        "[Deserialized.System.Diagnostics.Process]": "[Deserialized.System.Diagnostics.Process]",
        "[Deserialized.System.Enum]": "[Deserialized.System.Enum]",
        "[Deserialized.System.Globalization.CultureInfo]": "[Deserialized.System.Globalization.CultureInfo]",
        "[Deserialized.System.Management.Automation.BreakpointUpdatedEventArgs]": "[Deserialized.System.Management.Automation.BreakpointUpdatedEventArgs]",
        "[Deserialized.System.Management.Automation.Breakpoint]": "[Deserialized.System.Management.Automation.Breakpoint]",
        "[Deserialized.System.Management.Automation.DebuggerCommandResults]": "[Deserialized.System.Management.Automation.DebuggerCommandResults]",
        "[Deserialized.System.Management.Automation.DebuggerCommand]": "[Deserialized.System.Management.Automation.DebuggerCommand]",
        "[Deserialized.System.Management.Automation.DisplayEntry]": "[Deserialized.System.Management.Automation.DisplayEntry]",
        "[Deserialized.System.Management.Automation.ExtendedTypeDefinition]": "[Deserialized.System.Management.Automation.ExtendedTypeDefinition]",
        "[Deserialized.System.Management.Automation.FormatViewDefinition]": "[Deserialized.System.Management.Automation.FormatViewDefinition]",
        "[Deserialized.System.Management.Automation.JobStateInfo]": "[Deserialized.System.Management.Automation.JobStateInfo]",
        "[Deserialized.System.Management.Automation.ListControlEntryItem]": "[Deserialized.System.Management.Automation.ListControlEntryItem]",
        "[Deserialized.System.Management.Automation.ListControlEntry]": "[Deserialized.System.Management.Automation.ListControlEntry]",
        "[Deserialized.System.Management.Automation.PSControl]": "[Deserialized.System.Management.Automation.PSControl]",
        "[Deserialized.System.Management.Automation.PSCredential]": "[Deserialized.System.Management.Automation.PSCredential]",
        "[Deserialized.System.Management.Automation.PSListModifier]": "[Deserialized.System.Management.Automation.PSListModifier]",
        "[Deserialized.System.Management.Automation.PSPrimitiveDictionary]": "[Deserialized.System.Management.Automation.PSPrimitiveDictionary]",
        "[Deserialized.System.Management.Automation.ParameterSetMetadata]": "[Deserialized.System.Management.Automation.ParameterSetMetadata]",
        "[Deserialized.System.Management.Automation.SwitchParameter]": "[Deserialized.System.Management.Automation.SwitchParameter]",
        "[Deserialized.System.Management.Automation.TableControlColumnHeader]": "[Deserialized.System.Management.Automation.TableControlColumnHeader]",
        "[Deserialized.System.Management.Automation.TableControlColumn]": "[Deserialized.System.Management.Automation.TableControlColumn]",
        "[Deserialized.System.Management.Automation.TableControlRow]": "[Deserialized.System.Management.Automation.TableControlRow]",
        "[Deserialized.System.Management.Automation.WideControlEntryItem]": "[Deserialized.System.Management.Automation.WideControlEntryItem]",
        "[Deserialized.System.Management.ManagementEventArgs]": "[Deserialized.System.Management.ManagementEventArgs]",
        "[Deserialized.System.Net.IPAddress]": "[Deserialized.System.Net.IPAddress]",
        "[Deserialized.System.Net.Mail.MailAddress]": "[Deserialized.System.Net.Mail.MailAddress]",
        "[Deserialized.System.Security.AccessControl.FileSystemSecurity]": "[Deserialized.System.Security.AccessControl.FileSystemSecurity]",
        "[Deserialized.System.Security.AccessControl.RegistrySecurity]": "[Deserialized.System.Security.AccessControl.RegistrySecurity]",
        "[Deserialized.System.Security.Cryptography.X509Certificates.X500DistinguishedName]": "[Deserialized.System.Security.Cryptography.X509Certificates.X500DistinguishedName]",
        "[Deserialized.System.Security.Cryptography.X509Certificates.X509Certificate2]": "[Deserialized.System.Security.Cryptography.X509Certificates.X509Certificate2]",
        "[Deserialized.System.ServiceProcess.ServiceController]": "[Deserialized.System.ServiceProcess.ServiceController]",
        "[DirectoryEntry]": "[DirectoryEntry]",
        "[DirectorySearcher]": "[DirectorySearcher]",
        "[Double]": "[Double]",
        "[DscLocalConfigurationManagerAttribute]": "[DscLocalConfigurationManagerAttribute]",
        "[DscPropertyAttribute]": "[DscPropertyAttribute]",
        "[DscResourceAttribute]": "[DscResourceAttribute]",
        "[ExperimentAction]": "[ExperimentAction]",
        "[ExperimentalAttribute]": "[ExperimentalAttribute]",
        "[ExperimentalFeature]": "[ExperimentalFeature]",
        "[Guid]": "[Guid]",
        "[Hashtable]": "[Hashtable]",
        "[HelpInfo]": "[HelpInfo]",
        "[IPAddress]": "[IPAddress]",
        "[IPEndPoint]": "[IPEndPoint]",
        "[InitialSessionState]": "[InitialSessionState]",
        "[Int16]": "[Int16]",
        "[Int32]": "[Int32]",
        "[Int64]": "[Int64]",
        "[MailAddress]": "[MailAddress]",
        "[ManagementClass]": "[ManagementClass]",
        "[ManagementObjectSearcher]": "[ManagementObjectSearcher]",
        "[ManagementObject]": "[ManagementObject]",
        "[Microsoft.Management.Infrastructure.CimClass]": "[Microsoft.Management.Infrastructure.CimClass]",
        "[Microsoft.Management.Infrastructure.CimCmdlets.CimIndicationEventInstanceEventArgs]": "[Microsoft.Management.Infrastructure.CimCmdlets.CimIndicationEventInstanceEventArgs]",
        "[Microsoft.Management.Infrastructure.CimConverter]": "[Microsoft.Management.Infrastructure.CimConverter]",
        "[Microsoft.Management.Infrastructure.CimInstance]": "[Microsoft.Management.Infrastructure.CimInstance]",
        "[Microsoft.Management.Infrastructure.CimSession]": "[Microsoft.Management.Infrastructure.CimSession]",
        "[Microsoft.Management.Infrastructure.CimType]": "[Microsoft.Management.Infrastructure.CimType]",
        "[Microsoft.PowerShell.Commands.HistoryInfo]": "[Microsoft.PowerShell.Commands.HistoryInfo]",
        "[Microsoft.PowerShell.Commands.Internal.Format.FormatInfoData]": "[Microsoft.PowerShell.Commands.Internal.Format.FormatInfoData]",
        "[Microsoft.PowerShell.Commands.PSPropertyExpression]": "[Microsoft.PowerShell.Commands.PSPropertyExpression]",
        "[Microsoft.PowerShell.DeserializingTypeConverter]": "[Microsoft.PowerShell.DeserializingTypeConverter]",
        "[NullString]": "[NullString]",
        "[ObjectSecurity]": "[ObjectSecurity]",
        "[OutputTypeAttribute]": "[OutputTypeAttribute]",
        "[PSAliasProperty]": "[PSAliasProperty]",
        "[PSCredential]": "[PSCredential]",
        "[PSDefaultValueAttribute]": "[PSDefaultValueAttribute]",
        "[PSListModifier]": "[PSListModifier]",
        "[PSModuleInfo]": "[PSModuleInfo]",
        "[PSNoteProperty]": "[PSNoteProperty]",
        "[PSObject]": "[PSObject]",
        "[PSPrimitiveDictionary]": "[PSPrimitiveDictionary]",
        "[PSPropertyExpression]": "[PSPropertyExpression]",
        "[PSReference]": "[PSReference]",
        "[PSScriptMethod]": "[PSScriptMethod]",
        "[PSScriptProperty]": "[PSScriptProperty]",
        "[PSTypeNameAttribute]": "[PSTypeNameAttribute]",
        "[PSVariableProperty]": "[PSVariableProperty]",
        "[PSVariable]": "[PSVariable]",
        "[ParameterAttribute]": "[ParameterAttribute]",
        "[PhysicalAddress]": "[PhysicalAddress]",
        "[PowerShell]": "[PowerShell]",
        "[Regex]": "[Regex]",
        "[RunspaceFactory]": "[RunspaceFactory]",
        "[Runspace]": "[Runspace]",
        "[SByte]": "[SByte]",
        "[ScriptBlock]": "[ScriptBlock]",
        "[SecureString]": "[SecureString]",
        "[SemanticVersion]": "[SemanticVersion]",
        "[Single]": "[Single]",
        "[String]": "[String]",
        "[SupportsWildcardsAttribute]": "[SupportsWildcardsAttribute]",
        "[SwitchParameter]": "[SwitchParameter]",
        "[System.Array]": "[System.Array]",
        "[System.Boolean]": "[System.Boolean]",
        "[System.Byte]": "[System.Byte]",
        "[System.Char]": "[System.Char]",
        "[System.Collections.DictionaryEntry]": "[System.Collections.DictionaryEntry]",
        "[System.Collections.Hashtable]": "[System.Collections.Hashtable]",
        "[System.DateTime]": "[System.DateTime]",
        "[System.Decimal]": "[System.Decimal]",
        "[System.Diagnostics.EventLogEntry]": "[System.Diagnostics.EventLogEntry]",
        "[System.Diagnostics.FileVersionInfo]": "[System.Diagnostics.FileVersionInfo]",
        "[System.Diagnostics.ProcessModule]": "[System.Diagnostics.ProcessModule]",
        "[System.Diagnostics.Process]": "[System.Diagnostics.Process]",
        "[System.DirectoryServices.DirectoryEntry]": "[System.DirectoryServices.DirectoryEntry]",
        "[System.DirectoryServices.DirectorySearcher]": "[System.DirectoryServices.DirectorySearcher]",
        "[System.DirectoryServices.PropertyValueCollection]": "[System.DirectoryServices.PropertyValueCollection]",
        "[System.Double]": "[System.Double]",
        "[System.Drawing.Printing.PrintDocument]": "[System.Drawing.Printing.PrintDocument]",
        "[System.Globalization.CultureInfo]": "[System.Globalization.CultureInfo]",
        "[System.Guid]": "[System.Guid]",
        "[System.IO.DirectoryInfo]": "[System.IO.DirectoryInfo]",
        "[System.IO.FileInfo]": "[System.IO.FileInfo]",
        "[System.Int16]": "[System.Int16]",
        "[System.Int32]": "[System.Int32]",
        "[System.Int64]": "[System.Int64]",
        "[System.Management.Automation.AliasAttribute]": "[System.Management.Automation.AliasAttribute]",
        "[System.Management.Automation.AliasInfo]": "[System.Management.Automation.AliasInfo]",
        "[System.Management.Automation.AllowEmptyCollectionAttribute]": "[System.Management.Automation.AllowEmptyCollectionAttribute]",
        "[System.Management.Automation.AllowEmptyStringAttribute]": "[System.Management.Automation.AllowEmptyStringAttribute]",
        "[System.Management.Automation.AllowNullAttribute]": "[System.Management.Automation.AllowNullAttribute]",
        "[System.Management.Automation.ApplicationInfo]": "[System.Management.Automation.ApplicationInfo]",
        "[System.Management.Automation.ArgumentCompleterAttribute]": "[System.Management.Automation.ArgumentCompleterAttribute]",
        "[System.Management.Automation.ArgumentCompletionsAttribute]": "[System.Management.Automation.ArgumentCompletionsAttribute]",
        "[System.Management.Automation.BreakpointUpdatedEventArgs]": "[System.Management.Automation.BreakpointUpdatedEventArgs]",
        "[System.Management.Automation.Breakpoint]": "[System.Management.Automation.Breakpoint]",
        "[System.Management.Automation.CallStackFrame]": "[System.Management.Automation.CallStackFrame]",
        "[System.Management.Automation.CmdletBindingAttribute]": "[System.Management.Automation.CmdletBindingAttribute]",
        "[System.Management.Automation.CmdletInfo]": "[System.Management.Automation.CmdletInfo]",
        "[System.Management.Automation.CommandInfo]": "[System.Management.Automation.CommandInfo]",
        "[System.Management.Automation.DebuggerCommandResults]": "[System.Management.Automation.DebuggerCommandResults]",
        "[System.Management.Automation.DebuggerCommand]": "[System.Management.Automation.DebuggerCommand]",
        "[System.Management.Automation.DisplayEntry]": "[System.Management.Automation.DisplayEntry]",
        "[System.Management.Automation.DscLocalConfigurationManagerAttribute]": "[System.Management.Automation.DscLocalConfigurationManagerAttribute]",
        "[System.Management.Automation.DscPropertyAttribute]": "[System.Management.Automation.DscPropertyAttribute]",
        "[System.Management.Automation.DscResourceAttribute]": "[System.Management.Automation.DscResourceAttribute]",
        "[System.Management.Automation.ErrorRecord]": "[System.Management.Automation.ErrorRecord]",
        "[System.Management.Automation.ExperimentAction]": "[System.Management.Automation.ExperimentAction]",
        "[System.Management.Automation.ExperimentalAttribute]": "[System.Management.Automation.ExperimentalAttribute]",
        "[System.Management.Automation.ExperimentalFeature]": "[System.Management.Automation.ExperimentalFeature]",
        "[System.Management.Automation.ExtendedTypeDefinition]": "[System.Management.Automation.ExtendedTypeDefinition]",
        "[System.Management.Automation.FormatViewDefinition]": "[System.Management.Automation.FormatViewDefinition]",
        "[System.Management.Automation.JobStateInfo]": "[System.Management.Automation.JobStateInfo]",
        "[System.Management.Automation.Job]": "[System.Management.Automation.Job]",
        "[System.Management.Automation.Language.NullString]": "[System.Management.Automation.Language.NullString]",
        "[System.Management.Automation.ListControlEntryItem]": "[System.Management.Automation.ListControlEntryItem]",
        "[System.Management.Automation.ListControlEntry]": "[System.Management.Automation.ListControlEntry]",
        "[System.Management.Automation.OutputTypeAttribute]": "[System.Management.Automation.OutputTypeAttribute]",
        "[System.Management.Automation.PSAliasProperty]": "[System.Management.Automation.PSAliasProperty]",
        "[System.Management.Automation.PSControl]": "[System.Management.Automation.PSControl]",
        "[System.Management.Automation.PSCredential]": "[System.Management.Automation.PSCredential]",
        "[System.Management.Automation.PSDefaultValueAttribute]": "[System.Management.Automation.PSDefaultValueAttribute]",
        "[System.Management.Automation.PSDriveInfo]": "[System.Management.Automation.PSDriveInfo]",
        "[System.Management.Automation.PSListModifier]": "[System.Management.Automation.PSListModifier]",
        "[System.Management.Automation.PSModuleInfo]": "[System.Management.Automation.PSModuleInfo]",
        "[System.Management.Automation.PSNoteProperty]": "[System.Management.Automation.PSNoteProperty]",
        "[System.Management.Automation.PSObject]": "[System.Management.Automation.PSObject]",
        "[System.Management.Automation.PSPrimitiveDictionary]": "[System.Management.Automation.PSPrimitiveDictionary]",
        "[System.Management.Automation.PSReference]": "[System.Management.Automation.PSReference]",
        "[System.Management.Automation.PSScriptMethod]": "[System.Management.Automation.PSScriptMethod]",
        "[System.Management.Automation.PSScriptProperty]": "[System.Management.Automation.PSScriptProperty]",
        "[System.Management.Automation.PSTypeNameAttribute]": "[System.Management.Automation.PSTypeNameAttribute]",
        "[System.Management.Automation.PSTypeName]": "[System.Management.Automation.PSTypeName]",
        "[System.Management.Automation.PSVariableProperty]": "[System.Management.Automation.PSVariableProperty]",
        "[System.Management.Automation.PSVariable]": "[System.Management.Automation.PSVariable]",
        "[System.Management.Automation.ParameterAttribute]": "[System.Management.Automation.ParameterAttribute]",
        "[System.Management.Automation.ParameterMetadata]": "[System.Management.Automation.ParameterMetadata]",
        "[System.Management.Automation.ParameterSetMetadata]": "[System.Management.Automation.ParameterSetMetadata]",
        "[System.Management.Automation.PowerShell]": "[System.Management.Automation.PowerShell]",
        "[System.Management.Automation.Runspaces.InitialSessionState]": "[System.Management.Automation.Runspaces.InitialSessionState]",
        "[System.Management.Automation.Runspaces.PSSession]": "[System.Management.Automation.Runspaces.PSSession]",
        "[System.Management.Automation.Runspaces.RunspaceFactory]": "[System.Management.Automation.Runspaces.RunspaceFactory]",
        "[System.Management.Automation.Runspaces.Runspace]": "[System.Management.Automation.Runspaces.Runspace]",
        "[System.Management.Automation.ScriptBlock]": "[System.Management.Automation.ScriptBlock]",
        "[System.Management.Automation.SemanticVersion]": "[System.Management.Automation.SemanticVersion]",
        "[System.Management.Automation.Signature]": "[System.Management.Automation.Signature]",
        "[System.Management.Automation.SupportsWildcardsAttribute]": "[System.Management.Automation.SupportsWildcardsAttribute]",
        "[System.Management.Automation.SwitchParameter]": "[System.Management.Automation.SwitchParameter]",
        "[System.Management.Automation.TableControlColumnHeader]": "[System.Management.Automation.TableControlColumnHeader]",
        "[System.Management.Automation.TableControlColumn]": "[System.Management.Automation.TableControlColumn]",
        "[System.Management.Automation.TableControlRow]": "[System.Management.Automation.TableControlRow]",
        "[System.Management.Automation.ValidateCountAttribute]": "[System.Management.Automation.ValidateCountAttribute]",
        "[System.Management.Automation.ValidateDriveAttribute]": "[System.Management.Automation.ValidateDriveAttribute]",
        "[System.Management.Automation.ValidateLengthAttribute]": "[System.Management.Automation.ValidateLengthAttribute]",
        "[System.Management.Automation.ValidateNotNullAttribute]": "[System.Management.Automation.ValidateNotNullAttribute]",
        "[System.Management.Automation.ValidateNotNullOrEmptyAttribute]": "[System.Management.Automation.ValidateNotNullOrEmptyAttribute]",
        "[System.Management.Automation.ValidatePatternAttribute]": "[System.Management.Automation.ValidatePatternAttribute]",
        "[System.Management.Automation.ValidateRangeAttribute]": "[System.Management.Automation.ValidateRangeAttribute]",
        "[System.Management.Automation.ValidateScriptAttribute]": "[System.Management.Automation.ValidateScriptAttribute]",
        "[System.Management.Automation.ValidateSetAttribute]": "[System.Management.Automation.ValidateSetAttribute]",
        "[System.Management.Automation.ValidateTrustedDataAttribute]": "[System.Management.Automation.ValidateTrustedDataAttribute]",
        "[System.Management.Automation.ValidateUserDriveAttribute]": "[System.Management.Automation.ValidateUserDriveAttribute]",
        "[System.Management.Automation.WideControlEntryItem]": "[System.Management.Automation.WideControlEntryItem]",
        "[System.Management.Automation.WildcardPattern]": "[System.Management.Automation.WildcardPattern]",
        "[System.Management.ManagementBaseObject]": "[System.Management.ManagementBaseObject]",
        "[System.Management.ManagementClass]": "[System.Management.ManagementClass]",
        "[System.Management.ManagementEventArgs]": "[System.Management.ManagementEventArgs]",
        "[System.Management.ManagementObjectSearcher]": "[System.Management.ManagementObjectSearcher]",
        "[System.Management.ManagementObject]": "[System.Management.ManagementObject]",
        "[System.Net.IPAddress]": "[System.Net.IPAddress]",
        "[System.Net.IPEndPoint]": "[System.Net.IPEndPoint]",
        "[System.Net.Mail.MailAddress]": "[System.Net.Mail.MailAddress]",
        "[System.Net.NetworkInformation.PhysicalAddress]": "[System.Net.NetworkInformation.PhysicalAddress]",
        "[System.Numerics.BigInteger]": "[System.Numerics.BigInteger]",
        "[System.SByte]": "[System.SByte]",
        "[System.Security.AccessControl.FileSystemSecurity]": "[System.Security.AccessControl.FileSystemSecurity]",
        "[System.Security.AccessControl.ObjectSecurity]": "[System.Security.AccessControl.ObjectSecurity]",
        "[System.Security.AccessControl.RegistrySecurity]": "[System.Security.AccessControl.RegistrySecurity]",
        "[System.Security.Cryptography.X509Certificates.X500DistinguishedName]": "[System.Security.Cryptography.X509Certificates.X500DistinguishedName]",
        "[System.Security.Cryptography.X509Certificates.X509Certificate2]": "[System.Security.Cryptography.X509Certificates.X509Certificate2]",
        "[System.Security.Cryptography.X509Certificates.X509Certificate]": "[System.Security.Cryptography.X509Certificates.X509Certificate]",
        "[System.Security.SecureString]": "[System.Security.SecureString]",
        "[System.ServiceProcess.ServiceController]": "[System.ServiceProcess.ServiceController]",
        "[System.Single]": "[System.Single]",
        "[System.String]": "[System.String]",
        "[System.Text.RegularExpressions.Regex]": "[System.Text.RegularExpressions.Regex]",
        "[System.TimeSpan]": "[System.TimeSpan]",
        "[System.Type]": "[System.Type]",
        "[System.UInt16]": "[System.UInt16]",
        "[System.UInt32]": "[System.UInt32]",
        "[System.UInt64]": "[System.UInt64]",
        "[System.Uri]": "[System.Uri]",
        "[System.Version]": "[System.Version]",
        "[System.Void]": "[System.Void]",
        "[System.Web.Services.Protocols.SoapException]": "[System.Web.Services.Protocols.SoapException]",
        "[System.Xml.XmlDocument]": "[System.Xml.XmlDocument]",
        "[System.Xml.XmlNodeList]": "[System.Xml.XmlNodeList]",
        "[System.Xml.XmlNode]": "[System.Xml.XmlNode]",
        "[TimeSpan]": "[TimeSpan]",
        "[Type]": "[Type]",
        "[UInt16]": "[UInt16]",
        "[UInt32]": "[UInt32]",
        "[UInt64]": "[UInt64]",
        "[Uri]": "[Uri]",
        "[ValidateCountAttribute]": "[ValidateCountAttribute]",
        "[ValidateDriveAttribute]": "[ValidateDriveAttribute]",
        "[ValidateLengthAttribute]": "[ValidateLengthAttribute]",
        "[ValidateNotNullAttribute]": "[ValidateNotNullAttribute]",
        "[ValidateNotNullOrEmptyAttribute]": "[ValidateNotNullOrEmptyAttribute]",
        "[ValidatePatternAttribute]": "[ValidatePatternAttribute]",
        "[ValidateRangeAttribute]": "[ValidateRangeAttribute]",
        "[ValidateScriptAttribute]": "[ValidateScriptAttribute]",
        "[ValidateSetAttribute]": "[ValidateSetAttribute]",
        "[ValidateTrustedDataAttribute]": "[ValidateTrustedDataAttribute]",
        "[ValidateUserDriveAttribute]": "[ValidateUserDriveAttribute]",
        "[Version]": "[Version]",
        "[Void]": "[Void]",
        "[WildcardPattern]": "[WildcardPattern]",
        "[X500DistinguishedName]": "[X500DistinguishedName]",
        "[X509Certificate]": "[X509Certificate]",
        "[XmlDocument]": "[XmlDocument]",
    },
}

SetVariable0 = set(map(lambda x: x.lower(), ["Set-Variable", "SV", "Set"]))
SetVariable1 = set(map(lambda x: x.lower(), ["Set-Item", "SI"]))
GetVariable0 = set(map(lambda x: x.lower(), ["Get-Variable", "Variable"]))
GetVariable1 = set(map(lambda x: x.lower(), ["DIR", "Get-ChildItem", "GCI", "ChildItem", "LS", "Get-Item", "GI", "Item"]))

########################### PowerShell interface ###########################


class PS:
    def __init__(self):
        self.instance = PowerShell.Create()
        # Make up Variables like Windows 10 example
        vars = self.run_script("Gv")
        var_names = set(map(lambda v: v.get_Name(), vars))
        for k in Get_Variables.keys() - var_names:
            if Get_Variables[k] is None:
                self.run_script_without_return(f'Set-Variable -Name "{k}"')
            elif isinstance(Get_Variables[k], int):
                self.run_script_without_return(f'Set-Variable -Name "{k}" -Value {Get_Variables[k]}')
            else:
                self.run_script_without_return(f'Set-Variable -Name "{k}" -Value "{Get_Variables[k]}"')
        for v in ENV_VARIABLES:
            self.run_script_without_return(f'$env:{v} = "{ENV_VARIABLES[v]}"')
            self.run_script_without_return(f'$env:{v.lower()} = "{ENV_VARIABLES[v]}"')
        self.run_script_without_return('$OFS = " "') # $OFS = " "

    def convert_ps_type(self, x):
        if isinstance(x, int) or isinstance(x, str):
            return x
        elif type(x).__name__ == "PSCustomObject":
            return None
        else:
            return x.get_BaseObject()

    def run_script_without_return(self, script):
        self.instance.Commands.Clear()
        self.instance.Commands.AddScript(script)
        self.instance.Invoke()

        self.instance.Commands.Clear()
        self.instance.Commands.AddScript("$error")
        error = list(map(lambda x: self.convert_ps_type(x), self.instance.Invoke()))
        if len(error) > 0:
            self.instance.Commands.Clear()
            self.instance.Commands.AddScript("$error.clear()")
            self.instance.Invoke()
            raise Exception(obj_to_str(error))

    def run_script(self, script):
        self.instance.Commands.Clear()
        self.instance.Commands.AddScript('@{r={' + script + '}.Invoke()}')
        res = self.instance.Invoke()

        self.instance.Commands.Clear()
        self.instance.Commands.AddScript("$error")
        error = list(map(lambda x: self.convert_ps_type(x), self.instance.Invoke()))
        if len(error) > 0:
            self.instance.Commands.Clear()
            self.instance.Commands.AddScript("$error.clear()")
            self.instance.Invoke()
            raise Exception(obj_to_str(error))

        res = res[0].get_BaseObject().get_Item("r")
        if type(res).__name__.endswith("]"):
            return list(map(lambda x: self.convert_ps_type(x), res))
        else:
            return self.convert_ps_type(res)

    def parser_parseinput(self, script):
        return Parser.ParseInput(script, None, None)[0]

    def parser_parseinput_error(self, script):
        return list(Parser.ParseInput(script, None, None)[2])

    def psparser_tokenize(self, script):
        return list(PSParser.Tokenize(script, None)[0])

    def ast_findall(self, ast, ast_type=None):
        Func = getattr(System, "Func`2")
        func = Func[System.Management.Automation.Language.Ast, bool](
            lambda a: type(a).__name__ == ast_type if ast_type is not None else True
        )
        return ast.FindAll(func, True)


########################### Main ###########################


def token_type(token):
    return token.Type.ToString()


def node_type(ast):
    return ast.GetType().Name


def generate_lookup_table(ps):
    command_names = dict()
    for i in ps.run_script("Get-Command -CommandType Cmdlet,Function | Sort-Object -Property CommandType -Descending"):
        if i.Name not in command_names.keys():
            command_names[i.Name] = i.Name

    for i in CoreSafeAliases.keys():
        if i not in command_names.keys():
            command_names[i] = CoreSafeAliases[i]

    command_parameter_names = dict()
    for i in ps.run_script("Get-Command -CommandType Cmdlet | Where-Object { $_.ModuleName.StartsWith('Microsoft.PowerShell.') } | Where-Object { $null -ne $_.Parameters } | ForEach-Object { $_.Parameters.Keys } | Select-Object -Unique"):
        i = "-" + i
        command_parameter_names[i] = i
    for i in ps.run_script("Get-Command -CommandType Cmdlet,Function | Where-Object { $null -ne $_.Parameters } | ForEach-Object { $_.Parameters.Keys } | Select-Object -Unique | Sort-Object"):
        i = "-" + i
        if i not in command_parameter_names.keys():
            command_parameter_names[i] = i

    attribute_names = {
        "Alias": "Alias",
        "AllowEmptyCollection": "AllowEmptyCollection",
        "AllowEmptyString": "AllowEmptyString",
        "AllowNull": "AllowNull",
        "CmdletBinding": "CmdletBinding",
        "ConfirmImpact": "ConfirmImpact",
        "CredentialAttribute": "CredentialAttribute",
        "DefaultParameterSetName": "DefaultParameterSetName",
        "OutputType": "OutputType",
        "PSDefaultValue": "PSDefaultValue",
        "PSTypeName": "PSTypeName",
        "Parameter": "Parameter",
        "PositionalBinding": "PositionalBinding",
        "SupportsShouldProcess": "SupportsShouldProcess",
        "SupportsWildcards": "SupportsWildcards",
        "ValidateCount": "ValidateCount",
        "ValidateLength": "ValidateLength",
        "ValidateNotNull": "ValidateNotNull",
        "ValidateNotNullOrEmpty": "ValidateNotNullOrEmpty",
        "ValidatePattern": "ValidatePattern",
        "ValidateRange": "ValidateRange",
        "ValidateScript": "ValidateScript",
        "ValidateSet": "ValidateSet",
    }

    member_names = dict()
    for i in ps.run_script("([System.Management.Automation.ParameterAttribute], [string],[char],[byte], [int],[long],[decimal],[single],[double], [bool],[datetime],[guid],[hashtable],[xml],[array], [System.IO.File],[System.IO.FileInfo],[System.IO.FileAttributes],[System.IO.FileOptions], (Get-Item -Path $PSHOME), [System.IO.Directory],[System.IO.DirectoryInfo],[System.Exception])| ForEach-Object {($_ | Get-Member).Name;($_ | Get-Member -Static).Name;}"):
        member_names[i] = i

    variable_names = {"true": "True", "false": "False", "HOME": "HOME", "null": "Null"}

    command_argument_names = dict()

    validate_data = OtherValidNames
    validate_data["Command"] = command_names  # Used
    validate_data["CommandParameter"] = command_parameter_names  # Used
    validate_data["Attribute"] = attribute_names  # Used
    validate_data["Member"] = member_names  # Used
    validate_data["Variable"] = variable_names
    validate_data["CommandArgument"] = command_argument_names

    # Lower all second level keys to do case-insensitive match
    res = dict()
    for first_k in validate_data.keys():
        first_v = validate_data[first_k]
        tmp = dict()
        for k in first_v.keys():
            tmp[k.lower()] = first_v[k]
        res[first_k] = tmp

    return res


def normalize_script(ps, script):
    script = script.strip()
    if 2 * len(list(filter(lambda x: x == ' ', script))) > len(script) and len(list(filter(lambda x: x != ' ', script[1::2]))) == 0:
        # For space obfuscated case
        script = script[::2]

    tokens = ps.psparser_tokenize(script)
    valid_name_table = generate_lookup_table(ps)

    for i in range(len(tokens))[::-1]:
        token = tokens[i]
        if token_type(token) == "Variable":
            if "`" not in token.Content:
                origin = script[token.Start : token.Start + token.Length]
                if origin.startswith("${") and origin.endswith("}"):
                    obfus = origin[2:-1]
                else:
                    obfus = origin[1:]

                sub_str = token.Content.lower()
                table = valid_name_table["Variable"]
                if sub_str in table.keys():
                    sub_str = table[sub_str]
                script = (
                    script[: token.Start]
                    + origin.replace(obfus, sub_str)
                    + script[token.Start + token.Length :]
                )
        elif token_type(token) in {
            "Command",
            "Member",
            "Attribute",
            "Operator",
            "Keyword",
            "CommandParameter",
            "Type",
        }:
            table = valid_name_table[token_type(token)]
            tmp = token.Content.lower()
            if tmp in table.keys():
                tmp = table[tmp]
            else:
                tmp = tmp.lower()
            script = script[: token.Start] + tmp + script[token.Start + token.Length :]
        elif token_type(token) == "String":
            token_str = script[token.Start : token.Start + token.Length]
            if token_str.startswith('"'):
                tmp = '"' + token.Content.replace('"', '""') + '"'
            else:
                tmp = "'" + token.Content.replace("'", "''") + "'"
            script = script[: token.Start] + tmp + script[token.Start + token.Length :]

    validate_script(ps, script)
    return script


class ScriptInvalidException(Exception):
    pass

def validate_script(ps, script):
    script = script.strip()
    if 2 * len(list(filter(lambda x: x == ' ', script))) > len(script) and len(list(filter(lambda x: x != ' ', script[1::2]))) == 0:
        # For space obfuscated case
        script = script[::2]

    if len(ps.parser_parseinput_error(script)) > 0:
        raise ScriptInvalidException()


def build_child_info(ps, ast_root):
    res = dict()
    for node in ps.ast_findall(ast_root):
        if node.Parent != None:
            if node.Parent not in res.keys():
                res[node.Parent] = list()
            if node not in res.keys(): # Put all nodes in child_info.keys()
                res[node] = list()
            res[node.Parent].append(node)
    return res


def post_traverse(ast_root, child_info):
    stack = list()
    curr = ast_root
    pre = None
    layer_node_type = {
        "NamedBlockAst",
        "IfStatementAst",
        "WhileStatementAst",
        "ForStatementAst",
        "ForEachStatementAst",
        "StatementBlockAst",
    }
    level = -1

    while curr is not None or len(stack) > 0:
        while curr is not None:
            stack.append(curr)
            curr = child_info[curr][0] if len(child_info[curr]) > 0 else None
            if curr is not None and node_type(curr) in layer_node_type:
                level += 1

        if len(stack) > 0:
            curr = stack.pop()
            if len(child_info[curr]) == 0 or child_info[curr][-1] == pre:
                yield (curr, level)
                if node_type(curr) in layer_node_type:
                    level -= 1
                pre = curr
                curr = None
            else:
                stack.append(curr)
                curr = child_info[curr][child_info[curr].index(pre) + 1]
                if node_type(curr) in layer_node_type:
                    level += 1


def update_node_str_map(curr_node, child_info, node_str_map, script):
    children = child_info[curr_node]
    res = ''

    if node_type(curr_node) == "NamedBlockAst":
        if len(children) == 0:
            return curr_node.Extent.Text.strip()

        for i in range(len(children)):
            child = children[i]
            res += node_str_map[child]

            if i < len(children) - 1:
                next_child = children[i + 1]
                if next_child.Extent.StartOffset > child.Extent.EndOffset:
                    res += script[
                        child.Extent.EndOffset : next_child.Extent.StartOffset
                    ]

        if curr_node.Extent.EndOffset > children[-1].Extent.EndOffset:
            res += script[children[-1].Extent.EndOffset : curr_node.Extent.EndOffset]
        return res.strip()

    if len(children) > 0:
        if node_type(curr_node) not in {"DoWhileStatementAst", "DoUntilStatementAst"}:
            for i in range(len(children)):
                curr_child = children[i]

                if len(children) == 1 and node_str_map[curr_child] == '':
                    res = curr_node.Extent.Text
                    break

                if node_type(curr_child) == "ParamBlockAst":
                    grand_children = child_info[curr_child]
                    if (
                        i == 0
                        and grand_children[0].Extent.StartOffset > curr_node.Extent.StartOffset
                    ):
                        res += script[curr_node.Extent.StartOffset : grand_children[0].Extent.StartOffset]

                    for j in range(len(grand_children)):
                        res += node_str_map[grand_children[j]]

                        if j < len(grand_children) - 1:
                            next_grand_child = grand_children[j + 1]
                            if next_grand_child.Extent.StartOffset > grand_children[j].Extent.EndOffset:
                                res += script[grand_children[j].Extent.EndOffset : next_grand_child.Extent.StartOffset]

                    last_grand_child = grand_children[-1]
                    if i < len(children) - 1:
                        if children[i + 1].Extent.StartOffset < last_grand_child.Extent.EndOffset:
                            name_children = child_info[children[i + 1]]
                            if len(name_children) > 0:
                                first_name_child = name_children[0]
                                res += script[last_grand_child.Extent.EndOffset : first_name_child.Extent.StartOffset]
                        else:
                            res += script[last_grand_child.Extent.EndOffset : children[i+1].Extent.StartOffset]
                    else:
                        res += script[last_grand_child.Extent.EndOffset : curr_child.Extent.StartOffset]

                    continue

                if i == 0 and curr_child.Extent.StartOffset > curr_node.Extent.StartOffset:
                    res = script[curr_node.Extent.StartOffset : curr_child.Extent.StartOffset]

                if i < len(children) - 1:
                    next_child = children[i + 1]

                    if curr_child in node_str_map.keys():
                        res += node_str_map[curr_child]
                        if next_child.Extent.StartOffset > curr_child.Extent.EndOffset:
                            res += script[curr_child.Extent.EndOffset : next_child.Extent.StartOffset]
                else:
                    res += node_str_map[curr_child]

                if (
                    i == len(children) - 1
                    and curr_node.Extent.EndOffset > curr_child.Extent.EndOffset
                ):
                    res += script[curr_child.Extent.EndOffset : curr_node.Extent.EndOffset]
        else:
            pipeline_node = children[0]
            statement_block_node = children[1]
            res = (
                script[curr_node.Extent.StartOffset : statement_block_node.Extent.StartOffset]
                + node_str_map[statement_block_node]
                + script[statement_block_node.Extent.EndOffset : pipeline_node.Extent.StartOffset]
                + node_str_map[pipeline_node]
                + script[pipeline_node.Extent.EndOffset : curr_node.Extent.EndOffset]
            )
    else:
        res = curr_node.Extent.Text

    return res.strip()


def is_var_in_loop(node):
    loop_node_type = {
        "IfStatementAst",
        "WhileStatementAst",
        "ForStatementAst",
        "ForEachStatementAst",
        "DoWhileStatementAst",
    }
    loop_key = {"foreach-object"}

    if node.Extent.Text.strip() == "$_":
        return True

    while node.Parent is not None:
        if node_type(node.Parent) in loop_node_type:
            return True
        else:
            for k in loop_key:
                if (
                    node.Parent.Extent.Text.lower().startswith(k)
                    and node_type(node.Parent) == "CommandAst"
                ):
                    return True
            node = node.Parent

    return False


def obj_to_str(obj, is_pure=False):
    if isinstance(obj, list):
        '''
        if list(filter(lambda x: isinstance(x, str) and len(x) == 1, obj)) and is_pure and len(obj) > 1:
            return ''
        '''

        if len(obj) > 1:
            res = "@("
            for var in obj:
                if var is None:
                    res += ","
                elif isinstance(var, str):
                    if "'" in var:
                        var = var.replace("'", "''")
                    res += "'" + var + "',"
                elif isinstance(var, int):
                    res += str(var) + ","
                else:
                    if is_pure:
                        return ''
                    res += var.ToString() + ","

            if res.endswith(","):
                return res[:-1] + ")"
            else:
                return ""
        elif len(obj) == 0:
            return '@()'
    
    obj = obj[0] if isinstance(obj, list) else obj
    if obj is None:
        return ""
    if isinstance(obj, str):
        if "'" in obj:
            obj = obj.replace("'", "''")
        obj = "'" + obj + "'"
    elif isinstance(obj, int):
        obj = str(obj)
    else:
        if is_pure:
            return ''
        obj = obj.ToString()
    return obj


def get_var_name(s):
    if s.startswith("$"):
        return s[1:].strip("{}")
    else:
        return s


def get_var_node(node, child_info):
    queue = deque([node])

    while len(queue) > 0:
        curNode = queue.popleft()

        if node_type(curNode) == "VariableExpressionAst":
            return get_var_name(curNode.Extent.Text.strip())

        for i in child_info[curNode]:
            queue.append(i)

    return ""


def get_null_variables_in_childnodes(ps, script, symbols):
    variables = list()

    for curNode in ps.ast_findall(ps.parser_parseinput(script), ast_type="VariableExpressionAst"):
        varName = get_var_name(curNode.Extent.Text.strip()).lower()

        if varName == "_" or (symbols is not None and varName in symbols.keys()):
            continue

        if varName.startswith('env:'):
            if not invoke_command(ps, f"test-path env:\{varName[4:]}", is_assign=True) and varName not in variables:
                variables.append(varName)
        else:
            if not invoke_command(ps, f"test-path variable:\{varName}", is_assign=True) and varName not in variables:
                variables.append(varName)

    return variables

PTR_TO_STRING = {
    'securestringtoglobalallocansi': 'ptrtostringansi',
    'securestringtobstr': 'ptrtostringbstr',
    'securestringtoglobalallocunicode': 'ptrtostringuni'
}

def invoke_command(ps, command, symbols=None, is_assign=False):
    banned_commands = {
        "cmd",
        "cmd.exe",
        "get-wmiobject",
        "taskkill",
        "shutdown.exe",
        "iex",
        "invoke-expression",
        "invoke-webrequest",
        "invoke-shellcode",
        "invoke-command",
        "invoke-item",
        "start-bitstransfer",
        "createthread",
        "memset",
        "virtualalloc",
        "stop-process",
        "net.sockets.tcpclient",
        "restart",
        "shutdown",
        "download",
        "set-content",
        "new-item",
        "remove-item",
        "start-process",
        "start-sleep",
        "sleep",
        "create",
        "shouldcontinue",
        "readkey",
        "write",
        "exit",
        "save",
        "logoff",
        "get-credential",
        "main",
        # "invoke",
        "downloadstring",
        "test-connection",
        "wget",
        "mkdir",
        "start-job",
        "create",
        "restart-computer",
        "terminate",
        "add-type",
        "read-host",
    }

    tokens = ps.psparser_tokenize(command)

    for token in filter(lambda t: token_type(t) in ("Command", "CommandArgument", "Member"), tokens):
        if token.Content.lower() in banned_commands or token.Content.lower().startswith("system.net"):
            return ""

    for i in range(len(tokens)):
        token = tokens[i]
        if token_type(token) == "String":
            if (i > 0 and (tokens[i - 1].Content == "." or tokens[i - 1].Content == "&")) or (
                i > 1 and (tokens[i - 2].Content == "." or tokens[i - 2].Content == "&")
            ):
                if token.Content.lower() in banned_commands:
                    return ""
        elif token_type(token) == "Keyword" and token.Content.lower() == "function":
            return ""

    if len(get_null_variables_in_childnodes(ps, command, symbols)) > 0 and not is_assign:
        return ""

    if symbols is not None:
        symbols_string = ""
        for var in symbols.keys():
            symbols_string += "${" + var + "} = " + symbols[var] + ";"
        command = symbols_string + command
        tokens = ps.psparser_tokenize(command)

    # Fix PSHOME on Linux
    need_tokenize = False
    for i in range(len(tokens))[::-1]:
        tok = tokens[i]
        if token_type(tok) == 'Variable' and tok.Content.lower() == 'pshome':
            command = command[:tok.Start] + r'("C:\Windows\System32\WindowsPowerShell\v1.0")' + command[tok.Start+tok.Length:]
            need_tokenize = True
    if need_tokenize:
        tokens = ps.psparser_tokenize(command)

    # To fix .Net bug to confuse String.Split([char[]])
    need_tokenize = False
    for i in range(4, len(tokens))[::-1]:
        split_string = tokens[i - 4]
        split_dot = tokens[i - 3]
        split_split = tokens[i - 2]
        split_start = tokens[i - 1]
        split_chars = tokens[i]
        if (
            token_type(split_string) == "String"
            and split_dot.Content == "."
            and split_split.Content.lower() == "split"
            and split_start.Content == "("
            and (
                token_type(split_chars) == "String"
                and len(split_chars.Content) > 1
            )
        ):
            split_before = command[: split_chars.Start]
            split_after = command[split_chars.Start :]
            command = split_before + " [char[]] " + split_after
            need_tokenize = True
    if need_tokenize:
        tokens = ps.psparser_tokenize(command)

    # SecureStringToGlobalAllocUnicode with PtrToStringUni
    # Otherwise, SecureStringToBSTR with PtrToStringBSTR, etc.
    # On Windows, due to bug, PtrToStringAuto can be used with PtrToStringAuto, need to fix
    string_to = -1
    to_string = -1
    for i in range(2, len(tokens))[::-1]:
        if token_type(tokens[i-2]) == 'Type' and 'marshal' in tokens[i-2].Content.lower() and (token_type(tokens[i]) == 'Member' or tokens[i].Content == '('):
            if tokens[i].Content == '(':
                i += 1
            if tokens[i].Content.lower().startswith('securestringto'):
                to_string = i
            if tokens[i].Content.lower().startswith('ptrtostring'):
                string_to = i
    if string_to != -1 and to_string != -1 and tokens[to_string].Content.lower() in PTR_TO_STRING.keys():
        ptr_to_string = PTR_TO_STRING[tokens[to_string].Content.lower()]
        if ptr_to_string != tokens[string_to].Content.lower():
            command = command[:tokens[string_to].Start] + command[tokens[string_to].Start:tokens[string_to].Start+tokens[string_to].Length].replace(tokens[string_to].Content, ptr_to_string) + command[tokens[string_to].Start+tokens[string_to].Length:]

    try:
        output = ps.run_script(command)
    except Exception as e:
        return ""

    if output is None or output == "":
        return ""

    if is_assign:
        if isinstance(output, list) and len(output) == 1:
            return output[0]
        return output
    else:
        if ".." in command and isinstance(output, list) and len(output) > 1:
            return ""
        elif isinstance(output, list) and len(output) == 0:
            return ""
        else:
            tmp = output[0] if isinstance(output, list) and len(output) == 1 else output
            tmp = tmp.strip() if isinstance(tmp, str) else None
            if tmp is not None and all(map(lambda x: x == ' ', tmp[1::2])):
                # For space obfuscated case
                output = tmp[::2]
            return obj_to_str(output, is_pure=True)


known_obfus_iex = set(map(lambda x: x.lower(), [
    "IEX",
    "Invoke-Expression",
    "($ShellId[1]+$ShellId[13]+'x')",
    "($PSHome[4]+$PSHome[30]+'x')",
    "($PSHome[21]+$PSHome[30]+'x')",
    "($PSHome[4]+$PSHome[34]+'x')",
    "($PSHome[21]+$PSHome[34]+'x')",
    "($env:ComSpec[4,15,25]-Join'')",
    "($env:ComSpec[4,24,25]-Join'')",
    "($env:ComSpec[4,26,25]-Join'')",
    "((Get-Variable'*mdr*').Name[3,11,2]-Join'')",
    "((GV'*mdr*').Name[3,11,2]-Join'')",
    "((Variable'*mdr*').Name[3,11,2]-Join'')",
    "($VerbosePreference.ToString()[1,3]+'x'-Join'')",
    "(([String]$VerbosePreference)[1,3]+'x'-Join'')",
]))


def is_invoke_expr(ps, node, child_info, node_str_map):
    content = node_str_map[node]
    children = child_info[node]

    if content.startswith("(") or content.startswith("'") or content.startswith('"') or content.startswith('$'):
        if content.replace(" ", "").lower() in known_obfus_iex:
            return True

        try:
            content = ps.run_script(content)
            content = content[0] if isinstance(content, list) else content
        except:
            return False

    if not isinstance(content, str):
        return False

    if content.lower() in {"iex", "invoke-expression"}:
        return True

    if len(children) == 0:
        return False

    child_content = node_str_map[children[0]]
    if content.startswith(".") or content.startswith("&"):
        if child_content.replace(" ", "").lower() in known_obfus_iex:
            return True

        if (
            child_content.startswith("(")
            or child_content.startswith("'")
            or child_content.startswith('"')
            or child_content.startswith('$')
        ):
            try:
                child_content = ps.run_script(child_content)
                child_content = child_content[0] if isinstance(child_content, list) else child_content
            except:
                return False

        if isinstance(child_content, str) and child_content.replace(" ", "").lower() in known_obfus_iex:
            return True

    return False


def is_powershell(node, child_info, node_str_map):
    curr_string = node_str_map[node]

    if node_type(node) != "CommandAst" or "powershell" not in curr_string.lower():
        return False

    children = child_info[node]
    first_child_string = node_str_map[children[0]]
    if curr_string.startswith("&") or curr_string.startswith("."):
        if "powershell" in first_child_string.strip('"' "").lower():
            return True

    if first_child_string.lower() == "powershell" or "powershell.exe" in first_child_string.lower():
        return True

    if "cmd" in first_child_string.lower():
        for tmp in children:
            if "powershell" in node_str_map[tmp].lower():
                return True

    return False


def is_cur_variable_in_script(ps, script):
    return len(list(filter(lambda x: x.Extent.Text.strip() in {"$_", "${_}"}, ps.ast_findall(ps.parser_parseinput(script), ast_type="VariableExpressionAst")))) > 0

FOREACH_KEY = {"%", "foreach", "foreach-object"}

def is_cur_in_foreach_pipeline(ps, script):
    if not (("$_" in script or "${_}" in script) and len(list(filter(lambda x: x in script.lower(), FOREACH_KEY))) > 0):
        return False

    is_inloop, res = False, False
    indent = 0

    tokens = ps.psparser_tokenize(script)
    for i in range(len(tokens)):
        token = tokens[i]
        if (not is_inloop) and (token_type(token) == "Command"
                or (token_type(token) == 'String' and token_type(tokens[i-1]) == 'GroupStart' and token_type(tokens[i-2]) == 'Operator')):
            if token.Content.lower() in FOREACH_KEY:
                is_inloop = True
        elif token_type(token) == "GroupStart" and token.Content == "{" and is_inloop:
            indent += 1
        elif token_type(token) == "GroupEnd" and token.Content == "}" and is_inloop:
            indent -= 1
            if indent == 0:
                is_inloop = False
        elif token_type(token) == "Variable" and token.Content == "_":
            if is_inloop:
                res = True
            else:
                return False

    return res


def get_funcnames_from_script(ps, script):
    tokens = ps.psparser_tokenize(script)
    functionNames = list()

    for i in range(len(tokens)-1):
        token = tokens[i]
        if token_type(token) == "Keyword" and token.Content.strip().lower() == "function":
            functionNames.append(tokens[i + 1].Content.strip().lower())

    return functionNames


def get_var_name_call(node, child_info, node_str_map):
    if node_type(node) == "CommandAst":
        children = child_info[node]
        first_child_str = node_str_map[children[0]].strip()
        if len(children) >= 2 and (
            first_child_str in SetVariable0
            or first_child_str in SetVariable1
            or first_child_str in GetVariable0
            or first_child_str in GetVariable1
        ):
            if node_type(children[1]) == "StringConstantExpressionAst":  # eg: set m 3
                varName = node_str_map[children[1]]
            else:  # eg: set ('m'+'1') 3
                varName = invoke_command(ps, node_str_map[children[1]])
            varName = varName.strip(''''`"''')

            if varName.lower().startswith("variable:") and (first_child_str in SetVariable1 or first_child_str in GetVariable1):
                varName = varName[9:]

            return varName
        else:
            return ""


def resolve_curr_var(node, child_info):
    while node is not None:
        if node_type(node) == "ScriptBlockExpressionAst":
            parent = node.Parent
            brother = child_info[parent][0]
            if node_type(brother) == "StringConstantExpressionAst" and (
                brother.Extent.Text.strip().lower() == "foreach-object" or brother.Extent.Text.strip() == "%"
            ):
                return node.Parent

        node = node.Parent

    return None

def set_value(ps, expression, symbols):
    res = '$deobfus' + str(random.randint(0, 2**31-1))
    while res in symbols.values():
        res = '$deobfus' + str(random.randint(0, 2**31-1))

    def_var = ps.psparser_tokenize(expression)[-1]

    expression = ''.join(list(map(lambda var: "${" + var + "} = " + symbols[var] + ";", symbols.keys()))) + expression[:def_var.Start] + res + '=' + expression[def_var.Start:]

    ps.run_script_without_return(expression)
    return res

def resolve_script(ps, script):
    script_ast = ps.parser_parseinput(script)
    script_funcnames = get_funcnames_from_script(ps, script)
    child_info = build_child_info(ps, script_ast)

    aliasCommand = {"set-alias", "sal"}

    setCommand = ""
    symbols = dict()

    variableScope = dict()
    node_str_map = dict()

    for (curr_node, level) in post_traverse(script_ast, child_info):
        node_str_map[curr_node] = update_node_str_map(curr_node, child_info, node_str_map, script)
        children = child_info[curr_node]
        evaluation = ""

        if curr_node == script_ast:
            return node_str_map[curr_node]

        # if len(list(filter(lambda t: token_type(t) == 'Variable', ps.psparser_tokenize(node_str_map[curr_node])))) > 0 and is_var_in_loop(curr_node):
            # continue

        if node_type(curr_node) == "PipelineAst":
            last_child = children[-1]
            grandchildnodes = child_info[last_child]
            grandchildren = child_info[children[0]]

            if is_powershell(last_child, child_info, node_str_map):
                if len(children) == 1 and node_type(children[0]) == "CommandAst":
                    grandChilds = child_info[children[0]]
                    is_encodebase64 = False
                    encode_node = None
                    for i in grandChilds:
                        curParam = node_str_map[i].lower()
                        if "-encodedcommand".startswith(curParam) or curParam == "-ec":
                            encode_node = i
                            is_encodebase64 = True

                    lastGrandChild = grandChilds[-1]

                    if (
                        (not is_encodebase64) and node_type(lastGrandChild) != "StringConstantExpressionAst"
                        and node_type(lastGrandChild) != "ExpandableStringExpressionAst"
                    ):
                        continue

                    stringparam = node_str_map[lastGrandChild]
                    if (stringparam[0] == '"' and stringparam[-1] == '"') or (
                        stringparam[0] == "'" and stringparam[-1] == "'"
                    ):
                        stringparam = stringparam[1:-1]

                    if is_encodebase64 and (
                        node_type(lastGrandChild) == "StringConstantExpressionAst"
                        or node_type(lastGrandChild) == "CommandArgument"
                        or node_str_map[lastGrandChild][0] == "'"
                    ):
                        decodestr = base64.b64decode(stringparam).decode()
                    else:
                        decodestr = stringparam

                    node_str_map[lastGrandChild] = deobfuscate(decodestr).strip()

                    if encode_node is not None:
                        node_str_map[encode_node] = ""

                    node_str_map[children[0]] = update_node_str_map(children[0], child_info, node_str_map, script)
                    node_str_map[curr_node] = update_node_str_map(curr_node, child_info, node_str_map, script)

                    continue
                continue

            elif is_invoke_expr(ps, grandchildnodes[0], child_info, node_str_map) and len(children) == 1:
                pass # Do nothing
            elif node_type(last_child) == "CommandAst" and len(grandchildnodes) == 1 and len(children) >= 2:
                if is_invoke_expr(ps, last_child, child_info, node_str_map):
                    lastTwoChild = children[-2]
                    invokeParam = curr_node.Extent.Text[: lastTwoChild.Extent.EndOffset - curr_node.Extent.StartOffset]

                    resInvoke = invoke_command(ps, invokeParam, symbols)

                    if resInvoke != "" and (
                        (resInvoke[0] == "'" and resInvoke[-1] == "'")
                        or (resInvoke[0] == '"' and resInvoke[-1] == '"')
                    ):
                        try:
                            noQuotationString = ps.run_script(resInvoke)
                            noQuotationString = noQuotationString[0] if isinstance(noQuotationString, list) else noQuotationString
                            noQuotationString = noQuotationString.strip()
                            node_str_map[curr_node] = noQuotationString
                        except:
                            node_str_map[curr_node] = f"Invoke-Expression {resInvoke}"
                            continue

                        try:
                            validate_script(ps, noQuotationString)
                            try:
                                resInvoke = deobfuscate(noQuotationString).strip()
                            except:
                                continue
                        except:
                            node_str_map[curr_node] = f"Invoke-Expression {resInvoke}"

                        if resInvoke != "":
                            node_str_map[curr_node] = resInvoke
            else:
                evaluation = node_str_map[curr_node]
                for var in aliasCommand:
                    if var in node_str_map[curr_node].lower() and len(children) > 1:
                        grandchildren = child_info[children[0]]
                        if len(grandchildren) == 3 and grandchildren[0] in aliasCommand:
                            setCommand += (node_str_map[curr_node]) + "; "

                firstChild = children[0]
                firstChildNodes = child_info[firstChild]

                if (
                    node_type(curr_node.Parent) == "NamedBlockAst"
                    and len(children) == 1
                    and (
                        node_type(firstChildNodes[0]) == "StringConstantExpressionAst"
                        or node_type(firstChildNodes[0]) == "ConstantExpressionAst"
                    )
                    and curr_node.Extent.Text.strip().lower() == firstChildNodes[0].Extent.Text.strip().lower()
                ):
                    is_func = False
                    for func_name in script_funcnames:
                        if curr_node.Extent.Text.strip().lower() == func_name:
                            node_str_map[curr_node] = curr_node.Extent.Text.strip()
                            is_func = True
                            break
                    if not is_func:
                        node_str_map[curr_node] = ""
                    continue

                if is_cur_variable_in_script(ps, node_str_map[curr_node]) and not is_cur_in_foreach_pipeline(ps, node_str_map[curr_node]):
                    continue

                resInvoke = invoke_command(ps, evaluation, symbols)
                if resInvoke is not None and resInvoke != "":
                    if isinstance(resInvoke, str):
                        node_str_map[curr_node] = resInvoke.strip()
                    elif obj_to_str(resInvoke) == evaluation:
                        node_str_map[curr_node] = evaluation.strip()
                    else:
                        tmpRes = deobfuscate(obj_to_str(resInvoke))
                        if tmpRes is not None and tmpRes != "":
                            node_str_map[curr_node] = tmpRes.strip()
                    continue
                continue
        elif node_type(curr_node) == "InvokeMemberExpressionAst":
            if (
                len(children) == 3
                and (not is_var_in_loop(curr_node))
                and node_type(children[0]) == "TypeExpressionAst"
            ):
                varName = ""

                if node_type(children[2]) == "VariableExpressionAst":
                    varNode = children[2]
                    varName = get_var_name(node_str_map[varNode]).lower()
                elif node_type(children[2]) == "VariableExpressionAst": # Fix!!!
                    pipeNode = child_info[children[2]]
                    commandAstNodes = child_info[pipeNode[0]]
                    commandAstNode = commandAstNodes[0]
                    varName = get_var_name_call(commandAstNode, child_info, node_str_map).lower()

                if varName == "":
                    continue

                if (
                    varName in variableScope.keys()
                    and variableScope[varName] <= level
                    and varName in symbols.keys()
                    and node_type(curr_node.Parent) == "CommandExpressionAst"
                ):
                    evaluation = node_str_map[curr_node] + ";" + "${" + varName + "}"
                    resInvoke = invoke_command(ps, evaluation, symbols, is_assign=True)
                    if resInvoke is not None and resInvoke != '':
                        symbols[varName] = set_value(ps, evaluation, symbols)
                continue

            evaluation = node_str_map[curr_node]
        elif node_type(curr_node) == "BinaryExpressionAst" or (
            node_type(curr_node) == "ConvertExpressionAst" and children[0].Extent.Text.strip().lower() == "[string]"
        ):
            if is_cur_variable_in_script(ps, node_str_map[curr_node]) and not is_cur_in_foreach_pipeline(ps, node_str_map[curr_node]):
                continue

            evaluation = node_str_map[curr_node]
        elif node_type(curr_node) == "UnaryExpressionAst" and node_type(curr_node.Parent) == "CommandExpressionAst":
            childNodes = child_info[curr_node]

            if len(childNodes) == 1 and node_type(childNodes[0]) == "VariableExpressionAst":
                if is_var_in_loop(curr_node):
                    continue

                varNode = childNodes[0]

                varName = get_var_name(node_str_map[varNode]).lower()
                if varName == "":
                    continue

                if (
                    varName in variableScope.keys()
                    and variableScope[varName] <= level
                    and varName in symbols.keys()
                ):
                    evaluation = node_str_map[curr_node] + ";" + "${" + varName + "}"
                    resInvoke = invoke_command(ps, evaluation, symbols, is_assign=True)
                    if resInvoke is not None and obj_to_str(resInvoke) != "":
                        valueToString = obj_to_str(resInvoke)
                        if valueToString != "":
                            node_str_map[curr_node] = valueToString.strip()
                            symbols[varName] = set_value(ps, evaluation, symbols)
                continue
            else:
                if is_cur_variable_in_script(ps, node_str_map[curr_node]) and not is_cur_in_foreach_pipeline(ps, node_str_map[curr_node]):
                    continue

                evaluation = node_str_map[curr_node]
        elif node_type(curr_node) == "CommandExpressionAst" and node_type(curr_node.Parent) == "PipelineAst":
            if is_cur_variable_in_script(ps, node_str_map[curr_node]) and not is_cur_in_foreach_pipeline(ps, node_str_map[curr_node]):
                continue

            evaluation = node_str_map[curr_node]
        elif node_type(curr_node) == "VariableExpressionAst" and curr_node.Extent.Text.strip() == "$_":
            # foreachAstNode = resolve_curr_var(curr_node, child_info)
            continue
        elif (
            node_type(curr_node) == "VariableExpressionAst" 
            and node_type(curr_node.Parent) == "AssignmentStatementAst"
            and child_info[curr_node.Parent].index(curr_node) != 0 # Read
        ):
            if is_var_in_loop(curr_node):
                varName = get_var_name(node_str_map[curr_node]).lower()
                if varName in variableScope.keys():
                    del variableScope[varName]
                    del symbols[varName]

            if node_type(curr_node.Parent) == "UnaryExpressionAst":
                continue

            curVar = get_var_name(node_str_map[curr_node]).lower()
            if variableScope[curVar] <= level and curVar in symbols.keys():
                v = invoke_command(ps, symbols[curVar], is_assign=True)
                if node_type(curr_node.Parent) == "ExpandableStringExpressionAst":
                    node_str_map[curr_node] = v.ToString().replace('"', '""').strip()
                elif isinstance(v, str) or isinstance(v, int):
                    node_str_map[curr_node] = str(v)
            elif curVar in ps.run_script('(Gv).Name') and curVar != "_":
                continue
                # 9.30 resolve or not system variables
                # if ($node_type(curNode.Parent) -eq 'ExpandableStringExpressionAst') {
                #     $subNodeString[$curId] = $sysSymbols[$curVar].ToString().Replace('"', '""')
                # }
                # elseif ($expressionType -contains node_type($sysSymbols[$curVar])){
                #     # -and
                #     #($node_type(curNode.Parent) -eq 'CommandAst' -or $node_type(curNode.Parent) -eq 'InvokeMemberExpressionAst')) {  # eg: echo $a
                #     $varStr = Convert-ObjectToString -SrcObject $sysSymbols[$curVar]
                #     $subNodeString[$curId] = $varStr
                # }

            continue
        elif node_type(curr_node) == "AssignmentStatementAst":
            assignLeft = child_info[curr_node][0]
            assignRight = child_info[curr_node][1]
            if node_type(children[0]) == "VariableExpressionAst": # Write
                varLeft = get_var_name(node_str_map[assignLeft]).lower()
            else:
                varLeft = get_var_node(curr_node, child_info).lower()
                if varLeft == "":
                    continue

            nullVariables = get_null_variables_in_childnodes(ps, node_str_map[assignRight], symbols)

            if len(nullVariables) > 0:
                for i in nullVariables:
                    i = i.lower()
                    if i in variableScope.keys():
                        del variableScope[i]
                        del symbols[i]
                if varLeft in variableScope.keys():
                    del variableScope[varLeft]
                    del symbols[varLeft]

                continue

            # **** Can we get the value in another method? ****
            evaluation = node_str_map[curr_node] + ";" + "${" + varLeft + "}"

            is_noSub = False
            if node_type(children[1]) == "CommandExpressionAst":
                resInvoke = invoke_command(ps, evaluation, symbols, is_assign=True)

                # $CommandExpressAstNode = $hierarchy[$curId][1]
                CommandExpressAstNode = children[1]
                CommandChilds = child_info[CommandExpressAstNode]

                # ** how to simply continuous assignment？ **

                if node_type(CommandChilds[0]) == "StringConstantExpressionAst":
                    is_noSub = True
            else:
                resInvoke = invoke_command(ps, evaluation, symbols, is_assign=True)

            if resInvoke is not None and resInvoke != "":
                assignRes = obj_to_str(resInvoke, is_pure=True)

                if is_var_in_loop(children[0]):
                    continue

                if not is_noSub and assignRes != "":
                    node_str_map[curr_node] = node_str_map[assignLeft] + " = " + assignRes

                if varLeft in variableScope.keys() and variableScope[varLeft] <= level:
                    symbols[varLeft] = set_value(ps, evaluation, symbols)
                else:
                    variableScope[varLeft] = level
                    symbols[varLeft] = set_value(ps, evaluation, symbols)
            else:
                if varLeft in variableScope.keys():
                    del variableScope[varLeft]
                    del symbols[varLeft]

            continue
        elif node_type(curr_node) == "SubExpressionAst":
            if is_cur_variable_in_script(ps, node_str_map[curr_node]):
                continue

            evaluation = node_str_map[curr_node]
        elif node_type(curr_node) == "MemberExpressionAst":
            if node_str_map[curr_node].lower().replace(' ','') in GetMember_Alternate:
                node_str_map[curr_node] = GetMember_Alternate[node_str_map[curr_node].lower().replace(' ','')]
                continue

            firstChild = children[0]

            if len(children) == 2 and node_str_map[children[1]] == "value":
                try:
                    commandAstNode = child_info[child_info[firstChild][0]][0]
                    childcommandAstNode = child_info[commandAstNode]
                except IndexError as _e:
                    continue # Ignore node_str_map[curr_node] = $r.value case first.

                if (
                    node_type(commandAstNode) == "CommandAst"
                    and len(childcommandAstNode) >= 2
                    and node_type(childcommandAstNode[0]) == "StringConstantExpressionAst"
                ):
                    getVarCommand = node_str_map[childcommandAstNode[0]].lower()
                    getVarString = node_str_map[childcommandAstNode[1]]
                    getVarName = ""

                    if getVarCommand in GetVariable0 or getVarCommand in GetVariable1:
                        if node_type(childcommandAstNode[1]) == "StringConstantExpressionAst":
                            getVarName = getVarString
                        else:
                            getVarName = invoke_command(ps, getVarString)
                        getVarName = getVarName.strip(''''`"''').lower()
                    else:
                        continue

                    if getVarCommand in GetVariable1 and getVarName.startswith("variable:"):
                        getVarName = getVarName[9:]
                    elif getVarCommand in GetVariable1:
                        continue

                    if getVarName == "":
                        continue

                    if getVarName in symbols.keys() and variableScope[getVarName] <= level:
                        resString = obj_to_str(symbols[getVarName])

                        if resString != "":
                            node_str_map[curr_node] = resString

            continue
        elif node_type(curr_node) == "CommandAst":
            if len(children) == 2:
                firstChild = children[0]

                ### use original string or changed string
                secondContent = node_str_map[children[1]]

                # here maybe need to use first content
                if is_invoke_expr(ps, firstChild, child_info, node_str_map):
                    resInvoke = invoke_command(ps, secondContent, symbols).strip()
                    if (
                        resInvoke is not None
                        and resInvoke != ""
                        and resInvoke.startswith("'")
                        and resInvoke.endswith("'")
                    ):
                        try:
                            noQuotationString = ps.run_script(resInvoke)
                            noQuotationString = noQuotationString[0] if isinstance(noQuotationString, list) else noQuotationString
                            noQuotationString = noQuotationString.strip()
                            node_str_map[curr_node] = noQuotationString
                        except:
                            node_str_map[curr_node] = f"Invoke-Expression {resInvoke}"
                            continue

                        try:
                            validate_script(ps, noQuotationString)
                            resInvoke = deobfuscate(noQuotationString).strip()
                        except:
                            node_str_map[curr_node] = f"Invoke-Expression {resInvoke}"
                            continue

                        if resInvoke is not None and resInvoke != "":
                            node_str_map[curr_node] = resInvoke
                            continue

                    continue

            if len(children) >= 2:
                if node_type(children[0]) == "StringConstantExpressionAst":
                    setCommand = node_str_map[children[0]]
                else:
                    setCommand = invoke_command(ps, node_str_map[children[0]], is_assign=True)

                if isinstance(setCommand, str) and setCommand != '':
                    if setCommand.lower() in SetVariable0 or setCommand.lower() in SetVariable1:
                        if node_type(children[1]) == "StringConstantExpressionAst":
                            setVarName = node_str_map[children[1]]
                        else:
                            setVarName = invoke_command(ps, node_str_map[children[1]])
                        setVarName = setVarName.strip(''''`"''').lower()
                    else:
                        continue

                    if setCommand.lower() in SetVariable1 and setVarName.lower().startswith("variable:"):  # eg: Set-Item variable:m 3
                        setVarName = setVarName[9:]
                    elif setCommand.lower() in SetVariable1:
                        continue

                    if setVarName == "":
                        continue

                    evaluation = node_str_map[curr_node] + "; ${" + setVarName + "}"
                    setValue = invoke_command(ps, evaluation, symbols, is_assign=True)

                    ### change '' to null
                    if setVarName == "ofs":
                        continue
                    if setValue is not None and setValue != "":
                        variableScope[setVarName] = level
                        symbols[setVarName] = set_value(ps, evaluation, symbols)
                    continue
                else:
                    continue

        if evaluation == "":
            continue

        result = invoke_command(ps, evaluation, symbols)

        if result != '':
            if not (node_type(curr_node) == "CommandExpressionAst" and node_type(children[0]) == "StringConstantExpressionAst"):
                node_str_map[curr_node] = result

    validate_script(ps, script)
    return script


def deobfuscate(script):
    ps = PS()

    validate_script(ps, script)

    script = normalize_script(ps, script)

    script = resolve_script(ps, script)

    return script

########################### Main ###########################

if __name__ == '__main__':
    with open(sys.argv[-1], encoding='utf-8') as f:
        print(deobfuscate(f.read()))
