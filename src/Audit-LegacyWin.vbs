' ==============================================================================
' File: Audit-LegacyWin.vbs
' Description: VBScript Audit Engine for Legacy Windows platforms (Win 7 / 2008 R2).
' Syntax: cscript.exe //nologo src\Audit-LegacyWin.vbs <path_to_csv> <output_dir>
' ==============================================================================

Option Explicit

Dim fso, sh, scriptDir, csvPath, outputDir
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
If scriptDir = "" Then scriptDir = "."

' 1. Resolve Parameters
If WScript.Arguments.Count >= 1 Then
    csvPath = WScript.Arguments(0)
Else
    csvPath = fso.BuildPath(fso.GetParentFolderName(scriptDir), "lists\finding_list_cis_win7_sp1_machine.csv")
End If

If WScript.Arguments.Count >= 2 Then
    outputDir = WScript.Arguments(1)
Else
    outputDir = fso.BuildPath(fso.GetParentFolderName(scriptDir), "outputs")
End If

If Not fso.FileExists(csvPath) Then
    WScript.Echo "Error: Finding list CSV not found: " & csvPath
    WScript.Quit 1
End If

' Resolve Output File
Dim outputFile
If LCase(Right(outputDir, 4)) = ".csv" Then
    outputFile = outputDir
    Dim pDir
    pDir = fso.GetParentFolderName(outputFile)
    If pDir <> "" And Not fso.FolderExists(pDir) Then
        fso.CreateFolder pDir
    End If
Else
    If Not fso.FolderExists(outputDir) Then
        fso.CreateFolder outputDir
    End If
    Dim d, ts
    d = Now
    ts = Year(d) & Right("0" & Month(d), 2) & Right("0" & Day(d), 2) & "_" & _
         Right("0" & Hour(d), 2) & Right("0" & Minute(d), 2) & Right("0" & Second(d), 2)
    outputFile = fso.BuildPath(outputDir, "audit_report_vbs_" & ts & ".csv")
End If

' 2. RFC 4180 State Machine CSV Line Parser
Function ParseCsvLine(sLine)
    Dim fields(), count, inQuotes, i, n, ch, currentField
    count = 0
    inQuotes = False
    currentField = ""
    n = Len(sLine)
    ReDim fields(20)

    i = 1
    Do While i <= n
        ch = Mid(sLine, i, 1)
        If ch = """" Then
            If Not inQuotes Then
                If i < n And Mid(sLine, i + 1, 1) = """" And (i + 1 = n Or Mid(sLine, i + 2, 1) = ",") Then
                    currentField = ""
                    i = i + 1
                Else
                    inQuotes = True
                End If
            Else
                If i < n And Mid(sLine, i + 1, 1) = """" Then
                    currentField = currentField & """"
                    i = i + 1
                Else
                    inQuotes = False
                End If
            End If
        ElseIf ch = "," And Not inQuotes Then
            If count > UBound(fields) Then ReDim Preserve fields(count + 10)
            fields(count) = currentField
            count = count + 1
            currentField = ""
        Else
            currentField = currentField & ch
        End If
        i = i + 1
    Loop

    If count > UBound(fields) Then ReDim Preserve fields(count)
    fields(count) = currentField
    count = count + 1

    ReDim Preserve fields(count - 1)
    ParseCsvLine = fields
End Function

Function EscapeCsv(v)
    Dim s
    s = SafeToString(v)
    If InStr(s, """") > 0 Or InStr(s, ",") > 0 Or InStr(s, vbCr) > 0 Or InStr(s, vbLf) > 0 Then
        s = Replace(s, """", """""")
        s = """" & s & """"
    End If
    EscapeCsv = s
End Function

Function StripBom(s)
    Dim res
    res = s
    If Len(res) >= 3 Then
        If Left(res, 3) = Chr(&HEF) & Chr(&HBB) & Chr(&HBF) Then
            res = Mid(res, 4)
        End If
    End If
    If Len(res) >= 1 Then
        If Left(res, 1) = ChrW(&HFEFF) Then
            res = Mid(res, 2)
        End If
    End If
    StripBom = res
End Function

' 3. Registry Reader via WScript.Shell.RegRead & WMI StdRegProv
Dim objReg
On Error Resume Next
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
On Error GoTo 0

Function ReadRegistryValue(regPath, regItem, ByRef isFound)
    Dim fullPath, v, errNum, cleanPath
    isFound = False
    ReadRegistryValue = ""

    If Trim(regPath) = "" Or Trim(regItem) = "" Then Exit Function

    cleanPath = Trim(regPath)
    If UCase(Left(cleanPath, 6)) = "HKLM:\" Then
        cleanPath = "HKLM\" & Mid(cleanPath, 7)
    ElseIf UCase(Left(cleanPath, 6)) = "HKCU:\" Then
        cleanPath = "HKCU\" & Mid(cleanPath, 7)
    End If

    ' Method 1: WScript.Shell.RegRead
    fullPath = cleanPath & "\" & regItem
    On Error Resume Next
    v = sh.RegRead(fullPath)
    errNum = Err.Number
    On Error GoTo 0

    If errNum = 0 Then
        isFound = True
        If IsArray(v) Then
            ReadRegistryValue = Join(v, ",")
        Else
            ReadRegistryValue = CStr(v)
        End If
        Exit Function
    End If

    ' Method 2: WMI StdRegProv Fallback
    If objReg Is Nothing Then Exit Function

    Dim rootKey, subKey
    If UCase(Left(cleanPath, 5)) = "HKLM\" Then
        rootKey = &H80000002
        subKey = Mid(cleanPath, 6)
    ElseIf UCase(Left(cleanPath, 5)) = "HKCU\" Then
        rootKey = &H80000001
        subKey = Mid(cleanPath, 6)
    Else
        Exit Function
    End If

    Dim dwVal, strVal, arrVal, expVal, ret
    On Error Resume Next
    ' Try DWORD
    ret = objReg.GetDWORDValue(rootKey, subKey, regItem, dwVal)
    If ret = 0 And Not IsNull(dwVal) Then
        isFound = True
        ReadRegistryValue = CStr(dwVal)
        Exit Function
    End If

    ' Try String
    ret = objReg.GetStringValue(rootKey, subKey, regItem, strVal)
    If ret = 0 And Not IsNull(strVal) Then
        isFound = True
        ReadRegistryValue = CStr(strVal)
        Exit Function
    End If

    ' Try MultiString
    ret = objReg.GetMultiStringValue(rootKey, subKey, regItem, arrVal)
    If ret = 0 And IsArray(arrVal) Then
        isFound = True
        ReadRegistryValue = Join(arrVal, ",")
        Exit Function
    End If

    ' Try ExpandedString
    ret = objReg.GetExpandedStringValue(rootKey, subKey, regItem, expVal)
    If ret = 0 And Not IsNull(expVal) Then
        isFound = True
        ReadRegistryValue = CStr(expVal)
        Exit Function
    End If
    On Error GoTo 0
End Function

' 4. System Helpers for Other Methods (Service, LocalAccount, SecEdit, AuditPol, NetAccounts)
Dim localAccounts, secEditDict, auditPolDict, netAccountsDict
Set localAccounts = CreateObject("Scripting.Dictionary")
Set secEditDict = CreateObject("Scripting.Dictionary")
Set auditPolDict = CreateObject("Scripting.Dictionary")
Set netAccountsDict = CreateObject("Scripting.Dictionary")

Sub CacheLocalAccounts()
    Dim wmi, colUsers, usr
    On Error Resume Next
    Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Set colUsers = wmi.ExecQuery("Select Name, Disabled, SID from Win32_UserAccount Where LocalAccount = True")
    For Each usr In colUsers
        If Right(usr.SID, 4) = "-500" Then
            localAccounts("500_Status") = usr.Disabled
            localAccounts("500_Name") = usr.Name
            localAccounts("Administrator_Status") = usr.Disabled
            localAccounts("Administrator_Name") = usr.Name
        ElseIf Right(usr.SID, 4) = "-501" Then
            localAccounts("501_Status") = usr.Disabled
            localAccounts("501_Name") = usr.Name
            localAccounts("Guest_Status") = usr.Disabled
            localAccounts("Guest_Name") = usr.Name
        End If
        localAccounts(usr.Name & "_Status") = usr.Disabled
        localAccounts(usr.Name & "_Name") = usr.Name
    Next
    On Error GoTo 0
End Sub

Sub CacheSecEditPolicy()
    Dim tempInf, tempLog, cmd, exitCode
    tempInf = sh.ExpandEnvironmentStrings("%TEMP%") & "\secedit_vbs_" & fso.GetTempName() & ".inf"
    tempLog = tempInf & ".log"
    cmd = "secedit.exe /export /cfg """ & tempInf & """ /areas SECURITYPOLICY USER_RIGHTS /log """ & tempLog & """ /quiet"
    On Error Resume Next
    exitCode = sh.Run(cmd, 0, True)
    On Error GoTo 0
    If fso.FileExists(tempLog) Then fso.DeleteFile tempLog, True

    ' Fallback to SECURITYPOLICY if combined areas export was not produced
    If Not fso.FileExists(tempInf) Then
        cmd = "secedit.exe /export /cfg """ & tempInf & """ /areas SECURITYPOLICY /log """ & tempLog & """ /quiet"
        On Error Resume Next
        exitCode = sh.Run(cmd, 0, True)
        On Error GoTo 0
        If fso.FileExists(tempLog) Then fso.DeleteFile tempLog, True
    End If

    If fso.FileExists(tempInf) Then
        Dim stm, line, eqIdx, k, v, curSec
        Set stm = CreateObject("ADODB.Stream")
        stm.Type = 2
        stm.Charset = "Unicode"
        stm.Open
        stm.LoadFromFile tempInf
        curSec = ""
        Do Until stm.EOS
            line = Trim(stm.ReadText(-2))
            If Len(line) > 0 And Left(line, 1) <> ";" And Left(line, 1) <> "#" Then
                If Left(line, 1) = "[" And Right(line, 1) = "]" Then
                    curSec = Mid(line, 2, Len(line) - 2)
                Else
                    eqIdx = InStr(line, "=")
                    If eqIdx > 1 Then
                        k = Trim(Left(line, eqIdx - 1))
                        v = Trim(Mid(line, eqIdx + 1))
                        If Left(v, 1) = """" And Right(v, 1) = """" And Len(v) >= 2 Then
                            v = Mid(v, 2, Len(v) - 2)
                        End If
                        If curSec <> "" Then
                            secEditDict(LCase(curSec & "\" & k)) = v
                        End If
                        secEditDict(LCase(k)) = v
                    End If
                End If
            End If
        Loop
        stm.Close
        Set stm = Nothing
        fso.DeleteFile tempInf, True
    End If
End Sub

Sub CacheAuditPol()
    Dim tempCsv, cmd, exitCode
    tempCsv = sh.ExpandEnvironmentStrings("%TEMP%") & "\auditpol_vbs_" & fso.GetTempName() & ".csv"
    cmd = "cmd.exe /c auditpol.exe /get /category:* /r > """ & tempCsv & """"
    On Error Resume Next
    exitCode = sh.Run(cmd, 0, True)
    On Error GoTo 0

    If fso.FileExists(tempCsv) Then
        Dim tsFile, line, fArray
        Set tsFile = fso.OpenTextFile(tempCsv, 1)
        Do Until tsFile.AtEndOfStream
            line = Trim(tsFile.ReadLine)
            If Len(line) > 0 Then
                fArray = Split(line, ",")
                If UBound(fArray) >= 4 Then
                    Dim subCat, sett
                    subCat = Trim(Replace(fArray(2), """", ""))
                    sett = Trim(Replace(fArray(4), """", ""))
                    If Len(subCat) > 0 Then
                        auditPolDict(LCase(subCat)) = sett
                    End If
                End If
            End If
        Loop
        tsFile.Close
        fso.DeleteFile tempCsv, True
    End If
End Sub

Sub CacheNetAccounts()
    Dim tempNet, cmd, exitCode
    tempNet = sh.ExpandEnvironmentStrings("%TEMP%") & "\net_acc_vbs_" & fso.GetTempName() & ".txt"
    cmd = "cmd.exe /c net accounts > """ & tempNet & """"
    On Error Resume Next
    exitCode = sh.Run(cmd, 0, True)
    On Error GoTo 0

    If fso.FileExists(tempNet) Then
        Dim tsFile, line, colonIdx, k, v
        Set tsFile = fso.OpenTextFile(tempNet, 1)
        Do Until tsFile.AtEndOfStream
            line = Trim(tsFile.ReadLine)
            colonIdx = InStr(line, ":")
            If colonIdx > 1 Then
                k = LCase(Trim(Left(line, colonIdx - 1)))
                v = Trim(Mid(line, colonIdx + 1))
                If InStr(k, "force user logoff") > 0 Then
                    If LCase(v) = "never" Or v = "0" Then
                        netAccountsDict("force_logoff") = "Disabled"
                        netAccountsDict("forcelogoffwhenhourexpire") = "0"
                    Else
                        netAccountsDict("force_logoff") = "Enabled"
                        netAccountsDict("forcelogoffwhenhourexpire") = "1"
                    End If
                ElseIf InStr(k, "minimum password age") > 0 Then
                    netAccountsDict("minimum_password_age") = v
                    netAccountsDict("minimumpasswordage") = v
                ElseIf InStr(k, "maximum password age") > 0 Then
                    netAccountsDict("maximum_password_age") = v
                    netAccountsDict("maximumpasswordage") = v
                ElseIf InStr(k, "minimum password length") > 0 Then
                    netAccountsDict("minimum_password_length") = v
                    netAccountsDict("minimumpasswordlength") = v
                ElseIf InStr(k, "length of password history") > 0 Then
                    If LCase(v) = "none" Then v = "0"
                    netAccountsDict("enforce_password_history") = v
                    netAccountsDict("passwordhistorysize") = v
                ElseIf InStr(k, "lockout threshold") > 0 Then
                    If LCase(v) = "never" Then v = "0"
                    netAccountsDict("lockout_threshold") = v
                    netAccountsDict("lockoutbadcount") = v
                ElseIf InStr(k, "lockout duration") > 0 Then
                    netAccountsDict("lockout_duration") = v
                    netAccountsDict("lockoutduration") = v
                ElseIf InStr(k, "lockout observation window") > 0 Then
                    netAccountsDict("lockout_reset") = v
                    netAccountsDict("resetlockoutcount") = v
                End If
            End If
        Loop
        tsFile.Close
        fso.DeleteFile tempNet, True
    End If
End Sub

Function TranslateWellKnownSid(sidStr)
    Dim s
    s = UCase(Trim(sidStr))
    Select Case s
        Case "S-1-5-32-544": TranslateWellKnownSid = "BUILTIN\Administrators"
        Case "S-1-5-32-545": TranslateWellKnownSid = "BUILTIN\Users"
        Case "S-1-5-32-546": TranslateWellKnownSid = "BUILTIN\Guests"
        Case "S-1-5-32-555": TranslateWellKnownSid = "BUILTIN\Remote Desktop Users"
        Case "S-1-5-19":    TranslateWellKnownSid = "NT AUTHORITY\LOCAL SERVICE"
        Case "S-1-5-20":    TranslateWellKnownSid = "NT AUTHORITY\NETWORK SERVICE"
        Case "S-1-5-18":    TranslateWellKnownSid = "NT AUTHORITY\SYSTEM"
        Case "S-1-5-11":    TranslateWellKnownSid = "NT AUTHORITY\Authenticated Users"
        Case "S-1-1-0":     TranslateWellKnownSid = "Everyone"
        Case "S-1-5-6":     TranslateWellKnownSid = "NT AUTHORITY\SERVICE"
        Case "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420": TranslateWellKnownSid = "NT SERVICE\WdiServiceHost"
        Case Else:          TranslateWellKnownSid = sidStr
    End Select
End Function

Function TranslateSidsList(sRaw)
    Dim parts, p, i, res(), cnt, trName
    parts = Split(sRaw, ",")
    cnt = 0
    ReDim res(UBound(parts))
    For i = 0 To UBound(parts)
        p = Trim(parts(i))
        If Left(p, 1) = "*" Then p = Mid(p, 2)
        If p <> "" Then
            trName = TranslateWellKnownSid(p)
            If trName <> "" Then
                res(cnt) = trName
            Else
                res(cnt) = p
            End If
            cnt = cnt + 1
        End If
    Next
    If cnt = 0 Then
        TranslateSidsList = ""
    Else
        ReDim Preserve res(cnt - 1)
        TranslateSidsList = Join(res, ";")
    End If
End Function

Function QueryServiceStartMode(svcName, ByRef isFound)
    isFound = False
    QueryServiceStartMode = ""
    Dim wmi, colServices, svc
    On Error Resume Next
    Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Set colServices = wmi.ExecQuery("Select StartMode from Win32_Service Where Name = '" & Replace(svcName, "'", "''") & "'")
    For Each svc In colServices
        isFound = True
        QueryServiceStartMode = svc.StartMode
        Exit For
    Next
    On Error GoTo 0
End Function

Function SafeToString(v)
    If IsNull(v) Or IsEmpty(v) Then
        SafeToString = ""
    ElseIf IsObject(v) Then
        SafeToString = ""
    ElseIf IsArray(v) Then
        SafeToString = Trim(Join(v, ","))
    Else
        On Error Resume Next
        SafeToString = Trim(CStr(v))
        If Err.Number <> 0 Then SafeToString = ""
        On Error GoTo 0
    End If
End Function

' 5. Value Comparator
Function CompareValue(cVal, rVal, op, isFound)
    Dim cStr, rStr, cNum, rNum, cIsNum, rIsNum, cleanOp
    cStr = SafeToString(cVal)
    rStr = SafeToString(rVal)

    cIsNum = IsNumeric(cStr)
    rIsNum = IsNumeric(rStr)
    If cIsNum And rIsNum Then
        cNum = CDbl(cStr)
        rNum = CDbl(rStr)
    End If

    cleanOp = Trim(op)
    If cleanOp = "" Then cleanOp = "="

    Select Case LCase(cleanOp)
        Case "="
            If cIsNum And rIsNum Then
                If cNum = rNum Then
                    CompareValue = True
                    Exit Function
                End If
            End If
            If StrComp(cStr, rStr, vbTextCompare) = 0 Then
                CompareValue = True
                Exit Function
            End If
            If cStr = "" Then
                CompareValue = False
                Exit Function
            End If

            ' Regex fallback matching when string equality fails
            If rStr <> "" Then
                Dim hasRegex
                hasRegex = False
                If InStr(rStr, "[") > 0 Or InStr(rStr, "]") > 0 Or _
                   InStr(rStr, "(") > 0 Or InStr(rStr, ")") > 0 Or _
                   InStr(rStr, "*") > 0 Or InStr(rStr, "+") > 0 Or _
                   InStr(rStr, "?") > 0 Or InStr(rStr, "^") > 0 Or _
                   InStr(rStr, "$") > 0 Or InStr(rStr, "|") > 0 Or _
                   InStr(rStr, "{") > 0 Or InStr(rStr, "}") > 0 Or _
                   InStr(rStr, "\s") > 0 Or InStr(rStr, "\d") > 0 Or _
                   InStr(rStr, "\w") > 0 Or InStr(rStr, "\b") > 0 Then
                    hasRegex = True
                End If

                If hasRegex Then
                    Dim regEx, isMatch
                    isMatch = False
                    On Error Resume Next
                    Set regEx = CreateObject("VBScript.RegExp")
                    regEx.IgnoreCase = True
                    regEx.Global = False

                    ' Try anchored full match first
                    regEx.Pattern = "^(?:" & rStr & ")$"
                    isMatch = regEx.Test(cStr)

                    ' If not matched and not numeric, try unanchored match
                    If (Not isMatch) And (Not cIsNum) Then
                        regEx.Pattern = rStr
                        isMatch = regEx.Test(cStr)
                    End If
                    On Error GoTo 0

                    If isMatch Then
                        CompareValue = True
                        Exit Function
                    End If

                    ' If not matched and contains ||, convert CIS syntax to regex |
                    If InStr(rStr, "||") > 0 Then
                        Dim normR, cNorm, rNorm
                        normR = Replace(Replace(rStr, """", ""), "||", "|")
                        regEx.Pattern = "^(?:" & normR & ")$"
                        isMatch = regEx.Test(cStr)
                        If (Not isMatch) Then
                            cNorm = Replace(cStr, "BUILTIN\", "")
                            rNorm = Replace(normR, "BUILTIN\", "")
                            regEx.Pattern = "^(?:" & rNorm & ")$"
                            isMatch = regEx.Test(cNorm)
                        End If
                    End If
                    On Error GoTo 0

                    If isMatch Then
                        CompareValue = True
                        Exit Function
                    End If
                End If

                If StrComp(Replace(cStr, "BUILTIN\", ""), Replace(rStr, "BUILTIN\", ""), vbTextCompare) = 0 Then
                    CompareValue = True
                    Exit Function
                End If
            End If
            CompareValue = False

        Case "!="
            If cIsNum And rIsNum Then
                CompareValue = (cNum <> rNum)
            Else
                CompareValue = (StrComp(cStr, rStr, vbTextCompare) <> 0)
            End If

        Case ">="
            If cIsNum And rIsNum Then
                CompareValue = (cNum >= rNum)
            Else
                If cStr = "" Then
                    CompareValue = False
                Else
                    CompareValue = (StrComp(cStr, rStr, vbTextCompare) >= 0)
                End If
            End If

        Case "<="
            If cIsNum And rIsNum Then
                CompareValue = (cNum <= rNum)
            Else
                If cStr = "" Then
                    CompareValue = False
                Else
                    CompareValue = (StrComp(cStr, rStr, vbTextCompare) <= 0)
                End If
            End If

        Case "<=!0"
            If cStr = "" Or cStr = "0" Then
                CompareValue = False
            ElseIf cIsNum And rIsNum Then
                CompareValue = (cNum <= rNum And cNum <> 0)
            Else
                CompareValue = (StrComp(cStr, rStr, vbTextCompare) <= 0 And cStr <> "0")
            End If

        Case "contains"
            If rStr = "" Then
                CompareValue = True
            ElseIf cStr = "" Then
                CompareValue = False
            Else
                CompareValue = (InStr(1, cStr, rStr, vbTextCompare) > 0)
            End If

        Case "=|0"
            If cIsNum And rIsNum Then
                If cNum = rNum Or cNum = 0 Then
                    CompareValue = True
                    Exit Function
                End If
            End If
            If StrComp(cStr, rStr, vbTextCompare) = 0 Or cStr = "0" Or cStr = "" Or Not isFound Then
                CompareValue = True
            Else
                CompareValue = False
            End If

        Case Else
            CompareValue = (StrComp(cStr, rStr, vbTextCompare) = 0)
    End Select
End Function

Function GetFieldValue(arr, idx)
    If idx >= 0 And idx <= UBound(arr) Then
        GetFieldValue = Trim(arr(idx))
    Else
        GetFieldValue = ""
    End If
End Function

' 6. Pre-fetch Data
CacheLocalAccounts
CacheSecEditPolicy
CacheAuditPol
CacheNetAccounts

' 7. Execute Audit
Dim inFile, outStream
Dim line, fields
Dim id, cat, name, method, methodArg, regPath, regItem, defVal, recVal, op, sev
Dim currentVal, isFound, status, isCompliant
Dim totalCount, passedCount, failedCount, skippedCount

totalCount = 0
passedCount = 0
failedCount = 0
skippedCount = 0

Set inFile = fso.OpenTextFile(csvPath, 1)
Set outStream = fso.CreateTextFile(outputFile, True)

' Read & write header
line = StripBom(inFile.ReadLine)
Dim headerFields, colMap, hIdx, cName
headerFields = ParseCsvLine(line)
Set colMap = CreateObject("Scripting.Dictionary")
For hIdx = 0 To UBound(headerFields)
    cName = LCase(Trim(StripBom(headerFields(hIdx))))
    If cName <> "" And Not colMap.Exists(cName) Then
        colMap.Add cName, hIdx
    End If
Next

Dim idxID, idxCategory, idxName, idxMethod, idxMethodArg, idxRegPath, idxRegItem, idxDefVal, idxRecVal, idxOp, idxSev
idxID = -1: idxCategory = -1: idxName = -1: idxMethod = -1: idxMethodArg = -1
idxRegPath = -1: idxRegItem = -1: idxDefVal = -1: idxRecVal = -1: idxOp = -1: idxSev = -1

If colMap.Exists("id") Then idxID = colMap("id")
If colMap.Exists("category") Then idxCategory = colMap("category")
If colMap.Exists("name") Then idxName = colMap("name")
If colMap.Exists("method") Then idxMethod = colMap("method")
If colMap.Exists("methodargument") Then idxMethodArg = colMap("methodargument")
If colMap.Exists("registrypath") Then idxRegPath = colMap("registrypath")
If colMap.Exists("registryitem") Then idxRegItem = colMap("registryitem")
If colMap.Exists("defaultvalue") Then idxDefVal = colMap("defaultvalue")
If colMap.Exists("recommendedvalue") Then idxRecVal = colMap("recommendedvalue")
If colMap.Exists("operator") Then idxOp = colMap("operator")
If colMap.Exists("severity") Then idxSev = colMap("severity")

outStream.WriteLine "ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status"

Do Until inFile.AtEndOfStream
    line = Trim(inFile.ReadLine)
    If Len(line) > 0 Then
        fields = ParseCsvLine(line)
        If UBound(fields) >= 0 Then
            totalCount = totalCount + 1

            id = GetFieldValue(fields, idxID)
            cat = GetFieldValue(fields, idxCategory)
            name = GetFieldValue(fields, idxName)
            method = GetFieldValue(fields, idxMethod)
            methodArg = GetFieldValue(fields, idxMethodArg)
            regPath = GetFieldValue(fields, idxRegPath)
            regItem = GetFieldValue(fields, idxRegItem)
            defVal = GetFieldValue(fields, idxDefVal)
            recVal = GetFieldValue(fields, idxRecVal)
            op = GetFieldValue(fields, idxOp)
            If op = "" Then op = "="
            sev = GetFieldValue(fields, idxSev)

            currentVal = ""
            isFound = False
            status = ""
            Dim isUnknownMethod
            isUnknownMethod = False

            If LCase(method) = "mppreferenceasr" Then
                status = "Skipped"
                currentVal = "SKIPPED"
                skippedCount = skippedCount + 1
            Else
                Select Case LCase(method)
                    Case "registry"
                        currentVal = ReadRegistryValue(regPath, regItem, isFound)

                    Case "service"
                        currentVal = QueryServiceStartMode(methodArg, isFound)

                    Case "localaccount"
                        Dim targetAcc
                        targetAcc = Trim(methodArg)
                        If LCase(recVal) = "true" Or LCase(recVal) = "false" Then
                            If localAccounts.Exists(targetAcc & "_Status") Then
                                isFound = True
                                If localAccounts(targetAcc & "_Status") = True Then
                                    currentVal = "True"
                                Else
                                    currentVal = "False"
                                End If
                            End If
                        ElseIf InStr(1, name, "status", vbTextCompare) > 0 Or LCase(recVal) = "enabled" Or LCase(recVal) = "disabled" Then
                            If localAccounts.Exists(targetAcc & "_Status") Then
                                isFound = True
                                If localAccounts(targetAcc & "_Status") = True Then
                                    currentVal = "Disabled"
                                Else
                                    currentVal = "Enabled"
                                End If
                            End If
                        Else
                            If localAccounts.Exists(targetAcc & "_Name") Then
                                isFound = True
                                currentVal = localAccounts(targetAcc & "_Name")
                            End If
                        End If

                    Case "secedit", "accountpolicy"
                        Dim rawArg, mapKey
                        rawArg = LCase(Trim(methodArg))
                        mapKey = rawArg
                        Select Case rawArg
                            Case "enforce_password_history": mapKey = "passwordhistorysize"
                            Case "maximum_password_age":     mapKey = "maximumpasswordage"
                            Case "minimum_password_age":     mapKey = "minimumpasswordage"
                            Case "minimum_password_length":  mapKey = "minimumpasswordlength"
                            Case "complexity_requirements":  mapKey = "passwordcomplexity"
                            Case "reversible_encryption":    mapKey = "cleartextpassword"
                            Case "lockout_duration":         mapKey = "lockoutduration"
                            Case "lockout_threshold":        mapKey = "lockoutbadcount"
                            Case "lockout_reset":            mapKey = "resetlockoutcount"
                            Case "force_logoff":             mapKey = "forcelogoffwhenhourexpire"
                        End Select

                        If secEditDict.Exists(mapKey) Then
                            isFound = True
                            currentVal = secEditDict(mapKey)
                        ElseIf secEditDict.Exists("system access\" & mapKey) Then
                            isFound = True
                            currentVal = secEditDict("system access\" & mapKey)
                        ElseIf secEditDict.Exists(rawArg) Then
                            isFound = True
                            currentVal = secEditDict(rawArg)
                        ElseIf secEditDict.Exists("system access\" & rawArg) Then
                            isFound = True
                            currentVal = secEditDict("system access\" & rawArg)
                        End If

                        If Not isFound Then
                            If netAccountsDict.Exists(rawArg) Then
                                isFound = True
                                currentVal = netAccountsDict(rawArg)
                            ElseIf netAccountsDict.Exists(mapKey) Then
                                isFound = True
                                currentVal = netAccountsDict(mapKey)
                            End If
                        End If

                        If isFound Then
                            If LCase(recVal) = "enabled" Or LCase(recVal) = "disabled" Then
                                If currentVal = "1" Then
                                    currentVal = "Enabled"
                                ElseIf currentVal = "0" Then
                                    currentVal = "Disabled"
                                End If
                            ElseIf recVal = "1" Or recVal = "0" Then
                                If LCase(currentVal) = "enabled" Then
                                    currentVal = "1"
                                ElseIf LCase(currentVal) = "disabled" Then
                                    currentVal = "0"
                                End If
                            End If
                        End If

                    Case "accesschk"
                        Dim secKeyVal, privKey
                        privKey = LCase(Trim(methodArg))
                        secKeyVal = ""
                        isFound = False
                        If secEditDict.Exists("privilege rights\" & privKey) Then
                            secKeyVal = secEditDict("privilege rights\" & privKey)
                            isFound = True
                        ElseIf secEditDict.Exists(privKey) Then
                            secKeyVal = secEditDict(privKey)
                            isFound = True
                        End If

                        If Not isFound Or Trim(secKeyVal) = "" Then
                            currentVal = ""
                            isFound = True
                        Else
                            currentVal = TranslateSidsList(secKeyVal)
                            isFound = True
                        End If

                    Case "auditpol"
                        Dim searchSub
                        searchSub = LCase(Trim(methodArg))
                        If auditPolDict.Exists(searchSub) Then
                            isFound = True
                            currentVal = auditPolDict(searchSub)
                        End If

                    Case "command"
                        If id = "18.9.25.1" Or InStr(1, name, "EMET", vbTextCompare) > 0 Then
                            Dim emetFound, emetVer, testVal
                            emetFound = False
                            emetVer = ""
                            testVal = ReadRegistryValue("HKLM\SOFTWARE\Microsoft\EMET", "InstalledVersion", emetFound)
                            If Not emetFound Then
                                testVal = ReadRegistryValue("HKLM\SOFTWARE\Wow6432Node\Microsoft\EMET", "InstalledVersion", emetFound)
                            End If
                            If emetFound Then
                                If testVal <> "" Then
                                    currentVal = testVal
                                Else
                                    currentVal = "Installed"
                                End If
                                isFound = True
                            Else
                                currentVal = "Not Installed"
                                isFound = True
                            End If
                        Else
                            isUnknownMethod = True
                        End If

                    Case Else
                        isUnknownMethod = True
                End Select

                If isUnknownMethod Then
                    status = "Skipped"
                    currentVal = "SKIPPED: Unknown method '" & method & "'"
                    skippedCount = skippedCount + 1
                Else
                    isCompliant = CompareValue(currentVal, recVal, op, isFound)
                    If isCompliant Then
                        status = "Passed"
                        passedCount = passedCount + 1
                    Else
                        status = "Failed"
                        failedCount = failedCount + 1
                    End If
                End If
            End If

            ' Write CSV line
            outStream.WriteLine EscapeCsv(id) & "," & _
                                EscapeCsv(cat) & "," & _
                                EscapeCsv(name) & "," & _
                                EscapeCsv(method) & "," & _
                                EscapeCsv(methodArg) & "," & _
                                EscapeCsv(regPath) & "," & _
                                EscapeCsv(regItem) & "," & _
                                EscapeCsv(defVal) & "," & _
                                EscapeCsv(recVal) & "," & _
                                EscapeCsv(op) & "," & _
                                EscapeCsv(sev) & "," & _
                                EscapeCsv(currentVal) & "," & _
                                EscapeCsv(status)
        End If
    End If
Loop

inFile.Close
outStream.Close

' Summary Output
WScript.Echo "================ AUDIT SUMMARY (VBScript) ================"
WScript.Echo "Total Findings : " & totalCount
WScript.Echo "Passed         : " & passedCount
WScript.Echo "Failed         : " & failedCount
WScript.Echo "Skipped        : " & skippedCount
WScript.Echo "=========================================================="
WScript.Echo "Report Output  : " & outputFile
