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

' 3. Registry Reader via WScript.Shell.RegRead & WMI StdRegProv
Dim objReg
On Error Resume Next
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
On Error GoTo 0

Function ReadRegistryValue(regPath, regItem, ByRef isFound)
    Dim fullPath, v, errNum
    isFound = False
    ReadRegistryValue = ""

    ' Method 1: WScript.Shell.RegRead
    fullPath = regPath & "\" & regItem
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
    If UCase(Left(regPath, 5)) = "HKLM\" Then
        rootKey = &H80000002
        subKey = Mid(regPath, 6)
    ElseIf UCase(Left(regPath, 5)) = "HKCU\" Then
        rootKey = &H80000001
        subKey = Mid(regPath, 6)
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

' 4. System Helpers for Other Methods (Service, LocalAccount, SecEdit, AuditPol)
Dim localAccounts, secEditDict, auditPolDict
Set localAccounts = CreateObject("Scripting.Dictionary")
Set secEditDict = CreateObject("Scripting.Dictionary")
Set auditPolDict = CreateObject("Scripting.Dictionary")

Sub CacheLocalAccounts()
    Dim wmi, colUsers, usr
    On Error Resume Next
    Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
    Set colUsers = wmi.ExecQuery("Select Name, Disabled, SID from Win32_UserAccount Where LocalAccount = True")
    For Each usr In colUsers
        If Right(usr.SID, 4) = "-500" Then
            localAccounts("Administrator_Status") = usr.Disabled
            localAccounts("Administrator_Name") = usr.Name
        ElseIf Right(usr.SID, 4) = "-501" Then
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
    cmd = "secedit.exe /export /cfg """ & tempInf & """ /areas SECURITYPOLICY /log """ & tempLog & """ /quiet"
    On Error Resume Next
    exitCode = sh.Run(cmd, 0, True)
    On Error GoTo 0
    If fso.FileExists(tempLog) Then fso.DeleteFile tempLog, True

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
    Dim cStr, rStr, cNum, rNum, cIsNum, rIsNum
    cStr = SafeToString(cVal)
    rStr = SafeToString(rVal)

    cIsNum = IsNumeric(cStr)
    rIsNum = IsNumeric(rStr)
    If cIsNum And rIsNum Then
        cNum = CDbl(cStr)
        rNum = CDbl(rStr)
    End If

    Select Case LCase(Trim(op))
        Case "="
            If cIsNum And rIsNum Then
                CompareValue = (cNum = rNum)
            Else
                CompareValue = (StrComp(cStr, rStr, vbTextCompare) = 0)
            End If

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

' 6. Pre-fetch Data
CacheLocalAccounts
CacheSecEditPolicy
CacheAuditPol

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
line = inFile.ReadLine
outStream.WriteLine "ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status"

Do Until inFile.AtEndOfStream
    line = Trim(inFile.ReadLine)
    If Len(line) > 0 Then
        fields = ParseCsvLine(line)
        If UBound(fields) >= 10 Then
            totalCount = totalCount + 1

            id = fields(0)
            cat = fields(1)
            name = fields(2)
            method = Trim(fields(3))
            methodArg = fields(4)
            regPath = fields(5)
            regItem = fields(6)
            defVal = fields(7)
            recVal = fields(8)
            op = fields(9)
            sev = fields(10)

            currentVal = ""
            isFound = False
            status = ""

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
                        If InStr(1, name, "status", vbTextCompare) > 0 Or LCase(recVal) = "enabled" Or LCase(recVal) = "disabled" Then
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
                        Dim searchKey
                        searchKey = LCase(Trim(methodArg))
                        If secEditDict.Exists(searchKey) Then
                            isFound = True
                            currentVal = secEditDict(searchKey)
                        ElseIf secEditDict.Exists("system access\" & searchKey) Then
                            isFound = True
                            currentVal = secEditDict("system access\" & searchKey)
                        End If

                    Case "auditpol"
                        Dim searchSub
                        searchSub = LCase(Trim(methodArg))
                        If auditPolDict.Exists(searchSub) Then
                            isFound = True
                            currentVal = auditPolDict(searchSub)
                        End If

                    Case Else
                        currentVal = ""
                End Select

                isCompliant = CompareValue(currentVal, recVal, op, isFound)
                If isCompliant Then
                    status = "Passed"
                    passedCount = passedCount + 1
                Else
                    status = "Failed"
                    failedCount = failedCount + 1
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
