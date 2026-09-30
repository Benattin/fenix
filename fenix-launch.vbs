Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
url = "http://127.0.0.1:4250/?app=1"

Function Up()
  On Error Resume Next
  Set http = CreateObject("MSXML2.XMLHTTP")
  http.Open "GET", "http://127.0.0.1:4250/", False
  http.Send
  Up = (http.Status = 200)
End Function

If Not Up() Then
  sh.CurrentDirectory = dir
  sh.Run "node server.js", 0, False
  For i = 1 To 40
    WScript.Sleep 250
    If Up() Then Exit For
  Next
End If

edge = ""
cands = Array( _
  sh.ExpandEnvironmentStrings("%ProgramFiles(x86)%") & "\Microsoft\Edge\Application\msedge.exe", _
  sh.ExpandEnvironmentStrings("%ProgramFiles%") & "\Microsoft\Edge\Application\msedge.exe", _
  sh.ExpandEnvironmentStrings("%LocalAppData%") & "\Google\Chrome\Application\chrome.exe")
For Each p In cands
  If fso.FileExists(p) Then edge = p: Exit For
Next

If edge <> "" Then
  sh.Run """" & edge & """ --app=""" & url & """ --window-size=1280,800", 1, False
Else
  sh.Run "cmd /c start """" """ & url & """", 1, False
End If
