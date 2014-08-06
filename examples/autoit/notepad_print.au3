

Local $pid = $CmdLine[1]
Local $winhandle = 0

Local $ht = TimerInit()
While Not $winhandle
   $Windowlist=WinList("Untitled")
   For $i = 1 to $Windowlist[0][0]
	   If WinGetProcess($Windowlist[$i][1])= $pid Then
		   $winhandle=$Windowlist[$i][1]
	   EndIf
	Next
	
	If TimerDiff( $ht ) > 20000 Then
	   Exit
    EndIf
	
	Sleep(10)
WEnd
 
If $winhandle Then
   Local $cHandle = ControlGetHandle($winhandle,"","Edit1")
   $ht = TimerInit()
   While Not $cHandle
	  Sleep(10)
	  $cHandle = ControlGetHandle($winhandle,"","Edit1")
	  If TimerDiff( $ht ) > 20000 Then
		  Exit
	   EndIf
   WEnd
   
   For $i = 0 To 10
	  ControlSend($winhandle,"","Edit1","^p")
	  Sleep(100)
   Next
EndIf