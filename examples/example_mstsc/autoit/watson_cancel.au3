


While True
   $Windowlist=WinList("file:///C:/Users/glmcdona/Documents/Visual Studio 2012/Projects/Meddle/Meddle/bin/Debug/Meddle.EXE")
   if $Windowlist[0][0] = 0 Then
	  Exit
   EndIf
   
   $Windowlist=WinList("[CLASS:#32770]")
   
   For $i = 1 to $Windowlist[0][0]
	  Local $cHandle = ControlGetHandle($Windowlist[$i][1],"","Cancel")
	  
	   ControlClick($Windowlist[$i][1], "", "Cancel")
	Next
	
	$Windowlist=WinList("Remote Desktop Connection")
	
   Sleep(3000)
WEnd
