@echo off
ECHO ---- RDP fuzzing example print data version ----
ECHO Note: Make sure to edit this batch file to point to the right server ip address hosting the RDP server.

.\..\Meddle\bin\Release\Meddle.exe example_mstsc\controller.py -printonly -server 192.168.110.136