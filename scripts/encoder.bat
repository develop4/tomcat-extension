@echo off


set SUN_HOME=C:\data\narowner\product\sun\jdk1.8.0_05_64bit
set KEYTOOL=%JAVA_HOME%\bin\keytool

for /R "%SUN_HOME%" %%F in (keytool.exe.*) do (
	set KEYTOOL="%%F"
)

for /R "%SUN_HOME%" %%G in (cacerts.*) do (
	for %%H in (*.pem) do (
		%KEYTOOL% -noprompt -storepass changeit -import -alias %%~nH -keystore "%%G" -trustcacerts -file %%H
	)
)

if exist "%CATALINA_HOME%\bin\setenv.bat" call "%CATALINA_HOME%\bin\setenv.bat" start

