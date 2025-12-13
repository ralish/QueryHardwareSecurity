@ECHO OFF

WHERE /Q "MSBuild.exe"
IF %ERRORLEVEL% GEQ 1 (
    ECHO [CertUiExts] Unable to build as MSBuild was not found.
    EXIT /B 1
)

WHERE /Q "dotnet.exe"
IF %ERRORLEVEL% GEQ 1 (
    ECHO [QueryHardwareSecurity] Unable to build as dotnet was not found.
    EXIT /B 1
)

@REM Switch to repository root directory
PUSHD "%~dp0\.."

@REM Default MSBuild arguments (also used via dotnet build)
SET MSBuildProjectMain=src\QueryHardwareSecurity\QueryHardwareSecurity.csproj
SET MSBuildProjectLib=src\QueryHardwareSecurityLib\QueryHardwareSecurityLib.vcxproj
SET MSBuildArgs=-noLogo -verbosity:minimal -maxCpuCount
SET MSBuildTarget=Build

@REM Optional first arg is build target
IF NOT "%1" == "" SET MSBuildTarget=%1

ECHO [QueryHardwareSecurityLib] Running target "%MSBuildTarget%" for Debug/x64 ...
MSBuild %MSBuildProjectLib% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug;Platform=x64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [QueryHardwareSecurityLib] Running target "%MSBuildTarget%" for Debug/ARM64 ...
MSBuild %MSBuildProjectLib% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug;Platform=ARM64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [QueryHardwareSecurityLib] Running target "%MSBuildTarget%" for Release/x64 ...
MSBuild %MSBuildProjectLib% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release;Platform=x64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [QueryHardwareSecurityLib] Running target "%MSBuildTarget%" for Release/ARM64 ...
MSBuild %MSBuildProjectLib% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release;Platform=ARM64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [QueryHardwareSecurity] Running target "%MSBuildTarget%" for Debug ...
dotnet build %MSBuildProjectMain% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [QueryHardwareSecurity] Running target "%MSBuildTarget%" for Release ...
dotnet build %MSBuildProjectMain% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

:End
@REM Clean-up script variables
SET MSBuildProjectMain=
SET MSBuildProjectLib=
SET MSBuildArgs=
SET MSBuildTarget=

@REM Restore original directory
POPD
