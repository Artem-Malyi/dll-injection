call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

rem set latin encoding
chcp 850

if "%1"=="" (
    msbuild.exe dll-injection.proj
) else (
    msbuild.exe "%1"
)

pause