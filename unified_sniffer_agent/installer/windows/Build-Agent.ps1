param (
    [string]$VcpkgToolchain = ".\vcpkg\scripts\buildsystems\vcpkg.cmake"
)

Write-Host "Configuring and Building Unified Sniffer Agent..."
# We assume vcpkg is cloned in the current directory or provide path
$CompilerPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\cl.exe"

if (-Not (Test-Path $VcpkgToolchain)) {
    Write-Host "Warning: Could not find vcpkg toolchain at $VcpkgToolchain. Falling back to default cmake."
    & "C:\Program Files\CMake\bin\cmake.exe" -B build -S . "-DCMAKE_C_COMPILER=$CompilerPath" "-DCMAKE_CXX_COMPILER=$CompilerPath"
} else {
    & "C:\Program Files\CMake\bin\cmake.exe" -B build -S . "-DCMAKE_TOOLCHAIN_FILE=$VcpkgToolchain" "-DCMAKE_C_COMPILER=$CompilerPath" "-DCMAKE_CXX_COMPILER=$CompilerPath"
}

& "C:\Program Files\CMake\bin\cmake.exe" --build build --config Release
Write-Host "Build complete. Executable should be in build/Release/"
