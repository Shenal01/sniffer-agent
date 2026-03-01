Write-Host "Cloning and Bootstrapping vcpkg..."
if (-Not (Test-Path "vcpkg")) {
    git clone https://github.com/microsoft/vcpkg.git
}
cd vcpkg
.\bootstrap-vcpkg.bat
Write-Host "vcpkg bootstrapped successfully."
cd ..
