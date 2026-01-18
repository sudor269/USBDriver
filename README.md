# Проект Blue-Team "Защита устройств от незарегистрированных USB-накопителей
## Инструкция по использованию проекта:
Добавление драйвера на компьютер:
```
1) git clone https://github.com/sudor269/USBDriver.git
2) Copy-Item "C:\USBDriver\MyDriver1.sys" "C:\Windows\System32\drivers\MyDriver1.sys" -Force
3) bcdedit /set testsignign on
4) sc.exe create MyDriver1 type= filesys start= demand binPath= "\SystemRoot\System32\drivers\MyDriver1.sys" group= "FSFilter Activity Monitor" depend= FltMgr
5) reg add "HKLM\SYSTEM\CurrentControlSet\Services\MyDriver1\Instances" /v DefaultInstance /t REG_SZ /d "MyDriver1 Instance" /f
6) reg add "HKLM\SYSTEM\CurrentControlSet\Services\MyDriver1\Instances\MyDriver1 Instance" /v Altitude /t REG_SZ /d "370100" /f
7) reg add "HKLM\SYSTEM\CurrentControlSet\Services\MyDriver1\Instances\MyDriver1 Instance" /v Flags /t REG_DWORD /d 0 /f
8) fltmc load MyDriver1 
```
Получение идентификатора USB-устройства и добавление в реестр:
```
Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' }
python3 whitelist.py add <serial_number>
```
