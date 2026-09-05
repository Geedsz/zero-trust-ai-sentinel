@echo off
echo Checking AI DNS Sentinel Status...

schtasks /query /tn "AI_DNS_Sentinel" | find "Disabled" >nul
if %errorlevel% equ 0 (
    echo Sentinel is currently OFF. Enabling now...
    schtasks /change /tn "AI_DNS_Sentinel" /enable
    echo Protection Resumed.
) else (
    echo Sentinel is currently ON. Disabling for gaming...
    schtasks /change /tn "AI_DNS_Sentinel" /disable
    echo Protection Paused. Maximum framerates allocated.
)

timeout /t 3 >nul
