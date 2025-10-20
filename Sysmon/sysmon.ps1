#Requires -RunAsAdministrator
# Script para habilitar logs de seguranca do Windows + Sysmon
# Execucao: powershell.exe -ExecutionPolicy Bypass -File .\Enable-SecurityLogs.ps1

# Verificar privilegios de administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Este script requer privilegios administrativos. Execute como administrador."
    Exit
}

Write-Host ""
Write-Host "=== CONFIGURACAO DE LOGS DE SEGURANCA DO WINDOWS ===" -ForegroundColor Cyan
Write-Host ""

# Perguntar sobre instalacao do Sysmon
$InstallSysmon = Read-Host "Deseja instalar/reinstalar o Sysmon? (S/N)"
$InstallSysmon = $InstallSysmon.ToLower()

# ============================================
# PARTE 1: CONFIGURAR AUDITORIA VIA AUDITPOL
# ============================================
Write-Host ""
Write-Host "[1/5] Configurando politicas de auditoria..." -ForegroundColor Yellow

# Habilitar auditoria de criacao de processos (necessario para Event 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

# Habilitar auditorias de logon
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Habilitar auditorias de gerenciamento de contas
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

# Habilitar auditorias de acesso a objetos
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# Habilitar auditorias de mudancas de politica
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

# Habilitar auditorias de uso de privilegios
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable

Write-Host "  OK - Politicas de auditoria configuradas" -ForegroundColor Green

# ============================================
# PARTE 2: HABILITAR COMMAND LINE NO EVENT 4688
# ============================================
Write-Host ""
Write-Host "[2/5] Habilitando Command Line no Event 4688..." -ForegroundColor Yellow

# Configuracao correta para incluir linha de comando no evento 4688
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}
Set-ItemProperty -Path $RegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

Write-Host "  OK - Command Line habilitado no Event 4688" -ForegroundColor Green

# ============================================
# PARTE 3: HABILITAR POWERSHELL LOGGING
# ============================================
Write-Host ""
Write-Host "[3/5] Habilitando PowerShell Logging..." -ForegroundColor Yellow

# Script Block Logging
$PSScriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $PSScriptBlockPath)) {
    New-Item -Path $PSScriptBlockPath -Force | Out-Null
}
Set-ItemProperty -Path $PSScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

# Module Logging
$PSModulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $PSModulePath)) {
    New-Item -Path $PSModulePath -Force | Out-Null
}
Set-ItemProperty -Path $PSModulePath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

# Transcription Logging
$PSTranscriptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $PSTranscriptPath)) {
    New-Item -Path $PSTranscriptPath -Force | Out-Null
}
Set-ItemProperty -Path $PSTranscriptPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $PSTranscriptPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $PSTranscriptPath -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String -Force

# Criar diretorio para transcripts
if (-not (Test-Path "C:\PSTranscripts")) {
    New-Item -ItemType Directory -Path "C:\PSTranscripts" -Force | Out-Null
}

Write-Host "  OK - PowerShell Logging habilitado" -ForegroundColor Green

# ============================================
# PARTE 4: HABILITAR LOGS ADICIONAIS
# ============================================
Write-Host ""
Write-Host "[4/5] Habilitando logs adicionais de seguranca..." -ForegroundColor Yellow

# Funcao para habilitar logs do Event Viewer
function Enable-EventLog {
    param([string]$LogName)
    try {
        wevtutil sl "$LogName" /e:true 2>$null
        Write-Host "  OK - $LogName habilitado" -ForegroundColor Green
    } catch {
        Write-Host "  AVISO - Nao foi possivel habilitar $LogName" -ForegroundColor Yellow
    }
}

# Habilitar logs importantes
Enable-EventLog "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
Enable-EventLog "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
Enable-EventLog "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
Enable-EventLog "Microsoft-Windows-SmbClient/Security"
Enable-EventLog "Microsoft-Windows-SMBServer/Security"
Enable-EventLog "Microsoft-Windows-TaskScheduler/Operational"
Enable-EventLog "Microsoft-Windows-Windows Defender/Operational"
Enable-EventLog "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
Enable-EventLog "Microsoft-Windows-PowerShell/Operational"

# ============================================
# PARTE 5: INSTALAR/CONFIGURAR SYSMON
# ============================================
if ($InstallSysmon -eq "s" -or $InstallSysmon -eq "y") {
    Write-Host ""
    Write-Host "[5/5] Instalando Sysmon..." -ForegroundColor Yellow
    
    # Verificar se Sysmon ja esta instalado
    $SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($SysmonService) {
        Write-Host "  ! Sysmon ja instalado. Desinstalando versao antiga..." -ForegroundColor Yellow
        Start-Process -FilePath "$env:TEMP\Sysmon\Sysmon64.exe" -ArgumentList "-u","force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    
    # Definir caminhos
    $SysmonPath = "$env:TEMP\Sysmon.zip"
    $SysmonExtractPath = "$env:TEMP\Sysmon"
    $SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $SysmonConfigPath = "C:\Windows\sysmon-config.xml"
    
    try {
        # Configurar TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Baixar Sysmon
        Write-Host "  -> Baixando Sysmon..." -ForegroundColor Cyan
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($SysmonUrl, $SysmonPath)
        
        # Baixar configuracao (usando SwiftOnSecurity, mais completa)
        Write-Host "  -> Baixando configuracao Sysmon..." -ForegroundColor Cyan
        $WebClient.DownloadFile($SysmonConfigUrl, $SysmonConfigPath)
        
        # Extrair Sysmon
        Write-Host "  -> Extraindo Sysmon..." -ForegroundColor Cyan
        if (Test-Path $SysmonExtractPath) {
            Remove-Item -Path $SysmonExtractPath -Recurse -Force
        }
        Expand-Archive -Path $SysmonPath -DestinationPath $SysmonExtractPath -Force
        
        # Instalar Sysmon
        Write-Host "  -> Instalando Sysmon64..." -ForegroundColor Cyan
        $SysmonExe = Get-ChildItem -Path $SysmonExtractPath -Filter "Sysmon64.exe" -Recurse | Select-Object -First 1
        
        if ($SysmonExe) {
            Start-Process -FilePath $SysmonExe.FullName -ArgumentList "-accepteula","-i",$SysmonConfigPath -Wait -NoNewWindow
            Start-Sleep -Seconds 3
            
            # Verificar se o servico esta rodando
            $SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
            if ($SysmonService -and $SysmonService.Status -eq "Running") {
                Write-Host "  OK - Sysmon instalado e rodando com sucesso!" -ForegroundColor Green
                Write-Host "  -> Configuracao: $SysmonConfigPath" -ForegroundColor Cyan
            } else {
                Write-Host "  AVISO - Sysmon instalado mas servico nao esta rodando" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  ERRO - Sysmon64.exe nao encontrado" -ForegroundColor Red
        }
        
        # Limpar arquivos temporarios
        Remove-Item -Path $SysmonPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $SysmonExtractPath -Recurse -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "  ERRO ao instalar Sysmon: $_" -ForegroundColor Red
    }
} else {
    Write-Host ""
    Write-Host "[5/5] Instalacao do Sysmon ignorada" -ForegroundColor Yellow
}

# ============================================
# RESUMO FINAL
# ============================================
Write-Host ""
Write-Host ""
Write-Host "=== RESUMO DA CONFIGURACAO ===" -ForegroundColor Cyan

# Verificar Event 4688
$CmdLineEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
if ($CmdLineEnabled.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Host "OK - Event 4688 com Command Line: HABILITADO" -ForegroundColor Green
} else {
    Write-Host "ERRO - Event 4688 com Command Line: DESABILITADO" -ForegroundColor Red
}

# Verificar PowerShell Logging
$PSLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($PSLogging.EnableScriptBlockLogging -eq 1) {
    Write-Host "OK - PowerShell Script Block Logging: HABILITADO" -ForegroundColor Green
} else {
    Write-Host "ERRO - PowerShell Script Block Logging: DESABILITADO" -ForegroundColor Red
}

# Verificar Sysmon
$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($SysmonService -and $SysmonService.Status -eq "Running") {
    Write-Host "OK - Sysmon: INSTALADO E RODANDO" -ForegroundColor Green
} else {
    Write-Host "ERRO - Sysmon: NAO INSTALADO OU NAO RODANDO" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== COMO VERIFICAR OS LOGS ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Event 4688 com Command Line:"
Write-Host "   - Abra: Event Viewer -> Windows Logs -> Security"
Write-Host "   - Filtre por Event ID 4688"
Write-Host "   - Voce deve ver o campo 'Process Command Line'"
Write-Host ""
Write-Host "2. PowerShell Logs:"
Write-Host "   - Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational"
Write-Host "   - Event ID 4104 (Script Block)"
Write-Host ""
Write-Host "3. Sysmon Logs:"
Write-Host "   - Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational"
Write-Host "   - Event ID 1 (Process Creation), Event ID 3 (Network Connection), etc."
Write-Host ""
Write-Host "4. Testar agora:"
Write-Host "   - Execute: notepad.exe test.txt"
Write-Host "   - Va ao Event Viewer -> Security -> Event ID 4688"
Write-Host "   - Voce deve ver a linha de comando completa"
Write-Host ""
Write-Host "IMPORTANTE: Pode levar alguns minutos para os logs comecarem a aparecer apos a configuracao!"
Write-Host ""

Write-Host "Pressione qualquer tecla para sair..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
