# 32-bit bridge to Hamilton's COM transport, for pylabrobot.io.hamilton_com.HamiltonComIO.
#
# Hamilton's HxUsbComm COM server is a 32-bit in-process DLL, so a 64-bit Python cannot load
# it. This script runs under 32-bit PowerShell and relays a simple line protocol on
# stdin/stdout:
#
#   CONNECT <path to ML_STAR.cfg>   ->  OK | ERR <message>
#   W <command string>              ->  OK | ERR <message>
#   R                               ->  D <payload> | N | ERR <message>
#   QUIT                            ->  (exits)
#
# Replies arrive asynchronously on the OnReceive event, so R polls a queue rather than
# reading a stream. Nothing but protocol lines may be written to stdout.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$usb = $null
$cfg = $null
$running = $true

function Write-Line($text) {
  [Console]::Out.WriteLine($text)
  [Console]::Out.Flush()
}

while ($running) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  $line = $line.Trim()
  if ($line -eq '') { continue }

  $sp = $line.IndexOf(' ')
  if ($sp -lt 0) { $verb = $line; $arg = '' }
  else { $verb = $line.Substring(0, $sp); $arg = $line.Substring($sp + 1) }

  try {
    switch ($verb) {

      'CONNECT' {
        $cfg = New-Object -ComObject 'HXCFGFILLib.HxCfgFile'
        [void]$cfg.LoadFile($arg)
        $usb = New-Object -ComObject 'Hamilton.HxUSBIO'
        Register-ObjectEvent -InputObject $usb -EventName OnReceive -SourceIdentifier HXRX | Out-Null
        Register-ObjectEvent -InputObject $usb -EventName OnConnect -SourceIdentifier HXCONN | Out-Null
        $usb.InitFromCfgFil($cfg)

        # InitFromCfgFil returns before the link is up; Send fails with "Not connected to USB
        # Device" until OnConnect has fired. Wait-Event is used rather than a Get-Event poll
        # because it pumps the event queue - queued COM events are not delivered reliably
        # inside a nested block otherwise.
        $ev = Wait-Event -SourceIdentifier HXCONN -Timeout 15
        if ($ev) {
          Remove-Event -SourceIdentifier HXCONN -ErrorAction SilentlyContinue
          Write-Line 'OK'
        } else {
          Write-Line 'ERR OnConnect did not fire within 15s'
        }
      }

      'W' {
        if ($null -eq $usb) { Write-Line 'ERR not connected' }
        else { $usb.Send($arg); Write-Line 'OK' }
      }

      'R' {
        # Wait-Event pumps the queue and blocks briefly, so an idle poll is cheap and a reply
        # that lands mid-poll is returned immediately.
        $e = Wait-Event -SourceIdentifier HXRX -Timeout 1
        if ($e) {
          $payload = [string]$e.SourceArgs[0]
          Remove-Event -EventIdentifier $e.EventIdentifier
          # guard against a payload that would break the line protocol
          $payload = $payload -replace '\r?\n', ' '
          Write-Line "D $payload"
        } else {
          Write-Line 'N'
        }
      }

      'QUIT' {
        $running = $false
        Write-Line 'OK'
      }

      default { Write-Line "ERR unknown verb '$verb'" }
    }
  } catch {
    $msg = $_.Exception.Message -replace '\r?\n', ' '
    Write-Line "ERR $msg"
  }
}

try { Unregister-Event -SourceIdentifier HXRX -ErrorAction SilentlyContinue } catch {}
if ($null -ne $usb) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($usb) } catch {} }
if ($null -ne $cfg) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($cfg) } catch {} }
