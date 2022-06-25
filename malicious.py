import wmi
import subprocess


def WMIProcessCreation(name):
    c = wmi.WMI()
    processID, returnValue = c.Win32_Process.Create(CommandLine=name)


def PSProcessCreation(name):
    command = ["powershell", "& {Invoke-WmiMethod Win32_Process -Name Create -ArgumentList {calc.exe} "
                             "| select ProcessID | % {$_.ProcessID} | WriteHost } "]
    p = subprocess.run(command, shell=True, capture_output=True)
    #if p.returncode == 0:
      #  print("Process %s created with Powershell, PID %s" % (name, p.stdout.decode("utf-8")))


ccommand = "calc.exe"
WMIProcessCreation(ccommand)
PSProcessCreation(ccommand)
