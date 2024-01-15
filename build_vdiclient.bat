@echo off
pyinstaller --noconsole --noconfirm --hidden-import proxmoxer.backends --hidden-import proxmoxer.backends.https --hidden-import proxmoxer.backends.https.AuthenticationError --hidden-import proxmoxer.core --hidden-import proxmoxer.core.ResourceException --hidden-import subprocess.TimeoutExpired --hidden-import subprocess.CalledProcessError --hidden-import requests.exceptions --hidden-import requests.exceptions.ReadTimeout --hidden-import requests.exceptions.ConnectTimeout --hidden-import requests.exceptions.ConnectionError --noupx -i vdiicon.ico vdiclient.py
copy vdiclient.png dist\vdiclient
copy vdiicon.ico dist\vdiclient
REM del dist\vdiclient\opengl32sw.dll
REM del dist\vdiclient\libGLESv2.dll
REM del dist\vdiclient\d3dcompiler_47.dll
REM del dist\vdiclient\Qt5Pdf.dll
REM del dist\vdiclient\Qt5VirtualKeyboard.dll
REM del dist\vdiclient\Qt5WebSockets.dll
REM del dist\vdiclient\Qt5Quick.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qgif.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qjpeg.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qpdf.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qsvg.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qtga.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qtiff.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qwbmp.dll
REM del dist\vdiclient\PySide2\plugins\imageformats\qwebp.dll
REM del dist\vdiclient\PySide2\plugins\platforminputcontexts\qtvirtualkeyboardplugin.dll
REM del /Q dist\vdiclient\PySide2\translations\*
cd dist
python createmsi.py vdiclient.json
cd ..
