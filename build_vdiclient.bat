@echo off
pyinstaller --noconsole --noconfirm --hidden-import proxmoxer.backends --hidden-import proxmoxer.backends.https --hidden-import proxmoxer.backends.https.AuthenticationError --hidden-import proxmoxer.core --hidden-import proxmoxer.core.ResourceException --hidden-import subprocess.TimeoutExpired --hidden-import subprocess.CalledProcessError --hidden-import requests.exceptions --hidden-import requests.exceptions.ReadTimeout --hidden-import requests.exceptions.ConnectTimeout --hidden-import requests.exceptions.ConnectionError -i vdiicon.ico vdiclient.py
copy vdiclient.png dist\vdiclient
copy vdiicon.ico dist\vdiclient
del dist\vdiclient\opengl32sw.dll
del dist\vdiclient\libGLESv2.dll
del dist\vdiclient\d3dcompiler_47.dll
del dist\vdiclient\Qt5Pdf.dll
del dist\vdiclient\Qt5VirtualKeyboard.dll
del dist\vdiclient\Qt5WebSockets.dll
del dist\vdiclient\Qt5Quick.dll
del dist\vdiclient\PySide2\plugins\imageformats\qgif.dll
del dist\vdiclient\PySide2\plugins\imageformats\qjpeg.dll
del dist\vdiclient\PySide2\plugins\imageformats\qpdf.dll
del dist\vdiclient\PySide2\plugins\imageformats\qsvg.dll
del dist\vdiclient\PySide2\plugins\imageformats\qtga.dll
del dist\vdiclient\PySide2\plugins\imageformats\qtiff.dll
del dist\vdiclient\PySide2\plugins\imageformats\qwbmp.dll
del dist\vdiclient\PySide2\plugins\imageformats\qwebp.dll
del dist\vdiclient\PySide2\plugins\platforminputcontexts\qtvirtualkeyboardplugin.dll
del /Q dist\vdiclient\PySide2\translations\*
cd dist
python createmsi.py vdiclient.json
cd ..
