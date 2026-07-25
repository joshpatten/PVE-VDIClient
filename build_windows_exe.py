#!/usr/bin/env python3
"""
Build script to generate Windows .exe for BIA VDI Client
Run this on Windows with PyInstaller installed

Usage:
    pip install pyinstaller
    python build_windows_exe.py
"""

import PyInstaller.__main__
import os
import sys
import shutil

def build_exe():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(project_dir, 'dist')

    # Clean previous builds
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
        print("Cleaned previous build...")

    # Get absolute paths
    main_script = os.path.join(project_dir, 'vdiclient.py')
    icon_file = os.path.join(project_dir, 'vdiicon.ico')
    logo_file = os.path.join(project_dir, 'vdiclient.png')
    config_file = os.path.join(project_dir, 'vdiclient.ini.default')

    # Verify necessary files exist
    if not os.path.exists(main_script):
        print(f"ERROR: Main script not found: {main_script}")
        return False

    print("Building BIA VDI Client executable...")
    print(f"Project directory: {project_dir}")

    # PyInstaller arguments
    args = [
        main_script,
        '--name=BIA-VDIClient',
        '--onefile',
        '--windowed',
        '--noconfirm',
        f'--icon={icon_file}' if os.path.exists(icon_file) else '',
        '--hidden-import=proxmoxer',
        '--hidden-import=proxmoxer.backends',
        '--hidden-import=proxmoxer.backends.https',
        '--hidden-import=proxmoxer.core',
        '--hidden-import=requests',
        '--hidden-import=requests.exceptions',
        '--hidden-import=customtkinter',
        '--hidden-import=PIL',
        '--distpath=' + dist_dir,
        '--buildpath=' + os.path.join(project_dir, 'build'),
        '--specpath=' + project_dir,
    ]

    # Remove empty strings from args
    args = [arg for arg in args if arg]

    print("\nPyInstaller arguments:")
    for arg in args:
        print(f"  {arg}")

    print("\nStarting PyInstaller...")
    try:
        PyInstaller.__main__.run(args)

        # Copy additional files to dist folder
        dist_exe_dir = os.path.join(dist_dir)

        if os.path.exists(logo_file):
            dest_logo = os.path.join(dist_exe_dir, 'vdiclient.png')
            shutil.copy(logo_file, dest_logo)
            print(f"Copied logo: {dest_logo}")

        if os.path.exists(config_file):
            dest_config = os.path.join(dist_exe_dir, 'vdiclient.ini.default')
            shutil.copy(config_file, dest_config)
            print(f"Copied config: {dest_config}")

        print("\n" + "="*60)
        print("BUILD SUCCESSFUL!")
        print("="*60)
        print(f"\nExecutable location: {os.path.join(dist_exe_dir, 'BIA-VDIClient.exe')}")
        print("\nInstallation Instructions:")
        print("1. Copy BIA-VDIClient.exe and vdiclient.ini.default to your deployment folder")
        print("2. Create vdiclient.ini from vdiclient.ini.default and customize if needed")
        print("3. Place in %PROGRAMFILES%\\VDIClient\\ or %APPDATA%\\VDIClient\\")
        print("4. Users can configure server IP via Settings button in login screen")
        print("="*60)

        return True
    except Exception as e:
        print(f"\nERROR during build: {e}")
        return False

if __name__ == '__main__':
    success = build_exe()
    sys.exit(0 if success else 1)
