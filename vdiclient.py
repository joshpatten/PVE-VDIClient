#!/usr/bin/python3
import proxmoxer # pip install proxmoxer
import PySimpleGUIQt as sg # pip install PySimpleGUIQt
import requests
from configparser import ConfigParser
import random
import sys
import os
import subprocess
from time import sleep
from io import StringIO


class G:
	hostpool = []
	spiceproxy_conv = {}
	proxmox = None
	vvcmd = None
	#########
	title = 'VDI Login'
	backend = 'pve'
	user = ""
	token_name = None
	token_value = None
	totp = False
	imagefile = None
	kiosk = False
	verify_ssl = True
	icon = None
	theme = 'LightBlue'

sg.theme(G.theme)

def loadconfig(config_location = None):
	if config_location:
		config = ConfigParser(delimiters='=')
		try:
			config.read(config_location)
		except Exception as e:
			win_popup_button(f'Unable to read supplied configuration:\n{e!r}', 'OK')
			config_location = None
	if not config_location:
		if os.name == 'nt': # Windows
			config_location = f'{os.getenv("APPDATA")}\\VDIClient\\vdiclient.ini'
			if not os.path.exists(config_location):
				config_location = f'{os.getenv("PROGRAMFILES")}\\VDIClient\\vdiclient.ini'
			if not os.path.exists(config_location):
				win_popup_button(f'Unable to read supplied configuration from any location!', 'OK')
				return False
		elif os.name == 'posix': #Linux
			config_location = '~/.config/VDIClient/vdiclient.ini'
			if not os.path.exists(config_location):
				config_location = '/etc/vdiclient/vdiclient.ini'
			if not os.path.exists(config_location):
				config_location = '/usr/local/etc/vdiclient/vdiclient.ini'
			if not os.path.exists(config_location):
				win_popup_button(f'Unable to read supplied configuration from any location!', 'OK')
				return False
		config = ConfigParser(delimiters='=')
		try:
			config.read(config_location)
		except Exception as e:
			win_popup_button(f'Unable to read configuration file:\n{e!r}', 'OK')
			config_location = None
	if not 'General' in config:
		win_popup_button(f'Unable to read supplied configuration:\nNo `General` section defined!', 'OK')
		return False
	else:
		if 'title' in config['General']:
			G.title = config['General']['title']
		if 'theme' in config['General']:
			G.theme = config['General']['theme']
		if 'icon' in config['General']:
			if os.path.exists(config['General']['icon']):
				G.icon = config['General']['icon']
		if 'logo' in config['General']:
			if os.path.exists(config['General']['logo']):
				G.imagefile = config['General']['logo']
		if 'kiosk' in config['General']:
			G.kiosk = config['General'].getboolean('kiosk')
	if not 'Authentication' in config:
		win_popup_button(f'Unable to read supplied configuration:\nNo `Authentication` section defined!', 'OK')
		return False
	else:
		if 'auth_backend' in config['Authentication']:
			G.backend = config['Authentication']['auth_backend']
		if 'auth_totp' in config['Authentication']:
			G.totp = config['Authentication'].getboolean('auth_totp')
		if 'tls_verify' in config['Authentication']:
			G.verify_ssl = config['Authentication'].getboolean('tls_verify')
		if 'user' in config['Authentication']:
				G.user = config['Authentication']['user']
		if 'token_name' in config['Authentication']:
				G.token_name = config['Authentication']['token_name']
		if 'token_value' in config['Authentication']:
				G.token_value = config['Authentication']['token_value']
	if not 'Hosts' in config:
		win_popup_button(f'Unable to read supplied configuration:\nNo `Hosts` section defined!', 'OK')
		return False
	else:
		for key in config['Hosts']:
			G.hostpool.append({
				'host': key,
				'port': int(config['Hosts'][key])
			})
	if 'SpiceProxyRedirect' in config:
		for key in config['SpiceProxyRedirect']:
			G.spiceproxy_conv[key] = config['SpiceProxyRedirect'][key]
	return True

def win_popup(message):
	layout = [[sg.Text(message)]]
	window = sg.Window('Message', layout, no_titlebar=True, keep_on_top=True, finalize=True)
	return window
	
def win_popup_button(message, button):
	layout = [
				[sg.Text(message)],
				[sg.Button(button)]
			]
	window = sg.Window('Message', layout, return_keyboard_events=True, no_titlebar=True, keep_on_top=True, finalize=True)
	window.Element(button).SetFocus()
	while True:
		event, values = window.read()
		if event in (button, sg.WIN_CLOSED, 'Log In', '\r', 'special 16777220', 'special 16777221'):
			window.close()
			return

def setmainlayout():
	layout = []
	if G.imagefile:
		layout.append([sg.Image(G.imagefile), sg.Text(G.title, size =(18, 1), justification='c', font=["Helvetica", 18])])
	else:
		layout.append([sg.Text(G.title, size =(30, 1), justification='c', font=["Helvetica", 18])])
	layout.append([sg.Text("Username", size =(12, 1), font=["Helvetica", 12]), sg.InputText(default_text=G.user,key='-username-', font=["Helvetica", 12])])
	layout.append([sg.Text("Password", size =(12, 1),font=["Helvetica", 12]), sg.InputText(key='-password-', password_char='*', font=["Helvetica", 12])])
	
	if G.totp:
		layout.append([sg.Text("OTP Key", size =(12, 1), font=["Helvetica", 12]), sg.InputText(key='-totp-', font=["Helvetica", 12])])
	if G.kiosk:
		layout.append([sg.Button("Log In", font=["Helvetica", 14])])
	else:
		layout.append([sg.Button("Log In", font=["Helvetica", 14]), sg.Button("Cancel", font=["Helvetica", 14])])
	return layout

def getvms():
	vms = []
	for vm in G.proxmox.cluster.resources.get(type='vm'):
		vms.append(vm)
	return vms

def setvmlayout(vms):
	layout = []
	if G.imagefile:
		layout.append([sg.Image(G.imagefile), sg.Text(G.title, size =(18, 1), justification='c', font=["Helvetica", 18])])
	else:
		layout.append([sg.Text(G.title, size =(30, 1), justification='c', font=["Helvetica", 18])])
	layout.append([sg.Text('Please select a desktop instance to connect to', size =(40, 1), justification='c', font=["Helvetica", 10])])
	layoutcolumn = []
	for vm in vms:
		if not vm["status"] == "unknown":
			connkeyname = f'-CONN|{vm["vmid"]}-'
			layoutcolumn.append([sg.Text(vm['name'], font=["Helvetica", 14]), sg.Button('Connect', font=["Helvetica", 14], key=connkeyname)])
			layoutcolumn.append([sg.HorizontalSeparator()])
	if len(vms) > 5: # We need a scrollbar
		layout.append([sg.Column(layoutcolumn, scrollable = True, size = [450, None] )])
	else:
		for row in layoutcolumn:
			layout.append(row)
	layout.append([sg.Button('Logout', font=["Helvetica", 14])])
	return layout

def vmaction(vmnode, vmid, vmtype):
	status = False
	if vmtype == 'qemu':
		vmstatus = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.get('current')
	else: # Not sure this is even a thing, but here it is...
		vmstatus = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.get('current')
	if vmstatus['status'] != 'running':
		startpop = win_popup(f'Starting {vmstatus["name"]}...')
		try:
			if vmtype == 'qemu':
				jobid = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.start.post(timeout=28)
			else: # Not sure this is even a thing, but here it is...
				jobid = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.start.post(timeout=28)
		except proxmoxer.core.ResourceException as e:
			startpop.close()
			win_popup_button(f"Unable to start VM, please provide your system administrator with the following error:\n {e!r}", 'OK')
			return False
		running = False
		i = 0
		while running == False and i < 30:
			jobstatus = G.proxmox.nodes(vmnode).tasks(jobid).status.get()
			if 'exitstatus' in jobstatus:
				startpop.close()
				startpop = None
				if jobstatus['exitstatus'] != 'OK':
					win_popup_button('Unable to start VM, please contact your system administrator for assistance', 'OK')
					running = True
				else:
					running = True
					status = True
			sleep(1)
			i += 1
		if not status:
			if startpop:
				startpop.close()
			return status
	connpop = win_popup(f'Connecting to {vmstatus["name"]}...')
	if vmtype == 'qemu':
		spiceconfig = G.proxmox.nodes(vmnode).qemu(str(vmid)).spiceproxy.post()
	else: # Not sure this is even a thing, but here it is...
		spiceconfig = G.proxmox.nodes(vmnode).lxc(str(vmid)).spiceproxy.post()
	confignode = ConfigParser()
	confignode['virt-viewer'] = {}
	for key,value in spiceconfig.items():
		if key == 'proxy':
			val = value[7:]
			if val in G.spiceproxy_conv:
				confignode['virt-viewer'][key] = f'http://{G.spiceproxy_conv[val]}'
			else:
				confignode['virt-viewer'][key] = f'{value}'
		else:
			confignode['virt-viewer'][key] = f'{value}'
	inifile = StringIO('')
	confignode.write(inifile)
	inifile.seek(0)
	inistring = inifile.read()
	pcmd = [G.vvcmd]
	if G.kiosk:
		pcmd.append('--kiosk')
		pcmd.append('--kiosk-quit')
		pcmd.append('on-disconnect')
	else:
		pcmd.append('--full-screen')
	pcmd.append('-') #We need it to listen on stdin
	process = subprocess.Popen(pcmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
	try:
		output = process.communicate(input=inistring.encode('utf-8'), timeout=5)[0]
	except subprocess.TimeoutExpired:
		pass
	status = True
	connpop.close()
	return status


def setcmd():
	try:
		if os.name == 'nt': # Windows
			import csv
			cmd1 = 'ftype VirtViewer.vvfile'
			result = subprocess.check_output(cmd1, shell=True)
			cmdresult = result.decode('utf-8')
			cmdparts = cmdresult.split('=')
			for row in csv.reader([cmdparts[1]], delimiter = ' ', quotechar = '"'):
				G.cmd = row[0]
				break

		elif os.name == 'posix':
			cmd1 = 'which remote-viewer'
			result = subprocess.check_output(cmd1, shell=True)
			G.vvcmd = 'remote-viewer'
	except subprocess.CalledProcessError:
		if os.name == 'nt':
			win_popup_button('Installation of virt-viewer missing, please install from https://virt-manager.org/download/', 'OK')
		elif os.name == 'posix':
			win_popup_button('Installation of virt-viewer missing, please install using `apt install virt-viewer`', 'OK')
		sys.exit()

def pveauth(username, passwd, totp):
	random.shuffle(G.hostpool)
	err = None
	for hostinfo in G.hostpool:
		host = hostinfo['host']
		if 'port' in hostinfo:
			port = hostinfo['port']
		else:
			port = 8006
		connected = False
		authenticated = False
		if not connected and not authenticated:
			try:
				if G.token_name and G.token_value:
					G.proxmox = proxmoxer.ProxmoxAPI(host, user=f'{username}@{G.backend}',token_name=G.token_name,token_value=G.token_value, verify_ssl=G.verify_ssl, port=port)
				elif totp:
					G.proxmox = proxmoxer.ProxmoxAPI(host, user=f'{username}@{G.backend}', otp=totp, password=passwd, verify_ssl=G.verify_ssl, port=port)
				else:
					G.proxmox = proxmoxer.ProxmoxAPI(host, user=f'{username}@{G.backend}', password=passwd, verify_ssl=G.verify_ssl, port=port)
				connected = True
				authenticated = True
				return connected, authenticated, err
			except proxmoxer.backends.https.AuthenticationError as e:
				err = e
				connected = True
				return connected, authenticated, err
			except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
				err = e
				connected = False
	return connected, authenticated, err

def loginwindow():
	layout = setmainlayout()
	if G.icon:
		window = sg.Window(G.title, layout, return_keyboard_events=True, resizable=False, no_titlebar=G.kiosk, icon=G.icon)
	else:
		window = sg.Window(G.title, layout, return_keyboard_events=True, resizable=False, no_titlebar=G.kiosk)
	while True:
		event, values = window.read()
		if event == 'Cancel' or event == sg.WIN_CLOSED:
			window.close()
			return False
		else:
			if event in ('Log In', '\r', 'special 16777220', 'special 16777221'):
				popwin = win_popup("Please wait, authenticating...")
				user = values['-username-']
				passwd = values['-password-']
				totp = None
				if '-totp-' in values:
					if values['-totp-'] not in (None, ''):
						totp = values['-totp-']
				connected, authenticated, error = pveauth(user, passwd, totp)
				popwin.close()
				if not connected:
					win_popup_button(f'Unable to connect to any VDI server, are you connected to the Internet?\nError Info: {error}', 'OK')
				elif connected and not authenticated:
					win_popup_button('Invalid username and/or password, please try again!', 'OK')
				elif connected and authenticated:
					window.close()
					return True
				#break

def showvms():
	vms = getvms()
	if len(vms) < 1:
		win_popup_button('No desktop instances found, please consult with your system administrator', 'OK')
		return False
	layout = setvmlayout(vms)
	if G.icon:
		window = sg.Window(G.title, layout, return_keyboard_events=True, resizable=False, no_titlebar=G.kiosk, icon=G.icon)
	else:
		window = sg.Window(G.title, layout, return_keyboard_events=True, resizable=False, no_titlebar=G.kiosk)
	while True:
		event, values = window.read()
		if event == 'Logout':
			window.close()
			return False
		if event.startswith('-CONN'):
			eventparams = event.split('|')
			vmid = eventparams[1][:-1]
			found = False
			for vm in vms:
				if str(vm['vmid']) == vmid:
					found = True
					vmaction(vm['node'], vmid, vm['type'])
			if not found:
				win_popup_button(f'VM {vm["name"]} no longer availble, please contact your system administrator', 'OK')
	return True

def main():
	config_location = None
	if len(sys.argv) > 1:
		if sys.argv[1] == '--list_themes':
			sg.preview_all_look_and_feel_themes()
			return
		if sys.argv[1] == '--config':
			if len(sys.argv) < 3:
				win_popup_button('No config file provided with `--config` parameter.\nPlease provide location of config file!', 'OK')
				return
			else:
				config_location = sys.argv[2]
	setcmd()
	if not loadconfig(config_location):
		return False
	loggedin = False
	while True:
		if not loggedin:
			loggedin = loginwindow()
			if not loggedin:
				break
			else:
				vmstat = showvms()
				if not vmstat:
					G.proxmox = None
					loggedin = False
				else:
					return
sys.exit(main())
