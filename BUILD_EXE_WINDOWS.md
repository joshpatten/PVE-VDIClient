# Guia: Build do BIA VDI Client .exe para Windows

## 📋 Pré-requisitos

Antes de começar, você precisa ter instalado no seu Windows:

1. **Python 3.8+** - Baixe de https://www.python.org/downloads/
   - ⚠️ **IMPORTANTE**: Marque a opção "Add Python to PATH" durante a instalação

2. **Git** (opcional) - Para clonar/atualizar o repositório

## 🚀 Processo de Build Rápido

### Opção 1: Usando o Script Batch (Mais Fácil)

1. Abra o **Command Prompt** ou **PowerShell**
2. Navegue até a pasta do projeto:
   ```cmd
   cd caminho\para\BIA-VDIClient
   ```

3. Execute o script de build:
   ```cmd
   build_windows_exe.bat
   ```

4. O script irá:
   - Verificar se Python está instalado
   - Instalar as dependências necessárias
   - Gerar o arquivo `BIA-VDIClient.exe` na pasta `dist\`

### Opção 2: Manualmente (Mais Controle)

1. Abra o **Command Prompt** ou **PowerShell**

2. Navegue até a pasta do projeto:
   ```cmd
   cd caminho\para\BIA-VDIClient
   ```

3. Instale as dependências:
   ```cmd
   pip install proxmoxer customtkinter requests Pillow pyinstaller
   ```

4. Execute o build:
   ```cmd
   python build_windows_exe.py
   ```

## 📦 Arquivos Gerados

Após o build bem-sucedido, você terá:

```
dist/
├── BIA-VDIClient.exe          ← Executável principal
├── vdiclient.png              ← Logo BIA DATACENTER
└── vdiclient.ini.default      ← Configuração padrão
```

## 🔧 Configuração Pós-Build

### Para Instalação Individual

1. **Crie a pasta de configuração:**
   ```cmd
   mkdir "%APPDATA%\VDIClient"
   ```

2. **Copie o arquivo INI padrão:**
   ```cmd
   copy dist\vdiclient.ini.default "%APPDATA%\VDIClient\vdiclient.ini"
   ```

3. **Copie o logo:**
   ```cmd
   copy dist\vdiclient.png "%APPDATA%\VDIClient\"
   ```

4. **Execute o programa:**
   ```cmd
   dist\BIA-VDIClient.exe
   ```

### Para Instalação em Rede (Enterprise)

1. **Copie para pasta compartilhada:**
   ```cmd
   xcopy dist\* "\\servidor\compartilhado\BIA-VDIClient\" /Y /I
   ```

2. **Copie também o arquivo INI padrão:**
   ```cmd
   copy vdiclient.ini.default "\\servidor\compartilhado\BIA-VDIClient\"
   ```

3. **Crie um atalho de rede para os usuários:**
   ```
   "\\servidor\compartilhado\BIA-VDIClient\BIA-VDIClient.exe"
   ```

## 🔐 Configuração de Servidor Proxmox

### Primeira Execução

1. Clique em **"Settings"** na tela de login
2. Configure:
   - **Server IP Address**: IP do seu Proxmox (ex: 10.10.10.50)
   - **Hostname**: Nome para arquivo hosts (ex: pve.local)
   - **Port**: Porta Proxmox (padrão: 8006)
   - **Auth Backend**: tipo de autenticação (pve ou pam)

3. Se desejar, marque **"Add to Windows hosts file"** para:
   - Adicionar entrada em `C:\Windows\System32\drivers\etc\hosts`
   - ⚠️ Requer execução como Administrador

### Arquivo de Configuração

A configuração é salva em:
```
C:\Users\[seu_usuario]\AppData\Roaming\VDIClient\server_config.json
```

Exemplo:
```json
{
    "ip": "10.10.10.50",
    "hostname": "pve.local",
    "port": 8006,
    "backend": "pve"
}
```

## 🖼️ Customização da Logo

Para mudar a logo do BIA DATACENTER:

1. Prepare uma imagem PNG de 400x200px
2. Renomeie para `vdiclient.png`
3. Copie para a pasta do projeto
4. Reconstrua o .exe

## 🐛 Solução de Problemas

### Erro: "Python is not installed"
- Instale Python de https://www.python.org
- Certifique-se de marcar "Add Python to PATH"
- Reinicie o Command Prompt após instalar

### Erro: "ModuleNotFoundError: No module named 'proxmoxer'"
```cmd
pip install proxmoxer customtkinter requests Pillow
```

### Erro: PyInstaller não encontrado
```cmd
pip install pyinstaller
```

### Erro ao adicionar host file (Acesso negado)
- Execute o Command Prompt como Administrador
- Ou desmarque a opção "Add to Windows hosts file" durante configuração

### Arquivo .exe não inicia
- Verifique se `vdiclient.png` está na mesma pasta do .exe
- Copie também o arquivo `vdiclient.ini.default`

## 📝 Arquivo INI Padrão (vdiclient.ini.default)

```ini
[General]
title = BIA DATACENTER
theme = dark
icon = vdiicon.ico
logo = vdiclient.png
fullscreen = True
page_size = 10

[Hosts.PVE]
hostpool = {
               "10.10.10.50" : 8006
           }
auth_backend = pve
auth_totp = false
tls_verify = false
```

Você pode customizar este arquivo antes do build.

## 🔄 Atualizações

Para atualizar o programa:

1. Atualize o repositório:
   ```cmd
   git pull
   ```

2. Reconstrua o .exe:
   ```cmd
   build_windows_exe.bat
   ```

## 📞 Suporte

Para problemas com o Proxmox VDI Client:
- Repositório: https://github.com/joshpatten/PVE-VDIClient
- Issues: https://github.com/joshpatten/PVE-VDIClient/issues

## ✅ Checklist Pré-Deploy

- [ ] Python 3.8+ instalado e testado
- [ ] Todas as dependências instaladas
- [ ] Build completado com sucesso
- [ ] Arquivo BIA-VDIClient.exe gerado
- [ ] Logo vdiclient.png copiada
- [ ] Arquivo vdiclient.ini.default disponível
- [ ] IP Proxmox configurado (10.10.10.50)
- [ ] Hostname definido (pve.local)
- [ ] Testado em pelo menos 1 máquina Windows

---

**Data de Criação**: Julho de 2026
**Versão**: 2.0 (BIA DATACENTER Customizado)
