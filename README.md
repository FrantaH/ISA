# ISA

Projekt do předmětu Síťové aplikace a správa sítí v roce 2019/2020

Varianta termínu - DNS resolver (Dr. Polčák)

### zadání:

Napište program dns, který bude umět zasílat dotazy na DNS servery a v čitelné podobě vypisovat přijaté odpovědi na standardní výstup. Sestavení a analýza DNS paketů musí být implementována přímo v programu dns. Stačí uvažovat pouze komunikaci pomocí UDP.

### Obsažené soubory:
Makefile	- pro překlad
dns.c		- zdrojový soubor
manual.pdf	- dokumentace
README		- tento soubor

### Omezení:
při výpisu SOA záznamu nejspíše špatně vypisuje číselné hodnoty (serial, refresh, int retry, expire, minimum)

### Funkčnost:
aplikace dns slouží pro dotazování dns serveru a následné vypsání odpovědi.

### spuštění:
./dns dns [-r] [-x] [-6] -s server [-p port] adresa, kde význam parametru je následující: 
* -r: Určuje, zda chceme požádat o rekursivní dotaz (nastavuje flag RD).
* -x: Určuje, že chceme využít reversní dotaz, předpokládá v adrese IP adresu
* -6: Místo výchozího A dotazu se ptáme na AAAA. V kombinaci s -x určujeme, že zadaný argument <adresa> bude IPv6 adresa.
* -s <server>: Nutný argument, na který dns server máme dotaz posílat, možné zadat jak doménové jméno tak IP adresu.
* -p <port>: Zbytečný argument, který udává přes jaký port chceme komunikovat, kažopádně server na jiný, než výchozí port 53 neodpovídá.
* <adresa>: Jméno, případně IP, na které se chceme dotázat. Tato adresa je poslední zadaný argument, který neodpovídá žádnému předchozímu [1]. 

### příklad spuštění:
make 
sudo ./dns -r -s 8.8.8.8 www.fit.vutbr.cz

nebo

make test



[1]: například spuštění: 
		./dns -s 8.8.8.8 www.náhodná.doména www.fit.vutbr.cz
	odignoruje celý argument <www.náhodná.doména> a bude se ptát na www.fit.vutbr.cz
