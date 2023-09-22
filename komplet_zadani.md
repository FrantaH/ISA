### Společná část popisu:
Vytvořte komunikující aplikaci podle konkrétní vybrané specifikace pomocí síťové knihovny BSD sockets (pokud není ve variantě zadání uvedeno jinak). Projekt bude vypracován v jazyce C/C++. Pokud individuální zadání nespecifikuje vlastní referenční systém, musí být projekt přeložitelný a spustitelný na serveru merlin.fit.vutbr.cz pod operačním systémem GNU/Linux. Program by však měl být přenositelný. Hodnocení projektů může probíhat na jiném počítači s nainstalovaným OS GNU/Linux, včetně jiných architektur než Intel/AMD, jiných distribucí, jiných verzí knihoven apod. Pokud vyžadujete minimální verzi knihovny (dostupnou na serveru merlin), jasně tuto skutečnost označte v dokumentaci a README.

Vypracovaný projekt uložený v archívu .tar a se jménem xlogin00.tar odevzdejte elektronicky přes IS. Soubor nekomprimujte.
+ Termín odevzdání je 18.11.2019 (hard deadline). Odevzdání e-mailem po uplynutí termínu, dodatečné opravy či doplnění kódu není možné.
+ Odevzdaný projekt musí obsahovat:
1. soubor se zdrojovým kódem (dodržujte jména souborů uvedená v konkrétním zadání),
1. funkční Makefile pro překlad zdrojového souboru,
1. dokumentaci (soubor manual.pdf), která bude obsahovat uvedení do problematiky, návrhu aplikace, popis implementace, základní informace o programu, návod na použití. V dokumentaci se očekává následující: titulní strana, obsah, logické strukturování textu, přehled nastudovaných informací z literatury, popis zajímavějších pasáží implementace, použití vytvořených programů a literatura.
1. soubor README obsahující krátký textový popis programu s případnými rozšířeními/omezeními, příklad spuštění a seznam odevzdaných souborů,
1. další požadované soubory podle konkrétního typu zadání. 
+ Pokud v projektu nestihnete implementovat všechny požadované vlastnosti, je nutné veškerá omezení jasně uvést v dokumentaci a v souboru README.
+ Co není v zadání jednoznačně uvedeno, můžete implementovat podle svého vlastního výběru. Zvolené řešení popište v dokumentaci.
+ Při řešení projektu respektujte zvyklosti zavedené v OS unixového typu (jako je například formát textového souboru).
+ Vytvořené programy by měly být použitelné a smysluplné, řádně komentované a formátované a členěné do funkcí a modulů. Program by měl obsahovat nápovědu informující uživatele o činnosti programu a jeho parametrech. Případné chyby budou intuitivně popisovány uživateli.
+ Aplikace nesmí v žádném případě skončit s chybou SEGMENTATION FAULT ani jiným násilným systémovým ukončením (např. dělení nulou).
+ Pokud přejímáte krátké pasáže zdrojových kódů z různých tutoriálů či příkladů z Internetu (ne mezi sebou), tak je nutné vyznačit tyto sekce a jejich autory dle licenčních podmínek, kterými se distribuce daných zdrojových kódů řídí. V případě nedodržení bude na projekt nahlíženo jako na plagiát.
+ Konzultace k projektu podává vyučující, který zadání vypsal.
+ Před odevzdáním zkontrolujte, zda jste dodrželi všechna jména souborů požadovaná ve společné části zadání i v zadání pro konkrétní projekt. Zkontrolujte, zda je projekt přeložitelný.
### Hodnocení projektu:
+ Maximální počet bodů za projekt je 20 bodů.
  + Maximálně 15 bodů za plně funkční aplikaci.
  + Maximálně 5 bodů za dokumentaci. Dokumentace se hodnotí pouze v případě funkčního kódu. Pokud kód není odevzdán nebo nefunguje podle zadání, dokumentace se nehodnotí.
+ Příklad kriterií pro hodnocení projektů:
  + nepřehledný, nekomentovaný zdrojový text: až -7 bodů
  + nefunkční či chybějící Makefile: až -4 body
  + nekvalitní či chybějící dokumentace: až -5 bodů
  + nedodržení formátu vstupu/výstupu či konfigurace: -10 body
  + odevzdaný soubor nelze přeložit, spustit a odzkoušet: 0 bodů
  + odevzdáno po termínu: 0 bodů
  + nedodržení zadání: 0 bodů
  + nefunkční kód: 0 bodů
  + opsáno: 0 bodů (pro všechny, kdo mají stejný kód), návrh na zahájení disciplinárního řízení.
### Popis varianty:
Napište program dns, který bude umět zasílat dotazy na DNS servery a v čitelné podobě vypisovat přijaté odpovědi na standardní výstup. Sestavení a analýza DNS paketů musí být implementována přímo v programu dns. Stačí uvažovat pouze komunikaci pomocí UDP.

Není-li v jiné části zadání specifikováno jinak, je při vytváření programu povoleno použít hlavičkové soubory pro práci se sokety a další obvyklé funkce používané v síťovém prostředí (jako je netinet/*, sys/*, arpa/* apod.), knihovnu pro práci s vlákny (pthread), signály, časem, stejně jako standardní knihovnu jazyka C (varianty ISO/ANSI i POSIX), C++ a STL. Jiné knihovny nejsou povoleny.

### Spuštění aplikace
Použití: dns [-r] [-x] [-6] -s server [-p port] adresa

Pořadí parametrů je libovolné. Popis parametrů:
+ -r: Požadována rekurze (Recursion Desired = 1), jinak bez rekurze.
+ -x: Reverzní dotaz místo přímého.
+ -6: Dotaz typu AAAA místo výchozího A.
+ -s: IP adresa nebo doménové jméno serveru, kam se má zaslat dotaz.
+ -p port: Číslo portu, na který se má poslat dotaz, výchozí 53.
+ adresa: Dotazovaná adresa.

### Podporované typy dotazů

Program dns se v odpovědích musí vypořádat se záznamy typu CNAME. Není požadována podpora DNSSEC.

### Výstup aplikace

Na standardní výstup vypište informaci o tom, zda je získaná odpověď autoritativní, zda byla zjištěna rekurzivně a zda byla odpověď zkrácena. Dále vypište všechny sekce a záznamy obdržené v odpovědi.

Pro každou sekci v odpovědi vypište její název a počet získaných záznamů. Pro každý záznam vypište jeho název, typ, třídu, TTL a data.

Ukázka možného výstupu:

$ dns -r -s kazi.fit.vutbr.cz www.fit.vut.cz
Authoritative: No, Recursive: Yes, Truncated: No
Question section (1)
  www.fit.vut.cz., A, IN
Answer section (1)
  www.fit.vut.cz., A, IN, 14400, 147.229.9.26
Authority section (0)
Additional section (0)
$ dns -r -s kazi.fit.vutbr.cz www.ietf.org
Authoritative: No, Recursive: Yes, Truncated: No
Question section (1)
  www.ietf.org., A, IN
Answer section (3)
  www.ietf.org., CNAME, IN, 300, www.ietf.org.cdn.cloudflare.net.
  www.ietf.org.cdn.cloudflare.net., A, IN, 300, 104.20.1.85
  www.ietf.org.cdn.cloudflare.net., A, IN, 300, 104.20.0.85
Authority section (0)
Additional section (0)

### Doplňující informace k zadání
Před odevzdáním projektu si důkladně pročtěte společné zadání pro všechny projekty.
Jakékoliv rozšíření nezapomeňte zdůraznit v souboru README a v dokumentaci. Není však možné získat více bodů, než je stanovené maximum.
Program se musí vypořádat s chybnými vstupy.
Veškeré chybové výpisy vypisujte srozumitelně na standardní chybový výstup.
Pokud máte pocit, že v zadání není něco specifikováno, popište v dokumentaci vámi zvolené řešení a zdůvodněte, proč jste jej vybrali.
Vytvořený kód by měl být modulární a otestovaný. Testy, které jste při řešení projektu napsali se spustí voláním "make test".
Pište robustní aplikace, které budou vstřícné k drobným odchylkám od specifikace.
Při řešení projektu uplatněte znalosti získané v dřívějších kurzech týkající se jak zdrojového kódu (formátování, komentáře), pojmenování souborů, tak vstřícnosti programu k uživateli.
### Referenční prostředí pro překlad a testování
Program by měl být přenositelný. Referenční prostředí pro překlad budou servery eva.fit.vutbr.cz a merlin.fit.vutbr.cz (program musí být přeložitelný a funkční na obou systémech). Vlastní testování může probíhat na jiném počítači s nainstalovaným OS GNU/Linux, či FreeBSD, včetně jiných architektur než Intel/AMD, jiných distribucí, jiných verzí knihoven apod. Pokud vyžadujete minimální verzi knihovny (dostupné na serveru merlin a eva), jasně tuto skutečnost označte v dokumentaci a README.

Doporučená literatura
RFC1035
RFC3596
