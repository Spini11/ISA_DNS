# DNS Resolver - ISA projekt
Autor: Viliam Chudáčik, xchuda06\
Datum: 15. listopadu 2023
## Úvod
DNS Resolver vytváří DNS dotazy na základě přijatých argumentů, tyto dotazy následně odesílá na vybraný DNS a zobrazuje odpovědi uživateli.

## Jak vytvořit build aplikace
```sh
# Pro běžné použití
make
# Pro použití s debug funkcemi
make debug
# Pro spuštění testů
make test
```
## Jak spustit aplikaci
Použití: dns [-r] [-x] [-6] [-s server] [-p port] domain\
    -r Rekurzivní dotaz\
    -x Reverzní dotaz\
    -6 Dotaz IPv6\
    -s adresa serveru DNS\
    -p Port serveru DNS\
    domain Dotazované doménové jméno\
    -h, -help, --help a -? zobrazí tuto nápovědu

## Příklad použití
Pro zjištění IPv4 serveru google.com za použití DNS 1.1.1.1\
`./dns -r -s 1.1.1.1 google.com`

Výstup:
```
Authoritative:No,  Recursive:Yes,  Truncated:No, 
Question section(1)
google.com, A, IN
Answer section(1)
google.com, A, IN, 177, 142.251.37.110
Authority section(0)
Additional section(0)
```

Tento výstup nám říká, že přijatá odpověď nebyla odeslána autoritativním serverem, byla provedena rekurzivně a nebyla zkrácena.
Google.com má záznamy typu A, třídy IN, s TTL 177 a hodnotou 142.251.37.110

## Odevzdané soubory
```.
├── arguments.cpp
├── arguments.h
├── dns.cpp
├── dns.h
├── errorHandling.cpp
├── errorHandling.h
├── main.cpp
├── main.h
├── Makefile
├── manual.pdf
├── output.cpp
├── output.h
├── README.MD
└── test
    ├── ArgumentParserTest
    │   ├── ArgParsTest.cpp
    │   └── ArgParsTest.h
    ├── CompleteTest.cpp
    ├── CompleteTest.h
    ├── main.cpp
    ├── main.h
    ├── QueryCreateTest
    │   ├── QueryCreateTest.cpp
    │   └── QueryCreateTest.h
    └── ReadQueryTest
        ├── ReadQueryTest.cpp
        └── ReadQueryTest.h
```