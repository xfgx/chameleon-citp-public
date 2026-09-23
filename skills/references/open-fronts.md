# Otkrytye fronty - chto realno nikem ne izmereno

Kazhdyy front - ubivaemoe utverzhdenie. Esli zamer dast drugoe, utverzhdenie umiraet.
Cel: vybrat temu, kotoruyu mozhno ubit odnim chestnym zamerom (L1-L4).

## Front 1. eps-shchel

Utverzhdenie: net svyazki parametrov, pri kotoroy odnovremenno h_KS > 0 i nablyudatel
Pecora-Carroll skhoditsya. Izmereno: khaos trebuet eps <= 0.05, skhodimost eps >= 0.35;
oblast mezhdu nimi nikto ne kartografiroval dlya Q16.48-reshetki s dvumya eps.
Kak ubit: skan po (eps1, eps2), iskat okno gde lambda1 > 0 I BER kontrolya = 0.

## Front 2. potolok 2.5 bit/sempl

Utverzhdenie: MI-knee ~2.5-2.6 bit/sempl - fizicheskiy potolok emkosti kanala, a ne
artefakt vyborki. Izmereno: M=8 daet 2.46 pri dmax=2^-8; CSK 0.031 (x83 proigrysh).
Kak ubit: postroit MI(M) pri rastushchem M i oknakh; esli knee sdvigaetsya - potolka net.

## Front 3. HGO pipelined feed

Utverzhdenie: pri L >= 12 upravlenie Hayes-Grebogi-Ott dopuskaet konveyernuyu podachu
bez poteri BER=0. Izmereno: L>=12 -> 100% kontrol, BER 0.00; bez kontrolya BER=0.494.
Kak ubit: podat neskolko simvolov v konveyere, izmerit BER i mezhsimvolnuyu interferenciyu.

## Front 4. E6 protiv zhivogo DPI

Utverzhdenie: mutiruyushchee pole ostaetsya nerekonstruiruemym protiv zhivogo TSPU.
Izmereno tolko L1/L2: stationary NMSE ~0.0000, mutating 0.02-2.1, T-gap 200-1600.
Kak ubit: polevoy progon L4 cherez RU-nodu; esli DPI vosstanavlivaet pole v T-gap - umiraet.
Eticheskaya granica: tolko svoya dinamika, nikogda ne otravlyat izmeriteli cenzora.

## Front 5. T-gap formalnaya granica

Utverzhdenie: sushchestvuet nizhnyaya granica T-gap kak funkciya skorosti mutacii polya.
Izmereno: T-gap empiricheski 200-1600, formalnoy granicy net.
Kak ubit: vyvesti granicu iz teoremy Pezina/lyapunovskogo spektra, sverit s zamerom.

## Pravila raboty so spiskom

- Brat rovno odin front za raz i dovodit do chestnogo vyvoda.
- Snachala sanity izmeritelya, potom zamer.
- Zapisyvat uroven dokazatelnosti L1-L4 i chto rezultat NE dokazyvaet.
- Ne dvigat golden-geyty radi krasivogo rezultata.
- Proverit, chto eto ne pereotkrytie (Short 1994, Perez-Cerdeira 1995, Pecora-Carroll, HGO 1993).
