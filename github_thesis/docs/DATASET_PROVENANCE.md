# Herkunft und Geltungsbereich des Datensatzes

## Klare Herkunftsaussage

Der Datensatz ist kein aus dem Internet heruntergeladenes Schadcode-Korpus. Die 30 positiven Grundmuster sind direkt in <code>artifacts/source/generate_dataset.py</code> definiert. Der Generator erzeugt daraus jeweils eine klare Variante und vier obfuskierte Varianten. Dadurch entstehen 150 positive Testfälle.

Öffentliche Quellen dienen zur Auswahl, Benennung und MITRE-ATT&CK-Einordnung der dargestellten Techniken. Sie sind keine direkte Herkunft vollständiger Sample-Texte. Es wurden keine vollständigen Skripte, Payload-Dateien oder C2-Implantate aus den referenzierten Repositories importiert.

## Zusammensetzung

| Klasse oder Gruppe | Anzahl | Herkunft |
|---|---:|---|
| Normale benigne Testfälle | 100 | lokal zusammengestellte administrative PowerShell-Aufgaben |
| Schwierige benigne Grenzfälle | 50 | lokal zusammengestellte legitime Fälle mit auffälliger Textstruktur |
| Klare positive Indikatorfälle | 30 | je ein lokal definiertes Grundmuster |
| Obfuskierte positive Indikatorfälle | 120 | vier kontrollierte Varianten je Grundmuster |
| Gesamt | 300 | synthetischer, vom Verfasser gelabelter Labordatensatz |

Die 30 positiven Grundmuster decken neun taktische Kategorien ab:

| Taktische Kategorie | Grundmuster | Testfälle |
|---|---:|---:|
| Defense Evasion | 8 | 40 |
| Command and Control | 6 | 30 |
| Execution | 4 | 20 |
| Collection | 3 | 15 |
| Discovery | 3 | 15 |
| Credential Access | 2 | 10 |
| Persistence | 2 | 10 |
| Lateral Movement | 1 | 5 |
| Exfiltration | 1 | 5 |

## Rolle der Quellen

Das Feld <code>source_snapshot_ids</code> und die Datei <code>source_manifest.json</code> dokumentieren die fachlichen Bezugspunkte und deren Versionsstände. Diese Angaben bedeuten nicht, dass der jeweilige Sample-Text aus der angegebenen Quelle kopiert wurde.

Verwendete Bezugspunkte sind:

- MITRE ATT&CK für Techniken und taktische Einordnung,
- Atomic Red Team für dokumentierte Angriffsmuster,
- Sigma und Wazuh für regelbasierte Indikatoren,
- LOLBAS für Living-off-the-Land-Techniken,
- Invoke-Obfuscation für Obfuskationskategorien,
- Microsoft-Dokumentation für PowerShell- und Administrationsbezug.

## Bedeutung des Labels

<code>simulated_malicious</code> bedeutet:

> Der Testfall enthält einen zuvor definierten, angriffsbezogenen Textindikator.

Das Label bedeutet nicht:

> Der Testfall hat eine schädliche Aktion ausgeführt oder ein System kompromittiert.

Die positive Klasse gibt rekonstruierte oder dekodierte Zeichenketten nur aus. Der Ausführungslauf erlaubt für diese Fälle ausschließlich <code>Write-Output</code>. Reservierte <code>.invalid</code>-Domänen und IANA-TEST-NET-Adressen verhindern unbeabsichtigte Verbindungen.

## Wissenschaftliche Aussagegrenze

Der Datensatz eignet sich für einen kontrollierten und reproduzierbaren Vergleich textbasierter Erkennungsverfahren. Er bildet keine vollständigen C2-Implantate, mehrstufige Schadsoftware, produktive Benutzeraktivität oder reale Klassenprävalenz ab.

Daher werden Ergebnisse für den untersuchten Labordatensatz berichtet. Aussagen über Produktivsysteme oder allgemeine C2-Erkennung benötigen einen unabhängigen externen Datensatz mit realen, fachlich geprüften Event-4104-Aufzeichnungen.

## Reproduzierbarkeit

Der Datensatz lässt sich mit festem Seed reproduzieren:

~~~bash
python3 artifacts/source/generate_dataset.py \
  --benign-source artifacts/dataset/benign_source_samples.json \
  --out /tmp/powershell_scriptblock_samples.json \
  --manifest-out /tmp/source_manifest.json \
  --summary-out /tmp/dataset_summary.json
~~~

Erwartete SHA-256-Prüfsumme des Datensatzes:

~~~text
12f6aa415bb8fe96b50f854c8590e98769ece2c2cbd3775118294e32b58c4ae3
~~~
