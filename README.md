# Hostbasierte Erkennung obfuskierter PowerShell-Aktivität

Dieses Repository enthält die Bachelorarbeit, den synthetischen Labordatensatz, die Auswertungspipeline, die aufgezeichneten Event-4104- und Wazuh-Artefakte sowie alle Tabellen- und Abbildungsdaten des Messlaufs.

## Untersuchungsgegenstand

Die Arbeit vergleicht drei Entscheidungen auf denselben 300 PowerShell-ScriptBlocks:

1. unveränderte Wazuh-Standardregeln,
2. ein erklärbares lexikalisches Punktemodell,
3. eine statistische Vergleichsbasis aus Zeichen-n-Gramm-TF-IDF und logistischer Regression.

Die beiden lexikalischen Verfahren lesen <code>ScriptBlockText</code> direkt aus Event-ID 4104 des Kanals <code>Microsoft-Windows-PowerShell/Operational</code>. Das Wazuh-Archiv dient ausschließlich als Nachweis, dass auch Testfälle ohne Alarm den Manager erreicht haben. Es ist keine Eingabe der lexikalischen Verfahren.

## Datensatz und Sicherheitsgrenze

Der Datensatz wurde im Rahmen der Arbeit erzeugt und geprüft:

- 150 lokal zusammengestellte benigne Testfälle,
- 30 im Generator definierte positive Grundmuster,
- eine klare Variante und vier obfuskierte Varianten je positivem Grundmuster,
- insgesamt 150 simulierte Testfälle mit Angriffsindikatoren.

MITRE ATT&CK, Atomic Red Team, Sigma, LOLBAS, Wazuh und Invoke-Obfuscation dienen als fachliche Referenzen. Es wurden keine vollständigen C2-Implantate oder Nutzlastdateien aus diesen Quellen importiert. Positive Testfälle rekonstruieren oder dekodieren ausschließlich inerte Texte. Sie stellen keine tatsächlich ausgeführte Schadsoftware dar.

## Zentrale Ergebnisse

| Verfahren | Precision | Recall | F1-Score | FPR |
|---|---:|---:|---:|---:|
| Wazuh-Standardregeln | 0,6136 | 0,3600 | 0,4538 | 0,2267 |
| Lexikalisches Punktemodell | 0,8760 | 0,7533 | 0,8100 | 0,1067 |
| Zeichen-n-Gramm-TF-IDF | 0,9060 | 0,9000 | 0,9030 | 0,0933 |

Diese Werte gelten nur für den beschriebenen, ausgeglichenen Labordatensatz. Sie belegen keine Erkennungsleistung gegenüber realen C2-Implantaten oder in Produktivumgebungen.

## Verzeichnisstruktur

~~~text
.
├── Bachelorarbeit_Rashed_Alsuhaibi.tex
├── Bachelorarbeit_Rashed_Alsuhaibi.pdf
├── artifacts/
│   ├── dataset/          Datensatz, Quellenmanifest und Zusammenfassung
│   ├── messlauf/         Event-4104-, Wazuh- und Ergebnisartefakte
│   └── source/           Pipeline, Datensatzgenerator, Exporter und Tests
├── figures/
│   ├── screenshots/      Reale Nachweisaufnahmen der Laborumgebung
│   └── *.pdf             Ergebnisdiagramme und geprüfte Methodendiagramme
├── scripts/              Zusatzanalyse, Laufzeitmessung, Abbildungen und Prüfung
└── requirements.txt      Festgeschriebene Python-Abhängigkeiten
~~~

## Schnellprüfung

Voraussetzung ist Python 3.13. Im Projektverzeichnis:

~~~bash
python3 -m pip install -r requirements.txt
python3 -m unittest \
  artifacts/source/test_pipeline.py \
  scripts/test_additional_analyses.py \
  artifacts/source/test_wazuh_capture.py
python3 scripts/verify_repository.py
~~~

Erwartet werden 20 erfolgreiche Unit-Tests und eine vollständig erfolgreiche Repository-Prüfung.

## Berechnungen aus den aufgezeichneten Ereignissen wiederholen

Die veröffentlichten Messartefakte unter <code>artifacts/messlauf/analysis/</code> bleiben unverändert. Für einen Kontrolllauf wird ein getrenntes Ergebnisverzeichnis verwendet:

~~~bash
python3 artifacts/source/pipeline.py run \
  --dataset artifacts/dataset/powershell_scriptblock_samples.json \
  --event-channel-events artifacts/messlauf/local_event4104_dataset_run.jsonl \
  --alerts artifacts/messlauf/capture/alerts_standard_rules_dataset_run.jsonl \
  --out-dir artifacts/reproduced_analysis \
  --evaluation-mode grouped_cv --folds 5 --seed 20260711 \
  --bootstrap-iterations 2000 --max-fpr 0.10 \
  --agent-name Windows-Host --event-id 4104

python3 scripts/additional_analyses.py \
  --sample-results artifacts/reproduced_analysis/sample_results.csv \
  --overall-metrics artifacts/reproduced_analysis/metrics_overall.csv \
  --output-dir artifacts/reproduced_analysis \
  --figure-output reproduced_figures/baseline_comparison.pdf
~~~

Die vier Methodendiagramme `lab_architecture.pdf`, `dataset_construction.pdf`, `experiment_flow.pdf` und `windows_event_channel_evidence.pdf` sind als geprüfte statische Vektorgrafiken versioniert. Das Abbildungsskript erzeugt ausschließlich die datenabhängigen Ergebnisdiagramme und überschreibt diese vier Dateien nicht.

## PDF erstellen

Mit MiKTeX oder TeX Live:

~~~bash
latexmk -pdf -file-line-error -interaction=nonstopmode \
  -halt-on-error Bachelorarbeit_Rashed_Alsuhaibi.tex
~~~

Alternativ kann <code>pdflatex</code> dreimal ausgeführt werden. Die Abbildungen liegen bereits in den benötigten relativen Pfaden.

## Verantwortungsvolle Nutzung

Die enthaltenen Testfälle sind für die dokumentierte, isolierte Laborumgebung vorgesehen. Das Repository enthält keine vollständigen realen C2-Nutzlasten. Eine Erweiterung mit realer Schadsoftware oder produktiven Protokolldaten gehört nicht zum reproduzierten Messlauf und erfordert eine eigene rechtliche, ethische und technische Prüfung.
