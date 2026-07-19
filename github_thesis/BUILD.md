# Reproduktion und PDF-Kompilation

Alle relativen Pfade beziehen sich auf das Wurzelverzeichnis dieses Repositorys. Die eingefrorenen Dateien unter <code>artifacts/messlauf/</code> dokumentieren den berichteten Messlauf vom 17.07.2026. Kontrollläufe sollen getrennte Ausgabeverzeichnisse verwenden.

Die simulierten positiven Testfälle dürfen ausschließlich in der beschriebenen Laborumgebung ausgeführt werden.

## 1. Voraussetzungen

- Windows 11 und Windows PowerShell 5.1
- administrativer Zugriff zur Aktivierung von ScriptBlock-Logging
- Wazuh-Agent 4.14.4 auf Windows
- Wazuh-Manager 4.14.5-rc1 unter WSL Kali
- Python 3.13.12
- NumPy 2.3.5, SciPy 1.16.3 und Matplotlib 3.10.7
- MiKTeX oder TeX Live mit pdfLaTeX und deutschem Babel-Modul

Python-Abhängigkeiten:

~~~bash
python3 -m pip install -r requirements.txt
~~~

## 2. Eingefrorene Artefakte prüfen

~~~bash
python3 -m unittest \
  artifacts/source/test_pipeline.py \
  scripts/test_additional_analyses.py \
  artifacts/source/test_wazuh_capture.py

python3 scripts/verify_repository.py
~~~

Erwartet werden 20 erfolgreiche Unit-Tests. Die Repository-Prüfung kontrolliert Datensatz- und Exportprüfsummen, 300 direkte Event-4104-Texte, 300 Managerbelege, 88 Regelalarme, alle Konfusionsmatrizen und sämtliche Abbildungsverweise.

## 3. Datensatz reproduzieren

Der veröffentlichte Datensatz wird nicht überschrieben. Die Kontrollausgabe landet in einem temporären Verzeichnis:

~~~bash
mkdir -p /tmp/powershell_dataset_check

python3 artifacts/source/generate_dataset.py \
  --benign-source artifacts/dataset/benign_source_samples.json \
  --out /tmp/powershell_dataset_check/powershell_scriptblock_samples.json \
  --manifest-out /tmp/powershell_dataset_check/source_manifest.json \
  --summary-out /tmp/powershell_dataset_check/dataset_summary.json

sha256sum \
  artifacts/dataset/powershell_scriptblock_samples.json \
  /tmp/powershell_dataset_check/powershell_scriptblock_samples.json
~~~

Beide Datensatzprüfsummen müssen <code>12f6aa415bb8fe96b50f854c8590e98769ece2c2cbd3775118294e32b58c4ae3</code> lauten.

## 4. ScriptBlock-Logging und Wazuh konfigurieren

ScriptBlock-Logging wird in einer administrativen Windows-PowerShell aktiviert:

~~~powershell
New-Item `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Force

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name EnableScriptBlockLogging -Value 1 -Type DWord
~~~

Der Windows-Agent liest den PowerShell-Ereigniskanal mit folgendem Abschnitt in <code>ossec.conf</code>:

~~~xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
~~~

Für den managerseitigen Empfangsnachweis muss die JSON-Archivierung aktiviert sein:

~~~xml
<logall_json>yes</logall_json>
~~~

Danach werden Agent und Manager neu gestartet und ihr aktiver Zustand geprüft.

## 5. Messfenster öffnen

Auf dem Wazuh-Manager werden vor dem Lauf die Zeilenstände des Archivs und des Alarmprotokolls erfasst:

~~~bash
sudo python3 artifacts/source/capture_wazuh_offsets.py \
  --output artifacts/messlauf/capture_start.json
~~~

Anschließend startet auf Windows der direkte Kollektor. Er liest Event-ID 4104 unmittelbar aus <code>Microsoft-Windows-PowerShell/Operational</code> und bleibt aktiv, bis alle 300 IDs vorliegen:

~~~powershell
py -3 artifacts/source/pipeline.py collect-event4104 `
  --dataset artifacts/dataset/powershell_scriptblock_samples.json `
  --event-output artifacts/messlauf/local_event4104_dataset_run.jsonl `
  --summary-output artifacts/messlauf/event4104_capture_summary.json `
  --ready-file artifacts/messlauf/event4104_capture_ready.json
~~~

## 6. Testfälle kontrolliert ausführen

Nach Erzeugung der Bereitschaftsdatei wird in einer zweiten administrativen Windows-PowerShell ausgeführt:

~~~powershell
powershell -ExecutionPolicy Bypass `
  -File artifacts/source/run_dataset_samples.ps1 `
  -DatasetPath artifacts/dataset/powershell_scriptblock_samples.json `
  -ExecutionLogPath artifacts/messlauf/execution_log.csv `
  -DelayMs 300 -IUnderstandThisIsALab
~~~

Das PowerShell-Skript führt vor jedem Testfall eine AST-Sicherheitsprüfung durch. Positive Fälle dürfen nur <code>Write-Output</code> aufrufen.

## 7. Wazuh-Empfang und Standardregel-Alarme exportieren

Der Export berücksichtigt ausschließlich Zeilen, die nach dem gespeicherten Startpunkt hinzugekommen sind:

~~~bash
sudo python3 artifacts/source/export_wazuh_capture.py \
  --capture-start artifacts/messlauf/capture_start.json \
  --dataset artifacts/dataset/powershell_scriptblock_samples.json \
  --output-dir artifacts/messlauf/capture \
  --agent-name Windows-Host --event-id 4104
~~~

Der Empfangsnachweis wird getrennt geprüft:

~~~bash
python3 artifacts/source/verify_manager_receipts.py \
  --dataset artifacts/dataset/powershell_scriptblock_samples.json \
  --receipts artifacts/messlauf/capture/manager_event4104_receipts.jsonl \
  --output-summary artifacts/messlauf/analysis/manager_receipt_summary.json \
  --output-mapping artifacts/messlauf/analysis/manager_receipt_mapping.csv \
  --agent-name Windows-Host --event-id 4104
~~~

Der Managerexport dient nur als Transportnachweis. Die lexikalischen Verfahren lesen ausschließlich den direkten lokalen Event-4104-Export.

## 8. Methoden auswerten

Punktemodell, Wazuh-Referenz und binäre Verknüpfungen:

~~~bash
python3 artifacts/source/pipeline.py run \
  --dataset artifacts/dataset/powershell_scriptblock_samples.json \
  --event-channel-events artifacts/messlauf/local_event4104_dataset_run.jsonl \
  --alerts artifacts/messlauf/capture/alerts_standard_rules_dataset_run.jsonl \
  --out-dir artifacts/reproduced_analysis \
  --evaluation-mode grouped_cv --folds 5 --seed 20260711 \
  --bootstrap-iterations 2000 --max-fpr 0.10 \
  --agent-name Windows-Host --event-id 4104
~~~

Statistische Zeichen-n-Gramm-TF-IDF-Vergleichsbasis:

~~~bash
mkdir -p reproduced_figures

python3 scripts/additional_analyses.py \
  --sample-results artifacts/reproduced_analysis/sample_results.csv \
  --overall-metrics artifacts/reproduced_analysis/metrics_overall.csv \
  --output-dir artifacts/reproduced_analysis \
  --figure-output reproduced_figures/baseline_comparison.pdf
~~~

Isolierte Laufzeitmessung des Punktemodells:

~~~bash
python3 scripts/benchmark_pipeline.py \
  --pipeline artifacts/source/pipeline.py \
  --sample-results artifacts/messlauf/analysis/sample_results.csv \
  --output-csv artifacts/reproduced_analysis/lexical_runtime_benchmark.csv \
  --output-json artifacts/reproduced_analysis/lexical_runtime_benchmark.json \
  --figure-output reproduced_figures/lexical_runtime.pdf \
  --operation-counts 300 1500 3000
~~~

## 9. Vektorgrafiken erzeugen

Die in der PDF verwendeten Diagramme werden aus den eingefrorenen Messergebnissen erzeugt:

~~~bash
python3 scripts/generate_figures.py \
  --analysis-dir artifacts/messlauf/analysis \
  --out-dir figures
~~~

<code>baseline_comparison.pdf</code> und <code>lexical_runtime.pdf</code> entstehen durch die in Abschnitt 8 genannten Programme.

## 10. PDF kompilieren

Bevorzugt:

~~~bash
latexmk -pdf -file-line-error -interaction=nonstopmode \
  -halt-on-error Bachelorarbeit_Rashed_Alsuhaibi.tex
~~~

Alternativ:

~~~bash
pdflatex -file-line-error -interaction=nonstopmode -halt-on-error \
  Bachelorarbeit_Rashed_Alsuhaibi.tex
pdflatex -file-line-error -interaction=nonstopmode -halt-on-error \
  Bachelorarbeit_Rashed_Alsuhaibi.tex
pdflatex -file-line-error -interaction=nonstopmode -halt-on-error \
  Bachelorarbeit_Rashed_Alsuhaibi.tex
~~~

Die erzeugte Datei heißt <code>Bachelorarbeit_Rashed_Alsuhaibi.pdf</code>. Danach werden Warnungen, Abbildungsverweise, Tabellenränder, Seitenzahlen und Lesbarkeit der Screenshots geprüft.
