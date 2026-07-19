# Leitfaden für die sechs Nachweis-Screenshots

Die sechs verwendeten PNG-Dateien liegen unter `figures/screenshots/`. Dieser Leitfaden dokumentiert, wie sie bei Bedarf erneut aufgenommen werden. Verwende echte Aufnahmen der Laborumgebung mit mindestens 1600 Pixel Breite. Schneide sie auf den relevanten Inhalt zu und verdecke Zugangsdaten sowie nicht benötigte personenbezogene Daten.

## 1. Aktiviertes ScriptBlock-Logging

**Dateiname:** `scriptblock_logging_registry.png`

Öffne PowerShell als Administrator und führe aus:

```powershell
Get-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name EnableScriptBlockLogging |
  Format-List PSPath, EnableScriptBlockLogging
```

Sichtbar sein müssen der vollständige Registry-Pfad und `EnableScriptBlockLogging : 1`.

## 2. Event-ID 4104 mit Testfall-ID

**Dateiname:** `event_4104_sample_marker.png`

1. Öffne `eventvwr.msc`.
2. Navigiere zu `Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational`.
3. Filtere auf Event-ID `4104` und suche im Ereignistext nach `PST-034`.
4. Zeige Event-ID, Testfall-ID und einen lesbaren Ausschnitt von `ScriptBlockText`.

## 3. Aktiver Wazuh-Agent

**Dateiname:** `wazuh_agent_active.png`

Öffne die Agentenübersicht im Wazuh Dashboard. Sichtbar sein müssen Agent-ID `001`, Name `Windows-Host`, Status `Active` und Version `4.14.4`.

Alternativ eignet sich die echte Terminalausgabe:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

## 4. Zugeordnete Wazuh-Alarmmeldung

**Dateiname:** `wazuh_alert_sample.png`

1. Öffne `Threat Hunting` beziehungsweise `Security Events`.
2. Stelle den Zeitraum des Laufs vom 17.07.2026 zwischen 11:35 und 11:38 Uhr lokaler Zeit ein.
3. Filtere nach Agent `Windows-Host`, Event-ID `4104` und Testfall-ID `PST-034`.
4. Zeige Zeitstempel, `agent.name`, `rule.id`, `rule.description`, Event-ID und `ScriptBlockText`. Für `PST-034` ist Regel `91809` zu erwarten.

## 5. JSONL-Alarmexport

**Dateiname:** `wazuh_jsonl_sample.png`

Führe im Projektordner aus:

```bash
grep -m 1 'PST-034' \
  artifacts/messlauf/capture/alerts_standard_rules_dataset_run.jsonl \
  | jq '{timestamp, agent, rule,
         eventID: .data.win.system.eventID,
         scriptBlockText: (.data.win.eventdata.scriptBlockText[0:300])}'
```

Der Terminalausschnitt soll Zeitstempel, Agent, Regel-ID, Event-ID und Testfall-ID zeigen. Die Vektorgrafik `figures/windows_event_channel_evidence.pdf` wird separat aus dem direkten Windows-Export erzeugt und benötigt keinen Screenshot.

## 6. Abgeschlossener Pipeline-Lauf

**Dateiname:** `pipeline_terminal_summary.png`

Führe im Projektordner aus:

```bash
python3 artifacts/source/pipeline.py run \
  --dataset artifacts/dataset/powershell_scriptblock_samples.json \
  --event-channel-events artifacts/messlauf/local_event4104_dataset_run.jsonl \
  --alerts artifacts/messlauf/capture/alerts_standard_rules_dataset_run.jsonl \
  --out-dir artifacts/reproduced_analysis \
  --evaluation-mode grouped_cv --folds 5 --seed 20260711 \
  --bootstrap-iterations 2000 --max-fpr 0.10 \
  --agent-name Windows-Host --event-id 4104
```

Sichtbar sein sollen `sample_count: 300`, `mapped_alert_count: 88`, `mapped_sample_count: 300`, `deployment_threshold_full_dataset: 5`, die fünf Teilstichprobenschwellenwerte und

```text
lexical_input_source:
Microsoft-Windows-PowerShell/Operational:4104/EventData/ScriptBlockText
```

## Abschlusskontrolle

1. Lege alle sechs PNG-Dateien unter `figures/screenshots/` ab.
2. Kompiliere gemäß `BUILD.md` dreimal.
3. Prüfe, dass kein Platzhalterkasten verbleibt und alle Bilder lesbar sowie unverzerrt sind.
4. Prüfe Abbildungsverzeichnis, Seitenumbrüche und Datenschutz.
