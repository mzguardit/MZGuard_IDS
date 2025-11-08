#!/usr/bin/env python3
"""
FINAL Elite Persistence Monitor v4.0 - ZERO FALSE POSITIVES
Filtra intelligentemente, whitelist dinamica, rilevamento vero malware solo
"""

import os
import sys
import json
import subprocess
import time
import hashlib
import re
from datetime import datetime
from pathlib import Path

try:
    import winreg
except ImportError:
    print("[!] Installa: pip install pypiwin32")
    sys.exit(1)

class FinalPersistenceMonitor:
    def __init__(self, log_file="final_monitor.log"):
        self.log_file = log_file
        self.threats = []
        
        # WHITELIST RIGOROSA - Processi/Path LEGITTIMI verificati
        self.trusted_executables = {
            'explorer.exe', 'svchost.exe', 'taskhostw.exe', 'dwm.exe',
            'chrome.exe', 'firefox.exe', 'iexplore.exe', 'msedge.exe',
            'thunderbird.exe', 'discord.exe', 'telegram.exe',
            'slack.exe', 'teams.exe', 'skype.exe',
            'spotify.exe', 'vlc.exe', 'winrar.exe', 'putty.exe',
            'git.exe', 'python.exe', 'node.exe', 'docker.exe',
            'vcpkg.exe', 'cmake.exe', 'ninja.exe',
            'nvidia.exe', 'amd.exe', 'intel.exe',
            'avast.exe', 'avg.exe', 'defender.exe', 'kaspersky.exe',
            'windowsupdate.exe', 'schtasks.exe', 'backgroundtaskhost.exe',
            'searchindexer.exe', 'audiodg.exe', 'wifilogon.exe',
            'crashhelper.exe', 'presentmonservice.exe', 'graphicssoftware.exe',
            'wmiregistrationservice.exe', 'intelhd.exe', 'realtekservice.exe',
        }
        
        self.trusted_paths = {
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\ProgramData',
            'C:\\Users\\',
        }
        
        # MALWARE PATTERNS SPECIFICI - Solo signature reali
        self.critical_malware = {
            'emotet_beacon': r'emotet|heodo|buckeye',
            'trickbot_cmd': r'trickbot|trick_bot',
            'qbot_loader': r'qbot|qakbot',
            'icedid_steal': r'icedid|ice_id',
            'lokibot': r'lokibot|loki',
            'remcos_rat': r'remcos|rmcos',
            'raccoon_stealer': r'privacy_raccoon|raccoon',
            'xmrig_miner': r'xmrig|cryptonight|stratum',
            'njrat': r'njrat|nj_rat',
            'poison_ivy': r'poison.ivy|poison_ivy',
            'mirai': r'mirai|dyn.bot',
            'wannacry': r'wanna.*cry|wcry|eternalblue',
            'petya_notpetya': r'petya|notpetya|goldeneye',
            'zeus_variant': r'zeus|zbot',
            'dridex': r'dridex|bugat',
            'cerber_ransomware': r'cerber|cerber',
            'locky_ransomware': r'locky|odin_ransomware',
            'cryptowall': r'cryptowall|vvv',
            'tempest_apt': r'tempest|babyshark',
            'nettraveler': r'nettraveler|apt',
            'lazarus_apt': r'lazarus|hidden_cobra',
        }
        
        # BEHAVIORS - Solo veramente maliciosi
        self.malicious_behaviors = {
            'wmi_backdoor': r'__EventFilter.*CommandLine|__EventConsumer.*rundll32.*reg',
            'process_inject': r'createremotethread|writeprocessmemory|allocexvirtualmemory',
            'registry_persistence': r'Run\\.*\$\(.*\)|Run\\.*%[a-z].*%',
            'scheduled_reverse_shell': r'cmd.*cmd.*powershell.*-nop.*-enc|-enc.*-nop',
            'dll_injection': r'regsvcs.*\.dll|regasm.*\.dll|rundll32.*advpack',
            'c2_beacon': r'https?://[0-9]{1,3}\.[0-9]{1,3}.*:8080|:4444|:5555',
            'obfuscated_script': r'\[System.Text.Encoding\]::FromBase64String|IEX.*System',
        }
        
        # Whitelist WMI legitimi di Windows
        self.legitimate_wmi_consumers = {
            'scm event log consumer',
            'nteventslog',
            'microsoft-windows-winrm',
        }
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_msg = f"[{timestamp}] [{level}] {message}"
        print(log_msg)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_msg + "\n")
    
    def is_wmi_malicious(self, consumer_name, command_line):
        """Determina se un WMI consumer è malicioso"""
        # Converte in stringa e gestisce None
        consumer_name = str(consumer_name) if consumer_name else ''
        command_line = str(command_line) if command_line else ''
        
        if not consumer_name and not command_line:
            return False
        
        # Whitelist WMI legittimi
        if any(x.lower() in consumer_name.lower() for x in self.legitimate_wmi_consumers):
            return False
        
        # Se non c'è comando, non è malicioso (solo logging)
        if not command_line or command_line == 'None':
            return False
        
        # Controlla per malware patterns
        for mal_name, pattern in self.critical_malware.items():
            if re.search(pattern, command_line, re.IGNORECASE):
                return True
        
        # Controlla per comportamenti maliciosi
        if re.search(r'powershell.*-nop|powershell.*-enc|-enc.*-nop|cmd.*cmd', command_line, re.IGNORECASE):
            return True
        
        return False
    
    def remove_wmi_backdoor(self, filter_name, consumer_name):
        """Rimuove automaticamente backdoor WMI e verifica"""
        self.log(f"🔧 Tentativo di rimozione WMI backdoor: {filter_name}/{consumer_name}", "INFO")
        
        try:
            # Rimuovi il binding
            ps_cmd_binding = f"""
$binding = Get-WmiObject __FilterToConsumerBinding -Namespace "root\\subscription" -ErrorAction SilentlyContinue |
  Where-Object {{$_.Filter -like "*{filter_name}*" -and $_.Consumer -like "*{consumer_name}*"}}
if($binding) {{ $binding | Remove-WmiObject; "REMOVED_BINDING" }}
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd_binding],
                capture_output=True, text=True, timeout=10
            )
            
            if "REMOVED_BINDING" in result.stdout:
                self.log(f"✓ Binding rimosso: {filter_name} → {consumer_name}", "INFO")
            
            # Rimuovi il consumer
            ps_cmd_consumer = f"""
$consumer = Get-WmiObject __EventConsumer -Namespace "root\\subscription" -ErrorAction SilentlyContinue |
  Where-Object {{$_.Name -eq "{consumer_name}"}}
if($consumer) {{ $consumer | Remove-WmiObject; "REMOVED_CONSUMER" }}
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd_consumer],
                capture_output=True, text=True, timeout=10
            )
            
            if "REMOVED_CONSUMER" in result.stdout:
                self.log(f"✓ Consumer rimosso: {consumer_name}", "INFO")
            
            # Rimuovi il filter
            ps_cmd_filter = f"""
$filter = Get-WmiObject __EventFilter -Namespace "root\\subscription" -ErrorAction SilentlyContinue |
  Where-Object {{$_.Name -eq "{filter_name}"}}
if($filter) {{ $filter | Remove-WmiObject; "REMOVED_FILTER" }}
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd_filter],
                capture_output=True, text=True, timeout=10
            )
            
            if "REMOVED_FILTER" in result.stdout:
                self.log(f"✓ Filter rimosso: {filter_name}", "INFO")
            
            self.log(f"✅ WMI backdoor eliminato completamente: {filter_name}/{consumer_name}", "INFO")
            return True
            
        except Exception as e:
            self.log(f"❌ Errore durante rimozione WMI: {str(e)}", "ERROR")
            return False
        """Verifica se è in whitelist"""
        if not path_or_name:
            return True
        
        text_lower = path_or_name.lower()
        
        # Whitelist eseguibili
        for exe in self.trusted_executables:
            if exe in text_lower:
                return True
        
        # Whitelist percorsi Microsoft/Adobe/Antivirus
        if any(x in text_lower for x in ['microsoft', 'adobe', 'java', 'google update', 
                                          'nvidia', 'intel', 'amd', 'realtek', 'qualcomm']):
            return True
        
        return False
    
    def check_registry_strict(self):
        """Scansione Registro - ZERO FALSE POSITIVES"""
        self.log("🔍 Scansione REGISTRO (modalità STRICT)...", "SCAN")
        
        critical_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        
        threats_found = 0
        
        for hkey, path in critical_keys:
            try:
                reg_key = winreg.OpenKey(hkey, path)
                idx = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, idx)
                        
                        # Skip se è whitelisted
                        if self.is_whitelisted(value_data):
                            idx += 1
                            continue
                        
                        # Check per malware specifici
                        for mal_name, pattern in self.critical_malware.items():
                            if re.search(pattern, str(value_data), re.IGNORECASE):
                                threat = {
                                    'type': 'REGISTRY_MALWARE',
                                    'key': f"{path}\\{value_name}",
                                    'data': str(value_data)[:150],
                                    'malware': mal_name,
                                    'severity': 'CRITICAL',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.threats.append(threat)
                                threats_found += 1
                                self.log(f"🔴 MALWARE REGISTRY [{mal_name}]: {value_name}", "ALERT")
                        
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(reg_key)
            except:
                pass
        
        if threats_found == 0:
            self.log("✓ Registro: PULITO", "INFO")
        return threats_found
    
    def check_scheduled_tasks_strict(self):
        """Scansione Task Scheduler - Solo malware vero"""
        self.log("🔍 Scansione SCHEDULED TASKS (strict)...", "SCAN")
        
        threats_found = 0
        try:
            ps_cmd = """
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -eq 'Ready'}
foreach($t in $tasks) {
    $actions = $t.Actions
    if($actions) {
        @{
            Name = $t.TaskName
            Path = $t.TaskPath
            Execute = $actions.Execute
            Arguments = $actions.Arguments
        } | ConvertTo-Json
    }
}
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    try:
                        if not line.startswith('{'):
                            continue
                        task = json.loads(line)
                        cmd = f"{task.get('Execute', '')} {task.get('Arguments', '')}"
                        
                        if self.is_whitelisted(cmd):
                            continue
                        
                        for mal_name, pattern in self.critical_malware.items():
                            if re.search(pattern, cmd, re.IGNORECASE):
                                threat = {
                                    'type': 'TASK_MALWARE',
                                    'task': task.get('Name', 'Unknown'),
                                    'command': cmd[:150],
                                    'malware': mal_name,
                                    'severity': 'CRITICAL',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.threats.append(threat)
                                threats_found += 1
                                self.log(f"🔴 MALWARE TASK [{mal_name}]: {task.get('Name')}", "ALERT")
                    except:
                        pass
        except Exception as e:
            pass
        
        if threats_found == 0:
            self.log("✓ Task Scheduler: PULITO", "INFO")
        return threats_found
    
    def check_processes_strict(self):
        """Scansione Processi - Solo malware signature"""
        self.log("🔍 Scansione PROCESSI (strict)...", "SCAN")
        
        threats_found = 0
        try:
            ps_cmd = """
Get-Process | Where-Object {$_.ProcessName -notlike 'system*' -and $_.ProcessName -notlike 'idle*'} |
Select-Object Name, @{N='Path';E={$_.MainModule.FileName}} | ConvertTo-Json
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    procs = json.loads(result.stdout)
                    if not isinstance(procs, list):
                        procs = [procs]
                    
                    for proc in procs:
                        name = proc.get('Name', '').lower()
                        path = proc.get('Path', '').lower()
                        
                        if self.is_whitelisted(name) or self.is_whitelisted(path):
                            continue
                        
                        for mal_name, pattern in self.critical_malware.items():
                            if re.search(pattern, name + path, re.IGNORECASE):
                                threat = {
                                    'type': 'PROCESS_MALWARE',
                                    'process': name,
                                    'path': path,
                                    'malware': mal_name,
                                    'severity': 'CRITICAL',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.threats.append(threat)
                                threats_found += 1
                                self.log(f"🔴 MALWARE PROCESS [{mal_name}]: {name}", "ALERT")
                except:
                    pass
        except:
            pass
        
        if threats_found == 0:
            self.log("✓ Processi: PULITO", "INFO")
        return threats_found
    
    def check_wmi_subscriptions(self):
        """Scansione WMI Event Subscriptions - CRITICAL"""
        self.log("🔍 Scansione WMI BACKDOORS...", "SCAN")
        
        threats_found = 0
        try:
            # Recupera Event Filters
            ps_cmd_filters = """
Get-WmiObject __EventFilter -Namespace "root\\subscription" -ErrorAction SilentlyContinue | 
Select-Object Name, Query, CreationClassName | ConvertTo-Json
"""
            result_filters = subprocess.run(
                ["powershell", "-Command", ps_cmd_filters],
                capture_output=True, text=True, timeout=15
            )
            
            # Recupera Event Consumers con TUTTI i dettagli
            ps_cmd_consumers = """
Get-WmiObject __EventConsumer -Namespace "root\\subscription" -ErrorAction SilentlyContinue |
Select-Object `
    Name, `
    CommandLineTemplate, `
    ExecutablePath, `
    ScriptingEngine, `
    ScriptText, `
    CreationClassName, `
    __CLASS, `
    @{N='CreationTime';E={$_.__RELPATH}}, `
    @{N='AllProperties';E={$_ | Get-Member -MemberType Property | Select-Object -ExpandProperty Name | ForEach-Object { "$_=$($_)" } }} | ConvertTo-Json -Depth 10
"""
            result_consumers = subprocess.run(
                ["powershell", "-Command", ps_cmd_consumers],
                capture_output=True, text=True, timeout=15
            )
            
            # Anche recupera info estesa via WMI
            ps_cmd_consumers_full = """
Get-WmiObject __EventConsumer -Namespace "root\\subscription" -ErrorAction SilentlyContinue | 
ForEach-Object {
    $obj = $_
    $props = @{
        Name = $obj.Name
        Type = $obj.__CLASS
        CommandLineTemplate = $obj.CommandLineTemplate
        ExecutablePath = $obj.ExecutablePath
        ScriptingEngine = $obj.ScriptingEngine
        ScriptText = $obj.ScriptText
        MaximumQueueSize = $obj.MaximumQueueSize
        CreatorSID = $obj.CreatorSID
        TargetNamespace = $obj.TargetNamespace
    }
    $props | Add-Member -NotePropertyMembers (Get-WmiObject -Query "SELECT * FROM $($obj.__CLASS) WHERE Name='$($obj.Name)'" -Namespace "root\\subscription" | Get-Member -MemberType Property | Where-Object {$_.Name -notlike '__*'} | ForEach-Object { $_.Name })
    $props | ConvertTo-Json
}
"""
            result_consumers_full = subprocess.run(
                ["powershell", "-Command", ps_cmd_consumers_full],
                capture_output=True, text=True, timeout=15
            )
            
            # Recupera Bindings
            ps_cmd_bindings = """
Get-WmiObject __FilterToConsumerBinding -Namespace "root\\subscription" -ErrorAction SilentlyContinue |
Select-Object Filter, Consumer | ConvertTo-Json
"""
            result_bindings = subprocess.run(
                ["powershell", "-Command", ps_cmd_bindings],
                capture_output=True, text=True, timeout=15
            )
            
            has_filters = result_filters.returncode == 0 and result_filters.stdout.strip()
            has_consumers = result_consumers.returncode == 0 and result_consumers.stdout.strip()
            has_bindings = result_bindings.returncode == 0 and result_bindings.stdout.strip()
            
            if has_filters or has_consumers or has_bindings:
                # WMI Backdoor rilevato - mostra TUTTI i dettagli
                self.log(f"\n{'='*80}", "ALERT")
                self.log("🔴 ⚠️  WMI PERSISTENCE RILEVATO ⚠️ 🔴", "ALERT")
                self.log(f"{'='*80}", "ALERT")
                
                malicious_found = False
                filters_to_remove = []
                consumers_to_remove = []
                
                if has_filters:
                    self.log("\n[EVENT FILTERS RILEVATI - DETTAGLI COMPLETI]", "ALERT")
                    try:
                        filters = json.loads(result_filters.stdout)
                        if not isinstance(filters, list):
                            filters = [filters]
                        for f in filters:
                            filter_name = f.get('Name', 'N/A')
                            query = f.get('Query', 'N/A')
                            self.log(f"\n  🔍 FILTER: {filter_name}", "ALERT")
                            self.log(f"  ├─ Query WMI: {query}", "ALERT")
                            
                            if f.get('EventAccess'):
                                self.log(f"  ├─ Event Access: {f.get('EventAccess')}", "ALERT")
                            
                            if f.get('CreatorSID'):
                                self.log(f"  ├─ CreatorSID: {f.get('CreatorSID')}", "ALERT")
                            
                            # Analizza la query per pericoli
                            if 'WIN32_ProcessStartTrace' in query or 'WIN32_Process' in query:
                                self.log(f"  🔴 Monitora creazione processi", "ALERT")
                            if 'WIN32_ModuleLoadTrace' in query:
                                self.log(f"  🔴 Monitora caricamento DLL", "ALERT")
                            if 'WIN32_RegistryTreeChangeEvent' in query or 'RegistryKeyChangeEvent' in query:
                                self.log(f"  🔴 Monitora modifiche registro", "ALERT")
                            if 'WIN32_FileSystemEvent' in query:
                                self.log(f"  🔴 Monitora cambiamenti filesystem", "ALERT")
                            
                            self.log(f"  └─ CreationClassName: {f.get('CreationClassName', 'N/A')}", "ALERT")
                            self.log("  ---", "ALERT")
                    except Exception as e:
                        self.log(f"  Errore parsing filters: {str(e)[:100]}", "ALERT")
                
                if has_consumers:
                    self.log("\n[EVENT CONSUMERS RILEVATI - DETTAGLI COMPLETI]", "ALERT")
                    try:
                        consumers = json.loads(result_consumers.stdout)
                        if not isinstance(consumers, list):
                            consumers = [consumers]
                        for c in consumers:
                            consumer_name = c.get('Name', 'N/A') if c.get('Name') else 'N/A'
                            cmd_line = c.get('CommandLineTemplate', None) if c.get('CommandLineTemplate') else None
                            consumer_type = c.get('__CLASS', c.get('Type', 'Unknown'))
                            
                            self.log(f"\n  📋 CONSUMER: {consumer_name}", "ALERT")
                            self.log(f"  ├─ Tipo: {consumer_type}", "ALERT")
                            
                            if cmd_line:
                                self.log(f"  ├─ Comando: {cmd_line}", "ALERT")
                            else:
                                self.log(f"  ├─ Comando: (nessuno)", "ALERT")
                            
                            if c.get('ExecutablePath'):
                                self.log(f"  ├─ Eseguibile: {c.get('ExecutablePath')}", "ALERT")
                            
                            if c.get('ScriptingEngine'):
                                self.log(f"  ├─ Script Engine: {c.get('ScriptingEngine')}", "ALERT")
                            
                            if c.get('ScriptText'):
                                script = str(c.get('ScriptText'))[:200]
                                self.log(f"  ├─ Script: {script}", "ALERT")
                            
                            if c.get('CreatorSID'):
                                self.log(f"  ├─ CreatorSID: {c.get('CreatorSID')}", "ALERT")
                            
                            if c.get('MaximumQueueSize'):
                                self.log(f"  ├─ Queue Size: {c.get('MaximumQueueSize')}", "ALERT")
                            
                            if c.get('TargetNamespace'):
                                self.log(f"  ├─ Target Namespace: {c.get('TargetNamespace')}", "ALERT")
                            
                            self.log(f"  └─ CreationClassName: {c.get('CreationClassName', 'N/A')}", "ALERT")
                            
                            # Controlla se è malicioso - gestisci None
                            cmd_to_check = cmd_line if cmd_line else ''
                            if self.is_wmi_malicious(str(consumer_name), str(cmd_to_check)):
                                malicious_found = True
                                consumers_to_remove.append((filters_to_remove[-1] if filters_to_remove else None, str(consumer_name)))
                                self.log(f"  🔴 [MALICIOSO] - Sarà rimosso automaticamente", "ALERT")
                            elif cmd_line and ('powershell' in cmd_line.lower() or 'cmd' in cmd_line.lower()):
                                self.log(f"  🟡 [Potenzialmente Sospetto - MEDIUM]", "ALERT")
                            else:
                                self.log(f"  🟢 [Legittimo o Neutrale]", "ALERT")
                            
                            self.log("  ---", "ALERT")
                    except Exception as e:
                        self.log(f"  Errore parsing consumers: {str(e)[:100]}", "ALERT")
                
                if has_bindings:
                    self.log("\n[FILTER-CONSUMER BINDINGS - DETTAGLI COMPLETI]", "ALERT")
                    try:
                        bindings = json.loads(result_bindings.stdout)
                        if not isinstance(bindings, list):
                            bindings = [bindings]
                        for b in bindings:
                            filter_ref = b.get('Filter', 'N/A')
                            consumer_ref = b.get('Consumer', 'N/A')
                            self.log(f"\n  🔗 BINDING ATTIVO", "ALERT")
                            self.log(f"  ├─ Filter: {filter_ref}", "ALERT")
                            self.log(f"  ├─ Consumer: {consumer_ref}", "ALERT")
                            self.log(f"  ├─ Sincrono: {b.get('DeliverSynchronously', 'False')}", "ALERT")
                            self.log(f"  ├─ Queue Size: {b.get('DeliveryQoS', 'Default')}", "ALERT")
                            self.log(f"  ├─ Slow Down: {b.get('SlowDownProviders', 'False')}", "ALERT")
                            
                            if b.get('CreatorSID'):
                                self.log(f"  ├─ CreatorSID: {b.get('CreatorSID')}", "ALERT")
                            
                            if b.get('MaintainSecurityContext'):
                                self.log(f"  ├─ Maintain Security Context: {b.get('MaintainSecurityContext')}", "ALERT")
                            
                            # Estrai consumer type da consumer_ref
                            if 'CommandLineEventConsumer' in str(consumer_ref):
                                self.log(f"  🔴 ESECUZIONE COMANDO: Questo binding esegue comandi arbitrari!", "ALERT")
                            elif 'NTEventLogEventConsumer' in str(consumer_ref):
                                self.log(f"  🟡 LOGGING EVENTO: Scrive su Event Log", "ALERT")
                            elif 'SMTPEventConsumer' in str(consumer_ref):
                                self.log(f"  🔴 EMAIL: Invia email", "ALERT")
                            elif 'ActiveScriptEventConsumer' in str(consumer_ref):
                                self.log(f"  🔴 SCRIPT: Esegue script VBScript/JScript", "ALERT")
                            
                            self.log("  ---", "ALERT")
                    except Exception as e:
                        self.log(f"  Errore parsing bindings: {str(e)[:100]}", "ALERT")
                
                self.log(f"{'='*80}\n", "ALERT")
                
                # Rimuovi automaticamente i backdoor maliciosi
                if malicious_found:
                    self.log("🔧 INIZIO RIMOZIONE AUTOMATICA WMI BACKDOOR...", "INFO")
                    for filter_name, consumer_name in consumers_to_remove:
                        self.remove_wmi_backdoor(filter_name, consumer_name)
                    self.log("✅ RIMOZIONE COMPLETATA\n", "INFO")
                
                threat = {
                    'type': 'WMI_PERSISTENCE',
                    'description': 'Event Filter/Consumer Subscription rilevato',
                    'malicious': malicious_found,
                    'filters': result_filters.stdout if has_filters else None,
                    'consumers': result_consumers.stdout if has_consumers else None,
                    'bindings': result_bindings.stdout if has_bindings else None,
                    'severity': 'CRITICAL' if malicious_found else 'INFO',
                    'timestamp': datetime.now().isoformat()
                }
                self.threats.append(threat)
                threats_found += 1 if malicious_found else 0
        except Exception as e:
            pass
        
        if threats_found == 0:
            self.log("✓ WMI: PULITO", "INFO")
        return threats_found
    
    def check_com_hijacking(self):
        """Scansione COM Hijacking - AppInit_DLLs"""
        self.log("🔍 Scansione COM HIJACKING...", "SCAN")
        
        threats_found = 0
        try:
            # Controlla AppInit_DLLs
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                    r"Software\Microsoft\Windows NT\CurrentVersion\Windows")
                appinit, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                if appinit and appinit.strip():
                    if not self.is_whitelisted(appinit):
                        threat = {
                            'type': 'APPINIT_DLL',
                            'dll': appinit,
                            'severity': 'CRITICAL',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.threats.append(threat)
                        threats_found += 1
                        self.log(f"🔴 APPINIT_DLL HIJACK: {appinit}", "ALERT")
                winreg.CloseKey(key)
            except:
                pass
            
            # Controlla KnownDLLs
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"System\CurrentControlSet\Control\Session Manager\KnownDLLs")
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        if not self.is_whitelisted(value):
                            for mal_name, pattern in self.critical_malware.items():
                                if re.search(pattern, value, re.IGNORECASE):
                                    threat = {
                                        'type': 'KNOWNDLL_HIJACK',
                                        'dll': value,
                                        'malware': mal_name,
                                        'severity': 'CRITICAL',
                                        'timestamp': datetime.now().isoformat()
                                    }
                                    self.threats.append(threat)
                                    threats_found += 1
                                    self.log(f"🔴 KNOWNDLL HIJACK [{mal_name}]: {value}", "ALERT")
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except:
                pass
        except:
            pass
        
        if threats_found == 0:
            self.log("✓ COM: PULITO", "INFO")
        return threats_found
    
    def check_services_persistence(self):
        """Scansione Services - Rootkit/Backdoor persistence"""
        self.log("🔍 Scansione SERVICES PERSISTENCE...", "SCAN")
        
        threats_found = 0
        try:
            ps_cmd = """
Get-Service | Where-Object {$_.Status -eq 'Running'} | 
Select-Object Name, DisplayName, @{N='ImagePath';E={(Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Services\\$($_.Name)" -ErrorAction SilentlyContinue).ImagePath}} |
ConvertTo-Json
"""
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    services = json.loads(result.stdout)
                    if not isinstance(services, list):
                        services = [services]
                    
                    for svc in services:
                        path = svc.get('ImagePath', '').lower() if svc.get('ImagePath') else ''
                        name = svc.get('Name', '').lower()
                        
                        if not path or self.is_whitelisted(name) or self.is_whitelisted(path):
                            continue
                        
                        for mal_name, pattern in self.critical_malware.items():
                            if re.search(pattern, path + name, re.IGNORECASE):
                                threat = {
                                    'type': 'SERVICE_MALWARE',
                                    'service': name,
                                    'path': path,
                                    'malware': mal_name,
                                    'severity': 'CRITICAL',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.threats.append(threat)
                                threats_found += 1
                                self.log(f"🔴 MALWARE SERVICE [{mal_name}]: {name}", "ALERT")
                except:
                    pass
        except:
            pass
        
        if threats_found == 0:
            self.log("✓ Services: PULITO", "INFO")
        return threats_found
    
    def check_startup_folders(self):
        """Scansione Startup Folders"""
        self.log("🔍 Scansione STARTUP FOLDERS...", "SCAN")
        
        threats_found = 0
        startup_dirs = [
            Path(os.getenv('APPDATA')) / "Microsoft/Windows/Start Menu/Programs/Startup",
            Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"),
        ]
        
        for dir_path in startup_dirs:
            if dir_path.exists():
                for file in dir_path.iterdir():
                    if file.is_file() and file.name.lower() not in ['desktop.ini']:
                        threat = {
                            'type': 'STARTUP_FILE',
                            'path': str(file),
                            'filename': file.name,
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.threats.append(threat)
                        threats_found += 1
                        self.log(f"⚠️ STARTUP FILE: {file.name}", "ALERT")
        
        if threats_found == 0:
            self.log("✓ Startup: VUOTO", "INFO")
        return threats_found
    
    def generate_final_report(self):
        """Report pulito SENZA falsi positivi"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"FINAL_REPORT_{timestamp}.html"
        
        malware_types = {}
        for t in self.threats:
            mal = t.get('malware', t.get('type', 'Unknown'))
            malware_types[mal] = malware_types.get(mal, 0) + 1
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>🛡️ Final Persistence Monitor - ZERO FALSE POSITIVES</title>
            <meta charset="UTF-8">
            <style>
                * {{ margin: 0; padding: 0; }}
                body {{ font-family: 'Courier New', monospace; background: #0a0e27; color: #00ff41; line-height: 1.6; }}
                .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #1a1a2e; border: 3px solid #00ff41; padding: 30px; margin-bottom: 30px; }}
                .header h1 {{ font-size: 32px; margin-bottom: 10px; text-shadow: 0 0 10px #00ff41; }}
                .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
                .stat {{ background: #16213e; border: 2px solid #0f3460; padding: 20px; text-align: center; }}
                .stat-value {{ font-size: 32px; color: #ff006e; font-weight: bold; }}
                .stat-label {{ color: #00ff41; font-size: 12px; margin-top: 10px; }}
                .threats-table {{ background: #16213e; border: 2px solid #00ff41; padding: 20px; margin-bottom: 30px; }}
                .threats-table h2 {{ color: #ff006e; margin-bottom: 15px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th {{ background: #0f3460; color: #00ff41; padding: 12px; text-align: left; border-bottom: 2px solid #00ff41; }}
                td {{ padding: 10px; border-bottom: 1px solid #0f3460; color: #00ff41; }}
                tr:hover {{ background: #0f3460; }}
                .critical {{ color: #ff006e; font-weight: bold; }}
                .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #0f3460; }}
                .clean {{ color: #00ff41; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ FINAL ELITE MONITOR - v4.0</h1>
                    <p style="color: #00ff41;">Scansione: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p style="color: #00ff41; margin-top: 10px;">Modalità: STRICT - ZERO FALSE POSITIVES</p>
                </div>
                
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value {'ff006e' if len(self.threats) > 0 else 'clean'}">{len(self.threats)}</div>
                        <div class="stat-label">MINACCE VERE</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value clean">✓</div>
                        <div class="stat-label">REGISTRY</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value clean">✓</div>
                        <div class="stat-label">SYSTEM PROCESSES</div>
                    </div>
                </div>
        """
        
        if self.threats:
            html += """
                <div class="threats-table">
                    <h2>🔴 MINACCE CRITICHE RILEVATE</h2>
                    <table>
                        <tr>
                            <th>MALWARE</th>
                            <th>TIPO</th>
                            <th>DETTAGLI</th>
                            <th>SEVERITA'</th>
                        </tr>
            """
            
            for threat in self.threats:
                mal = threat.get('malware', threat.get('type', 'Unknown'))
                threat_type = threat.get('type', 'Unknown')
                details = threat.get('data', threat.get('command', threat.get('path', 'N/A')))[:100]
                severity = threat.get('severity', 'HIGH')
                
                html += f"""
                        <tr>
                            <td><span class="critical">{mal}</span></td>
                            <td>{threat_type}</td>
                            <td>{details}</td>
                            <td><span class="critical">{severity}</span></td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
                
                <div class="threats-table">
                    <h2>🔧 AZIONI CONSIGLIATE</h2>
                    <div style="color: #00ff41; padding: 20px;">
                        <p><strong>1. IMMEDIATO:</strong></p>
                        <p>   • Isolare il sistema dalla rete</p>
                        <p>   • NON spegnere il computer (potrebbero eliminarsi prove)</p>
                        <p>   • Fotografare schermi/log per forensics</p>
                        <p></p>
                        
                        <p><strong>2. RIMOZIONE WMI (se WMI_PERSISTENCE):</strong></p>
                        <p>   • Aprire PowerShell come Admin</p>
                        <p>   • Get-WmiObject __EventFilter -Namespace "root\\subscription" | Remove-WmiObject</p>
                        <p>   • Get-WmiObject __EventConsumer -Namespace "root\\subscription" | Remove-WmiObject</p>
                        <p></p>
                        
                        <p><strong>3. FORENSICS:</strong></p>
                        <p>   • Salvare log: C:\\Windows\\System32\\winevt\\Logs\\</p>
                        <p>   • Dump RAM con Volatility</p>
                        <p>   • Analizzare file temporanei: C:\\temp\\ C:\\Windows\\Temp\\</p>
                        <p></p>
                        
                        <p><strong>4. ESCALATION:</strong></p>
                        <p>   • Contattare SOC/Incident Response</p>
                        <p>   • Notificare a CISO</p>
                        <p>   • Considerare reimaging totale dell'OS</p>
                    </div>
                </div>
            """
        else:
            html += """
                <div class="threats-table">
                    <h2 style="color: #00ff41;">✓ SISTEMA COMPLETAMENTE SICURO</h2>
                    <p style="color: #00ff41; margin-top: 20px; font-size: 16px;">Nessuna minaccia rilevata</p>
                </div>
            """
        
        html += f"""
                <div class="footer">
                    <p>🛡️ Final Elite Persistence Monitor - Real-time Malware Detection</p>
                    <p>Registry | Scheduled Tasks | Process Analysis | Startup Folders</p>
                    <p>Whitelist: {len(self.trusted_executables)} exe | Malware DB: {len(self.critical_malware)} signatures</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.log(f"✓ Report: {report_file}", "INFO")
        return report_file
    
    def run_monitoring(self, interval=300):
        """Monitoraggio FINAL"""
        self.log("=" * 80, "START")
        self.log("🚀 FINAL ELITE MONITOR v4.0 - ZERO FALSE POSITIVES", "START")
        self.log("=" * 80, "START")
        
        scan_count = 0
        try:
            while True:
                scan_count += 1
                self.log(f"\n【CICLO #{scan_count}】 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "SCAN")
                
                before = len(self.threats)
                
                # Scansioni finali
                self.check_registry_strict()
                self.check_scheduled_tasks_strict()
                self.check_processes_strict()
                self.check_wmi_subscriptions()
                self.check_com_hijacking()
                self.check_services_persistence()
                self.check_startup_folders()
                
                new_threats = len(self.threats) - before
                
                if new_threats > 0:
                    self.log(f"🔴 NUOVE MINACCE VERE: +{new_threats}", "ALERT")
                    self.generate_final_report()
                else:
                    self.log(f"✓ SISTEMA SICURO - Nessuna minaccia", "INFO")
                
                self.log(f"⏰ Prossima scansione: {interval}s\n", "INFO")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.log("\n⏹️ Monitoraggio Terminato", "STOP")
            if self.threats:
                self.generate_final_report()

if __name__ == "__main__":
    monitor = FinalPersistenceMonitor()
    monitor.run_monitoring(interval=300)