/**
 * MITRE ATT&CK Coverage Dashboard — SOC/CSIRT
 * Google Apps Script Web App. Puxa as regras do Elastic (Kibana Detection Engine API),
 * calcula a cobertura contra o catálogo ATT&CK v19.1 (15 táticas) e serve o dashboard.
 *
 * SETUP (uma vez):
 *  1. Projeto > Configurações do projeto > Propriedades do script, adicione:
 *       KIBANA_URL   = https://SEU-KIBANA:5601        (sem barra no final)
 *       ES_API_KEY   = <API key do Elastic, formato base64 do "id:key">
 *       KIBANA_SPACE = default                        (opcional; se usar space próprio)
 *  2. Implantar > Nova implantação > Tipo: App da Web
 *       Executar como: Eu  |  Quem tem acesso: (conforme sua política; p/ Sites interno: sua org)
 *  3. Copie a URL /exec e use no Google Sites: Inserir > Por URL.
 *  4. (Auto-update) Gatilhos > Adicionar gatilho > refreshCache, baseado em tempo, a cada 1–6h.
 */

var CATALOG = {"tactics":[{"id":"TA0043","order":1,"name":"Reconnaissance","src":"TA0043","techniques":[{"id":"T1592","name":"Gather Victim Host Information","subs":[{"id":"T1592.001","name":"Hardware"},{"id":"T1592.002","name":"Software"},{"id":"T1592.003","name":"Firmware"},{"id":"T1592.004","name":"Client Configurations"}]},{"id":"T1682","name":"Query Public AI Services","subs":[]},{"id":"T1594","name":"Search Victim-Owned Websites","subs":[]},{"id":"T1589","name":"Gather Victim Identity Information","subs":[{"id":"T1589.001","name":"Credentials"},{"id":"T1589.002","name":"Email Addresses"},{"id":"T1589.003","name":"Employee Names"}]},{"id":"T1596","name":"Search Open Technical Databases","subs":[{"id":"T1596.001","name":"DNS/Passive DNS"},{"id":"T1596.002","name":"WHOIS"},{"id":"T1596.003","name":"Digital Certificates"},{"id":"T1596.004","name":"CDNs"},{"id":"T1596.005","name":"Scan Databases"}]},{"id":"T1681","name":"Search Threat Vendor Data","subs":[]},{"id":"T1595","name":"Active Scanning","subs":[{"id":"T1595.001","name":"Scanning IP Blocks"},{"id":"T1595.002","name":"Vulnerability Scanning"},{"id":"T1595.003","name":"Wordlist Scanning"}]},{"id":"T1591","name":"Gather Victim Org Information","subs":[{"id":"T1591.001","name":"Determine Physical Locations"},{"id":"T1591.002","name":"Business Relationships"},{"id":"T1591.003","name":"Identify Business Tempo"},{"id":"T1591.004","name":"Identify Roles"}]},{"id":"T1590","name":"Gather Victim Network Information","subs":[{"id":"T1590.001","name":"Domain Properties"},{"id":"T1590.002","name":"DNS"},{"id":"T1590.003","name":"Network Trust Dependencies"},{"id":"T1590.004","name":"Network Topology"},{"id":"T1590.005","name":"IP Addresses"},{"id":"T1590.006","name":"Network Security Appliances"}]},{"id":"T1593","name":"Search Open Websites/Domains","subs":[{"id":"T1593.001","name":"Social Media"},{"id":"T1593.002","name":"Search Engines"},{"id":"T1593.003","name":"Code Repositories"}]},{"id":"T1597","name":"Search Closed Sources","subs":[{"id":"T1597.001","name":"Threat Intel Vendors"},{"id":"T1597.002","name":"Purchase Technical Data"}]},{"id":"T1598","name":"Phishing for Information","subs":[{"id":"T1598.001","name":"Spearphishing Service"},{"id":"T1598.002","name":"Spearphishing Attachment"},{"id":"T1598.003","name":"Spearphishing Link"},{"id":"T1598.004","name":"Spearphishing Voice"}]}]},{"id":"TA0042","order":2,"name":"Resource Development","src":"TA0042","techniques":[{"id":"T1583","name":"Acquire Infrastructure","subs":[{"id":"T1583.001","name":"Domains"},{"id":"T1583.002","name":"DNS Server"},{"id":"T1583.003","name":"Virtual Private Server"},{"id":"T1583.004","name":"Server"},{"id":"T1583.005","name":"Botnet"},{"id":"T1583.006","name":"Web Services"},{"id":"T1583.007","name":"Serverless"},{"id":"T1583.008","name":"Malvertising"}]},{"id":"T1584","name":"Compromise Infrastructure","subs":[{"id":"T1584.001","name":"Domains"},{"id":"T1584.002","name":"DNS Server"},{"id":"T1584.003","name":"Virtual Private Server"},{"id":"T1584.004","name":"Server"},{"id":"T1584.005","name":"Botnet"},{"id":"T1584.006","name":"Web Services"},{"id":"T1584.007","name":"Serverless"},{"id":"T1584.008","name":"Network Devices"}]},{"id":"T1586","name":"Compromise Accounts","subs":[{"id":"T1586.001","name":"Social Media Accounts"},{"id":"T1586.002","name":"Email Accounts"},{"id":"T1586.003","name":"Cloud Accounts"}]},{"id":"T1608","name":"Stage Capabilities","subs":[{"id":"T1608.001","name":"Upload Malware"},{"id":"T1608.002","name":"Upload Tool"},{"id":"T1608.003","name":"Install Digital Certificate"},{"id":"T1608.004","name":"Drive-by Target"},{"id":"T1608.005","name":"Link Target"},{"id":"T1608.006","name":"SEO Poisoning"}]},{"id":"T1683","name":"Generate Content","subs":[{"id":"T1683.001","name":"Written Content"},{"id":"T1683.002","name":"Audio-Visual Content"}]},{"id":"T1585","name":"Establish Accounts","subs":[{"id":"T1585.001","name":"Social Media Accounts"},{"id":"T1585.002","name":"Email Accounts"},{"id":"T1585.003","name":"Cloud Accounts"}]},{"id":"T1588","name":"Obtain Capabilities","subs":[{"id":"T1588.001","name":"Malware"},{"id":"T1588.002","name":"Tool"},{"id":"T1588.003","name":"Code Signing Certificates"},{"id":"T1588.004","name":"Digital Certificates"},{"id":"T1588.005","name":"Exploits"},{"id":"T1588.006","name":"Vulnerabilities"},{"id":"T1588.007","name":"Artificial Intelligence"}]},{"id":"T1650","name":"Acquire Access","subs":[]},{"id":"T1587","name":"Develop Capabilities","subs":[{"id":"T1587.001","name":"Malware"},{"id":"T1587.002","name":"Code Signing Certificates"},{"id":"T1587.003","name":"Digital Certificates"},{"id":"T1587.004","name":"Exploits"}]}]},{"id":"TA0001","order":3,"name":"Initial Access","src":"TA0001","techniques":[{"id":"T1133","name":"External Remote Services","subs":[]},{"id":"T1091","name":"Replication Through Removable Media","subs":[]},{"id":"T1195","name":"Supply Chain Compromise","subs":[{"id":"T1195.001","name":"Compromise Software Dependencies and Development Tools"},{"id":"T1195.002","name":"Compromise Software Supply Chain"},{"id":"T1195.003","name":"Compromise Hardware Supply Chain"}]},{"id":"T1190","name":"Exploit Public-Facing Application","subs":[]},{"id":"T1659","name":"Content Injection","subs":[]},{"id":"T1199","name":"Trusted Relationship","subs":[]},{"id":"T1566","name":"Phishing","subs":[{"id":"T1566.001","name":"Spearphishing Attachment"},{"id":"T1566.002","name":"Spearphishing Link"},{"id":"T1566.003","name":"Spearphishing via Service"},{"id":"T1566.004","name":"Spearphishing Voice"}]},{"id":"T1078","name":"Valid Accounts","subs":[{"id":"T1078.001","name":"Default Accounts"},{"id":"T1078.002","name":"Domain Accounts"},{"id":"T1078.003","name":"Local Accounts"},{"id":"T1078.004","name":"Cloud Accounts"}]},{"id":"T1200","name":"Hardware Additions","subs":[]},{"id":"T1189","name":"Drive-by Compromise","subs":[]},{"id":"T1669","name":"Wi-Fi Networks","subs":[]}]},{"id":"TA0002","order":4,"name":"Execution","src":"TA0002","techniques":[{"id":"T1047","name":"Windows Management Instrumentation","subs":[]},{"id":"T1129","name":"Shared Modules","subs":[]},{"id":"T1675","name":"ESXi Administration Command","subs":[]},{"id":"T1053","name":"Scheduled Task/Job","subs":[{"id":"T1053.002","name":"At"},{"id":"T1053.003","name":"Cron"},{"id":"T1053.005","name":"Scheduled Task"},{"id":"T1053.006","name":"Systemd Timers"},{"id":"T1053.007","name":"Container Orchestration Job"}]},{"id":"T1106","name":"Native API","subs":[]},{"id":"T1610","name":"Deploy Container","subs":[]},{"id":"T1674","name":"Input Injection","subs":[]},{"id":"T1059","name":"Command and Scripting Interpreter","subs":[{"id":"T1059.001","name":"PowerShell"},{"id":"T1059.002","name":"AppleScript"},{"id":"T1059.003","name":"Windows Command Shell"},{"id":"T1059.004","name":"Unix Shell"},{"id":"T1059.005","name":"Visual Basic"},{"id":"T1059.006","name":"Python"},{"id":"T1059.007","name":"JavaScript"},{"id":"T1059.008","name":"Network Device CLI"},{"id":"T1059.009","name":"Cloud API"},{"id":"T1059.010","name":"AutoHotKey & AutoIT"},{"id":"T1059.011","name":"Lua"},{"id":"T1059.012","name":"Hypervisor CLI"},{"id":"T1059.013","name":"Container CLI/API"}]},{"id":"T1677","name":"Poisoned Pipeline Execution","subs":[]},{"id":"T1609","name":"Container Administration Command","subs":[]},{"id":"T1204","name":"User Execution","subs":[{"id":"T1204.001","name":"Malicious Link"},{"id":"T1204.002","name":"Malicious File"},{"id":"T1204.003","name":"Malicious Image"},{"id":"T1204.004","name":"Malicious Copy and Paste"},{"id":"T1204.005","name":"Malicious Library"}]},{"id":"T1072","name":"Software Deployment Tools","subs":[]},{"id":"T1559","name":"Inter-Process Communication","subs":[{"id":"T1559.001","name":"Component Object Model"},{"id":"T1559.002","name":"Dynamic Data Exchange"},{"id":"T1559.003","name":"XPC Services"}]},{"id":"T1574","name":"Hijack Execution Flow","subs":[{"id":"T1574.001","name":"DLL"},{"id":"T1574.004","name":"Dylib Hijacking"},{"id":"T1574.005","name":"Executable Installer File Permissions Weakness"},{"id":"T1574.006","name":"Dynamic Linker Hijacking"},{"id":"T1574.007","name":"Path Interception by PATH Environment Variable"},{"id":"T1574.008","name":"Path Interception by Search Order Hijacking"},{"id":"T1574.009","name":"Path Interception by Unquoted Path"},{"id":"T1574.010","name":"Services File Permissions Weakness"},{"id":"T1574.011","name":"Services Registry Permissions Weakness"},{"id":"T1574.012","name":"COR_PROFILER"},{"id":"T1574.013","name":"KernelCallbackTable"},{"id":"T1574.014","name":"AppDomainManager"}]},{"id":"T1203","name":"Exploitation for Client Execution","subs":[]},{"id":"T1197","name":"BITS Jobs","subs":[]},{"id":"T1569","name":"System Services","subs":[{"id":"T1569.001","name":"Launchctl"},{"id":"T1569.002","name":"Service Execution"},{"id":"T1569.003","name":"Systemctl"}]},{"id":"T1651","name":"Cloud Administration Command","subs":[]},{"id":"T1648","name":"Serverless Execution","subs":[]},{"id":"T1127","name":"Trusted Developer Utilities Proxy Execution","subs":[{"id":"T1127.001","name":"MSBuild"},{"id":"T1127.002","name":"ClickOnce"},{"id":"T1127.003","name":"JamPlus"}]}]},{"id":"TA0003","order":5,"name":"Persistence","src":"TA0003","techniques":[{"id":"T1037","name":"Boot or Logon Initialization Scripts","subs":[{"id":"T1037.001","name":"Logon Script (Windows)"},{"id":"T1037.002","name":"Login Hook"},{"id":"T1037.003","name":"Network Logon Script"},{"id":"T1037.004","name":"RC Scripts"},{"id":"T1037.005","name":"Startup Items"}]},{"id":"T1543","name":"Create or Modify System Process","subs":[{"id":"T1543.001","name":"Launch Agent"},{"id":"T1543.002","name":"Systemd Service"},{"id":"T1543.003","name":"Windows Service"},{"id":"T1543.004","name":"Launch Daemon"},{"id":"T1543.005","name":"Container Service"}]},{"id":"T1133","name":"External Remote Services","subs":[]},{"id":"T1547","name":"Boot or Logon Autostart Execution","subs":[{"id":"T1547.001","name":"Registry Run Keys / Startup Folder"},{"id":"T1547.002","name":"Authentication Package"},{"id":"T1547.003","name":"Time Providers"},{"id":"T1547.004","name":"Winlogon Helper DLL"},{"id":"T1547.005","name":"Security Support Provider"},{"id":"T1547.006","name":"Kernel Modules and Extensions"},{"id":"T1547.007","name":"Re-opened Applications"},{"id":"T1547.008","name":"LSASS Driver"},{"id":"T1547.009","name":"Shortcut Modification"},{"id":"T1547.010","name":"Port Monitors"},{"id":"T1547.012","name":"Print Processors"},{"id":"T1547.013","name":"XDG Autostart Entries"},{"id":"T1547.014","name":"Active Setup"},{"id":"T1547.015","name":"Login Items"}]},{"id":"T1137","name":"Office Application Startup","subs":[{"id":"T1137.001","name":"Office Template Macros"},{"id":"T1137.002","name":"Office Test"},{"id":"T1137.003","name":"Outlook Forms"},{"id":"T1137.004","name":"Outlook Home Page"},{"id":"T1137.005","name":"Outlook Rules"},{"id":"T1137.006","name":"Add-ins"}]},{"id":"T1053","name":"Scheduled Task/Job","subs":[{"id":"T1053.002","name":"At"},{"id":"T1053.003","name":"Cron"},{"id":"T1053.005","name":"Scheduled Task"},{"id":"T1053.006","name":"Systemd Timers"},{"id":"T1053.007","name":"Container Orchestration Job"}]},{"id":"T1176","name":"Software Extensions","subs":[{"id":"T1176.001","name":"Browser Extensions"},{"id":"T1176.002","name":"IDE Extensions"}]},{"id":"T1205","name":"Traffic Signaling","subs":[{"id":"T1205.001","name":"Port Knocking"},{"id":"T1205.002","name":"Socket Filters"}]},{"id":"T1525","name":"Implant Internal Image","subs":[]},{"id":"T1112","name":"Modify Registry","subs":[]},{"id":"T1542","name":"Pre-OS Boot","subs":[{"id":"T1542.001","name":"System Firmware"},{"id":"T1542.002","name":"Component Firmware"},{"id":"T1542.003","name":"Bootkit"},{"id":"T1542.004","name":"ROMMONkit"},{"id":"T1542.005","name":"TFTP Boot"}]},{"id":"T1554","name":"Compromise Host Software Binary","subs":[]},{"id":"T1098","name":"Account Manipulation","subs":[{"id":"T1098.001","name":"Additional Cloud Credentials"},{"id":"T1098.002","name":"Additional Email Delegate Permissions"},{"id":"T1098.003","name":"Additional Cloud Roles"},{"id":"T1098.004","name":"SSH Authorized Keys"},{"id":"T1098.005","name":"Device Registration"},{"id":"T1098.006","name":"Additional Container Cluster Roles"},{"id":"T1098.007","name":"Additional Local or Domain Groups"}]},{"id":"T1078","name":"Valid Accounts","subs":[{"id":"T1078.001","name":"Default Accounts"},{"id":"T1078.002","name":"Domain Accounts"},{"id":"T1078.003","name":"Local Accounts"},{"id":"T1078.004","name":"Cloud Accounts"}]},{"id":"T1546","name":"Event Triggered Execution","subs":[{"id":"T1546.001","name":"Change Default File Association"},{"id":"T1546.002","name":"Screensaver"},{"id":"T1546.003","name":"Windows Management Instrumentation Event Subscription"},{"id":"T1546.004","name":"Unix Shell Configuration Modification"},{"id":"T1546.005","name":"Trap"},{"id":"T1546.006","name":"LC_LOAD_DYLIB Addition"},{"id":"T1546.007","name":"Netsh Helper DLL"},{"id":"T1546.008","name":"Accessibility Features"},{"id":"T1546.009","name":"AppCert DLLs"},{"id":"T1546.010","name":"AppInit DLLs"},{"id":"T1546.011","name":"Application Shimming"},{"id":"T1546.012","name":"Image File Execution Options Injection"},{"id":"T1546.013","name":"PowerShell Profile"},{"id":"T1546.014","name":"Emond"},{"id":"T1546.015","name":"Component Object Model Hijacking"},{"id":"T1546.016","name":"Installer Packages"},{"id":"T1546.017","name":"Udev Rules"},{"id":"T1546.018","name":"Python Startup Hooks"}]},{"id":"T1671","name":"Cloud Application Integration","subs":[]},{"id":"T1197","name":"BITS Jobs","subs":[]},{"id":"T1505","name":"Server Software Component","subs":[{"id":"T1505.001","name":"SQL Stored Procedures"},{"id":"T1505.002","name":"Transport Agent"},{"id":"T1505.003","name":"Web Shell"},{"id":"T1505.004","name":"IIS Components"},{"id":"T1505.005","name":"Terminal Services DLL"},{"id":"T1505.006","name":"vSphere Installation Bundles"}]},{"id":"T1668","name":"Exclusive Control","subs":[]},{"id":"T1136","name":"Create Account","subs":[{"id":"T1136.001","name":"Local Account"},{"id":"T1136.002","name":"Domain Account"},{"id":"T1136.003","name":"Cloud Account"}]},{"id":"T1653","name":"Power Settings","subs":[]},{"id":"T1556","name":"Modify Authentication Process","subs":[{"id":"T1556.001","name":"Domain Controller Authentication"},{"id":"T1556.002","name":"Password Filter DLL"},{"id":"T1556.003","name":"Pluggable Authentication Modules"},{"id":"T1556.004","name":"Network Device Authentication"},{"id":"T1556.005","name":"Reversible Encryption"},{"id":"T1556.006","name":"Multi-Factor Authentication"},{"id":"T1556.007","name":"Hybrid Identity"},{"id":"T1556.008","name":"Network Provider DLL"},{"id":"T1556.009","name":"Conditional Access Policies"}]}]},{"id":"TA0004","order":6,"name":"Privilege Escalation","src":"TA0004","techniques":[{"id":"T1037","name":"Boot or Logon Initialization Scripts","subs":[{"id":"T1037.001","name":"Logon Script (Windows)"},{"id":"T1037.002","name":"Login Hook"},{"id":"T1037.003","name":"Network Logon Script"},{"id":"T1037.004","name":"RC Scripts"},{"id":"T1037.005","name":"Startup Items"}]},{"id":"T1543","name":"Create or Modify System Process","subs":[{"id":"T1543.001","name":"Launch Agent"},{"id":"T1543.002","name":"Systemd Service"},{"id":"T1543.003","name":"Windows Service"},{"id":"T1543.004","name":"Launch Daemon"},{"id":"T1543.005","name":"Container Service"}]},{"id":"T1547","name":"Boot or Logon Autostart Execution","subs":[{"id":"T1547.001","name":"Registry Run Keys / Startup Folder"},{"id":"T1547.002","name":"Authentication Package"},{"id":"T1547.003","name":"Time Providers"},{"id":"T1547.004","name":"Winlogon Helper DLL"},{"id":"T1547.005","name":"Security Support Provider"},{"id":"T1547.006","name":"Kernel Modules and Extensions"},{"id":"T1547.007","name":"Re-opened Applications"},{"id":"T1547.008","name":"LSASS Driver"},{"id":"T1547.009","name":"Shortcut Modification"},{"id":"T1547.010","name":"Port Monitors"},{"id":"T1547.012","name":"Print Processors"},{"id":"T1547.013","name":"XDG Autostart Entries"},{"id":"T1547.014","name":"Active Setup"},{"id":"T1547.015","name":"Login Items"}]},{"id":"T1053","name":"Scheduled Task/Job","subs":[{"id":"T1053.002","name":"At"},{"id":"T1053.003","name":"Cron"},{"id":"T1053.005","name":"Scheduled Task"},{"id":"T1053.006","name":"Systemd Timers"},{"id":"T1053.007","name":"Container Orchestration Job"}]},{"id":"T1055","name":"Process Injection","subs":[{"id":"T1055.001","name":"Dynamic-link Library Injection"},{"id":"T1055.002","name":"Portable Executable Injection"},{"id":"T1055.003","name":"Thread Execution Hijacking"},{"id":"T1055.004","name":"Asynchronous Procedure Call"},{"id":"T1055.005","name":"Thread Local Storage"},{"id":"T1055.008","name":"Ptrace System Calls"},{"id":"T1055.009","name":"Proc Memory"},{"id":"T1055.011","name":"Extra Window Memory Injection"},{"id":"T1055.012","name":"Process Hollowing"},{"id":"T1055.013","name":"Process Doppelgänging"},{"id":"T1055.014","name":"VDSO Hijacking"},{"id":"T1055.015","name":"ListPlanting"}]},{"id":"T1611","name":"Escape to Host","subs":[]},{"id":"T1548","name":"Abuse Elevation Control Mechanism","subs":[{"id":"T1548.001","name":"Setuid and Setgid"},{"id":"T1548.002","name":"Bypass User Account Control"},{"id":"T1548.003","name":"Sudo and Sudo Caching"},{"id":"T1548.004","name":"Elevated Execution with Prompt"},{"id":"T1548.005","name":"Temporary Elevated Cloud Access"},{"id":"T1548.006","name":"TCC Manipulation"}]},{"id":"T1098","name":"Account Manipulation","subs":[{"id":"T1098.001","name":"Additional Cloud Credentials"},{"id":"T1098.002","name":"Additional Email Delegate Permissions"},{"id":"T1098.003","name":"Additional Cloud Roles"},{"id":"T1098.004","name":"SSH Authorized Keys"},{"id":"T1098.005","name":"Device Registration"},{"id":"T1098.006","name":"Additional Container Cluster Roles"},{"id":"T1098.007","name":"Additional Local or Domain Groups"}]},{"id":"T1078","name":"Valid Accounts","subs":[{"id":"T1078.001","name":"Default Accounts"},{"id":"T1078.002","name":"Domain Accounts"},{"id":"T1078.003","name":"Local Accounts"},{"id":"T1078.004","name":"Cloud Accounts"}]},{"id":"T1068","name":"Exploitation for Privilege Escalation","subs":[]},{"id":"T1546","name":"Event Triggered Execution","subs":[{"id":"T1546.001","name":"Change Default File Association"},{"id":"T1546.002","name":"Screensaver"},{"id":"T1546.003","name":"Windows Management Instrumentation Event Subscription"},{"id":"T1546.004","name":"Unix Shell Configuration Modification"},{"id":"T1546.005","name":"Trap"},{"id":"T1546.006","name":"LC_LOAD_DYLIB Addition"},{"id":"T1546.007","name":"Netsh Helper DLL"},{"id":"T1546.008","name":"Accessibility Features"},{"id":"T1546.009","name":"AppCert DLLs"},{"id":"T1546.010","name":"AppInit DLLs"},{"id":"T1546.011","name":"Application Shimming"},{"id":"T1546.012","name":"Image File Execution Options Injection"},{"id":"T1546.013","name":"PowerShell Profile"},{"id":"T1546.014","name":"Emond"},{"id":"T1546.015","name":"Component Object Model Hijacking"},{"id":"T1546.016","name":"Installer Packages"},{"id":"T1546.017","name":"Udev Rules"},{"id":"T1546.018","name":"Python Startup Hooks"}]},{"id":"T1134","name":"Access Token Manipulation","subs":[{"id":"T1134.001","name":"Token Impersonation/Theft"},{"id":"T1134.002","name":"Create Process with Token"},{"id":"T1134.003","name":"Make and Impersonate Token"},{"id":"T1134.004","name":"Parent PID Spoofing"},{"id":"T1134.005","name":"SID-History Injection"}]},{"id":"T1484","name":"Domain or Tenant Policy Modification","subs":[{"id":"T1484.001","name":"Group Policy Modification"},{"id":"T1484.002","name":"Trust Modification"}]}]},{"id":"TA0005","order":7,"name":"Stealth","src":"TA0005","techniques":[{"id":"T1006","name":"Direct Volume Access","subs":[]},{"id":"T1014","name":"Rootkit","subs":[]},{"id":"T1564","name":"Hide Artifacts","subs":[{"id":"T1564.001","name":"Hidden Files and Directories"},{"id":"T1564.002","name":"Hidden Users"},{"id":"T1564.003","name":"Hidden Window"},{"id":"T1564.004","name":"NTFS File Attributes"},{"id":"T1564.005","name":"Hidden File System"},{"id":"T1564.006","name":"Run Virtual Instance"},{"id":"T1564.007","name":"VBA Stomping"},{"id":"T1564.008","name":"Email Hiding Rules"},{"id":"T1564.009","name":"Resource Forking"},{"id":"T1564.010","name":"Process Argument Spoofing"},{"id":"T1564.011","name":"Ignore Process Interrupts"},{"id":"T1564.012","name":"File/Path Exclusions"},{"id":"T1564.013","name":"Bind Mounts"},{"id":"T1564.014","name":"Extended Attributes"}]},{"id":"T1202","name":"Indirect Command Execution","subs":[]},{"id":"T1140","name":"Deobfuscate/Decode Files or Information","subs":[]},{"id":"T1684","name":"Social Engineering","subs":[{"id":"T1684.001","name":"Impersonation"},{"id":"T1684.002","name":"Email Spoofing"}]},{"id":"T1036","name":"Masquerading","subs":[{"id":"T1036.001","name":"Invalid Code Signature"},{"id":"T1036.002","name":"Right-to-Left Override"},{"id":"T1036.003","name":"Rename Legitimate Utilities"},{"id":"T1036.004","name":"Masquerade Task or Service"},{"id":"T1036.005","name":"Match Legitimate Resource Name or Location"},{"id":"T1036.006","name":"Space after Filename"},{"id":"T1036.007","name":"Double File Extension"},{"id":"T1036.008","name":"Masquerade File Type"},{"id":"T1036.009","name":"Break Process Trees"},{"id":"T1036.010","name":"Masquerade Account Name"},{"id":"T1036.011","name":"Overwrite Process Arguments"},{"id":"T1036.012","name":"Browser Fingerprint"}]},{"id":"T1055","name":"Process Injection","subs":[{"id":"T1055.001","name":"Dynamic-link Library Injection"},{"id":"T1055.002","name":"Portable Executable Injection"},{"id":"T1055.003","name":"Thread Execution Hijacking"},{"id":"T1055.004","name":"Asynchronous Procedure Call"},{"id":"T1055.005","name":"Thread Local Storage"},{"id":"T1055.008","name":"Ptrace System Calls"},{"id":"T1055.009","name":"Proc Memory"},{"id":"T1055.011","name":"Extra Window Memory Injection"},{"id":"T1055.012","name":"Process Hollowing"},{"id":"T1055.013","name":"Process Doppelgänging"},{"id":"T1055.014","name":"VDSO Hijacking"},{"id":"T1055.015","name":"ListPlanting"}]},{"id":"T1205","name":"Traffic Signaling","subs":[{"id":"T1205.001","name":"Port Knocking"},{"id":"T1205.002","name":"Socket Filters"}]},{"id":"T1218","name":"System Binary Proxy Execution","subs":[{"id":"T1218.001","name":"Compiled HTML File"},{"id":"T1218.002","name":"Control Panel"},{"id":"T1218.003","name":"CMSTP"},{"id":"T1218.004","name":"InstallUtil"},{"id":"T1218.005","name":"Mshta"},{"id":"T1218.007","name":"Msiexec"},{"id":"T1218.008","name":"Odbcconf"},{"id":"T1218.009","name":"Regsvcs/Regasm"},{"id":"T1218.010","name":"Regsvr32"},{"id":"T1218.011","name":"Rundll32"},{"id":"T1218.012","name":"Verclsid"},{"id":"T1218.013","name":"Mavinject"},{"id":"T1218.014","name":"MMC"},{"id":"T1218.015","name":"Electron Applications"}]},{"id":"T1620","name":"Reflective Code Loading","subs":[]},{"id":"T1535","name":"Unused/Unsupported Cloud Regions","subs":[]},{"id":"T1070","name":"Indicator Removal","subs":[{"id":"T1070.003","name":"Clear Command History"},{"id":"T1070.004","name":"File Deletion"},{"id":"T1070.005","name":"Network Share Connection Removal"},{"id":"T1070.006","name":"Timestomp"},{"id":"T1070.007","name":"Clear Network Connection History and Configurations"},{"id":"T1070.008","name":"Clear Mailbox Data"},{"id":"T1070.009","name":"Clear Persistence"},{"id":"T1070.010","name":"Relocate Malware"}]},{"id":"T1542","name":"Pre-OS Boot","subs":[{"id":"T1542.001","name":"System Firmware"},{"id":"T1542.002","name":"Component Firmware"},{"id":"T1542.003","name":"Bootkit"},{"id":"T1542.004","name":"ROMMONkit"},{"id":"T1542.005","name":"TFTP Boot"}]},{"id":"T1612","name":"Build Image on Host","subs":[]},{"id":"T1497","name":"Virtualization/Sandbox Evasion","subs":[{"id":"T1497.001","name":"System Checks"},{"id":"T1497.002","name":"User Activity Based Checks"},{"id":"T1497.003","name":"Time Based Checks"}]},{"id":"T1480","name":"Execution Guardrails","subs":[{"id":"T1480.001","name":"Environmental Keying"},{"id":"T1480.002","name":"Mutual Exclusion"}]},{"id":"T1679","name":"Selective Exclusion","subs":[]},{"id":"T1678","name":"Delay Execution","subs":[]},{"id":"T1574","name":"Hijack Execution Flow","subs":[{"id":"T1574.001","name":"DLL"},{"id":"T1574.004","name":"Dylib Hijacking"},{"id":"T1574.005","name":"Executable Installer File Permissions Weakness"},{"id":"T1574.006","name":"Dynamic Linker Hijacking"},{"id":"T1574.007","name":"Path Interception by PATH Environment Variable"},{"id":"T1574.008","name":"Path Interception by Search Order Hijacking"},{"id":"T1574.009","name":"Path Interception by Unquoted Path"},{"id":"T1574.010","name":"Services File Permissions Weakness"},{"id":"T1574.011","name":"Services Registry Permissions Weakness"},{"id":"T1574.012","name":"COR_PROFILER"},{"id":"T1574.013","name":"KernelCallbackTable"},{"id":"T1574.014","name":"AppDomainManager"}]},{"id":"T1078","name":"Valid Accounts","subs":[{"id":"T1078.001","name":"Default Accounts"},{"id":"T1078.002","name":"Domain Accounts"},{"id":"T1078.003","name":"Local Accounts"},{"id":"T1078.004","name":"Cloud Accounts"}]},{"id":"T1027","name":"Obfuscated Files or Information","subs":[{"id":"T1027.001","name":"Binary Padding"},{"id":"T1027.002","name":"Software Packing"},{"id":"T1027.003","name":"Steganography"},{"id":"T1027.004","name":"Compile After Delivery"},{"id":"T1027.005","name":"Indicator Removal from Tools"},{"id":"T1027.006","name":"HTML Smuggling"},{"id":"T1027.007","name":"Dynamic API Resolution"},{"id":"T1027.008","name":"Stripped Payloads"},{"id":"T1027.009","name":"Embedded Payloads"},{"id":"T1027.010","name":"Command Obfuscation"},{"id":"T1027.011","name":"Fileless Storage"},{"id":"T1027.012","name":"LNK Icon Smuggling"},{"id":"T1027.013","name":"Encrypted/Encoded File"},{"id":"T1027.014","name":"Polymorphic Code"},{"id":"T1027.015","name":"Compression"},{"id":"T1027.016","name":"Junk Code Insertion"},{"id":"T1027.017","name":"SVG Smuggling"},{"id":"T1027.018","name":"Invisible Unicode"}]},{"id":"T1197","name":"BITS Jobs","subs":[]},{"id":"T1221","name":"Template Injection","subs":[]},{"id":"T1134","name":"Access Token Manipulation","subs":[{"id":"T1134.001","name":"Token Impersonation/Theft"},{"id":"T1134.002","name":"Create Process with Token"},{"id":"T1134.003","name":"Make and Impersonate Token"},{"id":"T1134.004","name":"Parent PID Spoofing"},{"id":"T1134.005","name":"SID-History Injection"}]},{"id":"T1622","name":"Debugger Evasion","subs":[]},{"id":"T1220","name":"XSL Script Processing","subs":[]},{"id":"T1216","name":"System Script Proxy Execution","subs":[{"id":"T1216.001","name":"PubPrn"},{"id":"T1216.002","name":"SyncAppvPublishingServer"}]},{"id":"T1211","name":"Exploitation for Stealth","subs":[]},{"id":"T1127","name":"Trusted Developer Utilities Proxy Execution","subs":[{"id":"T1127.001","name":"MSBuild"},{"id":"T1127.002","name":"ClickOnce"},{"id":"T1127.003","name":"JamPlus"}]}]},{"id":"TA0112","order":8,"name":"Defense Impairment","src":"TA0005","techniques":[{"id":"T1687","name":"Exploitation for Defense Impairment","subs":[]},{"id":"T1666","name":"Modify Cloud Resource Hierarchy","subs":[]},{"id":"T1578","name":"Modify Cloud Compute Infrastructure","subs":[{"id":"T1578.001","name":"Create Snapshot"},{"id":"T1578.002","name":"Create Cloud Instance"},{"id":"T1578.003","name":"Delete Cloud Instance"},{"id":"T1578.004","name":"Revert Cloud Instance"},{"id":"T1578.005","name":"Modify Cloud Compute Configurations"}]},{"id":"T1600","name":"Weaken Encryption","subs":[{"id":"T1600.001","name":"Reduce Key Space"},{"id":"T1600.002","name":"Disable Crypto Hardware"}]},{"id":"T1689","name":"Downgrade Attack","subs":[]},{"id":"T1207","name":"Rogue Domain Controller","subs":[]},{"id":"T1112","name":"Modify Registry","subs":[]},{"id":"T1222","name":"File and Directory Permissions Modification","subs":[{"id":"T1222.001","name":"Windows Permissions"},{"id":"T1222.002","name":"Linux and Mac Permissions"}]},{"id":"T1647","name":"Plist File Modification","subs":[]},{"id":"T1601","name":"Modify System Image","subs":[{"id":"T1601.001","name":"Patch System Image"},{"id":"T1601.002","name":"Downgrade System Image"}]},{"id":"T1599","name":"Network Boundary Bridging","subs":[{"id":"T1599.001","name":"Network Address Translation Traversal"}]},{"id":"T1690","name":"Prevent Command History Logging","subs":[]},{"id":"T1553","name":"Subvert Trust Controls","subs":[{"id":"T1553.001","name":"Gatekeeper Bypass"},{"id":"T1553.002","name":"Code Signing"},{"id":"T1553.003","name":"SIP and Trust Provider Hijacking"},{"id":"T1553.004","name":"Install Root Certificate"},{"id":"T1553.005","name":"Mark-of-the-Web Bypass"},{"id":"T1553.006","name":"Code Signing Policy Modification"}]},{"id":"T1685","name":"Disable or Modify Tools","subs":[{"id":"T1685.001","name":"Disable or Modify Windows Event Log"},{"id":"T1685.002","name":"Disable or Modify Cloud Log"},{"id":"T1685.003","name":"Modify or Spoof Tool UI"},{"id":"T1685.004","name":"Disable or Modify Linux Audit System Log"},{"id":"T1685.005","name":"Clear Windows Event Logs"},{"id":"T1685.006","name":"Clear Linux or Mac System Logs"}]},{"id":"T1688","name":"Safe Mode Boot","subs":[]},{"id":"T1484","name":"Domain or Tenant Policy Modification","subs":[{"id":"T1484.001","name":"Group Policy Modification"},{"id":"T1484.002","name":"Trust Modification"}]},{"id":"T1686","name":"Disable or Modify System Firewall","subs":[{"id":"T1686.001","name":"Cloud Firewall"},{"id":"T1686.002","name":"Network Device Firewall"},{"id":"T1686.003","name":"Windows Host Firewall"}]},{"id":"T1556","name":"Modify Authentication Process","subs":[{"id":"T1556.001","name":"Domain Controller Authentication"},{"id":"T1556.002","name":"Password Filter DLL"},{"id":"T1556.003","name":"Pluggable Authentication Modules"},{"id":"T1556.004","name":"Network Device Authentication"},{"id":"T1556.005","name":"Reversible Encryption"},{"id":"T1556.006","name":"Multi-Factor Authentication"},{"id":"T1556.007","name":"Hybrid Identity"},{"id":"T1556.008","name":"Network Provider DLL"},{"id":"T1556.009","name":"Conditional Access Policies"}]}]},{"id":"TA0006","order":9,"name":"Credential Access","src":"TA0006","techniques":[{"id":"T1557","name":"Adversary-in-the-Middle","subs":[{"id":"T1557.001","name":"Name Resolution Poisoning and SMB Relay"},{"id":"T1557.002","name":"ARP Cache Poisoning"},{"id":"T1557.003","name":"DHCP Spoofing"},{"id":"T1557.004","name":"Evil Twin"}]},{"id":"T1003","name":"OS Credential Dumping","subs":[{"id":"T1003.001","name":"LSASS Memory"},{"id":"T1003.002","name":"Security Account Manager"},{"id":"T1003.003","name":"NTDS"},{"id":"T1003.004","name":"LSA Secrets"},{"id":"T1003.005","name":"Cached Domain Credentials"},{"id":"T1003.006","name":"DCSync"},{"id":"T1003.007","name":"Proc Filesystem"},{"id":"T1003.008","name":"/etc/passwd and /etc/shadow"}]},{"id":"T1539","name":"Steal Web Session Cookie","subs":[]},{"id":"T1040","name":"Network Sniffing","subs":[]},{"id":"T1558","name":"Steal or Forge Kerberos Tickets","subs":[{"id":"T1558.001","name":"Golden Ticket"},{"id":"T1558.002","name":"Silver Ticket"},{"id":"T1558.003","name":"Kerberoasting"},{"id":"T1558.004","name":"AS-REP Roasting"},{"id":"T1558.005","name":"Ccache Files"}]},{"id":"T1555","name":"Credentials from Password Stores","subs":[{"id":"T1555.001","name":"Keychain"},{"id":"T1555.002","name":"Securityd Memory"},{"id":"T1555.003","name":"Credentials from Web Browsers"},{"id":"T1555.004","name":"Windows Credential Manager"},{"id":"T1555.005","name":"Password Managers"},{"id":"T1555.006","name":"Cloud Secrets Management Stores"}]},{"id":"T1552","name":"Unsecured Credentials","subs":[{"id":"T1552.001","name":"Credentials In Files"},{"id":"T1552.002","name":"Credentials in Registry"},{"id":"T1552.003","name":"Shell History"},{"id":"T1552.004","name":"Private Keys"},{"id":"T1552.005","name":"Cloud Instance Metadata API"},{"id":"T1552.006","name":"Group Policy Preferences"},{"id":"T1552.007","name":"Container API"},{"id":"T1552.008","name":"Chat Messages"}]},{"id":"T1649","name":"Steal or Forge Authentication Certificates","subs":[]},{"id":"T1528","name":"Steal Application Access Token","subs":[]},{"id":"T1606","name":"Forge Web Credentials","subs":[{"id":"T1606.001","name":"Web Cookies"},{"id":"T1606.002","name":"SAML Tokens"}]},{"id":"T1621","name":"Multi-Factor Authentication Request Generation","subs":[]},{"id":"T1212","name":"Exploitation for Credential Access","subs":[]},{"id":"T1110","name":"Brute Force","subs":[{"id":"T1110.001","name":"Password Guessing"},{"id":"T1110.002","name":"Password Cracking"},{"id":"T1110.003","name":"Password Spraying"},{"id":"T1110.004","name":"Credential Stuffing"}]},{"id":"T1187","name":"Forced Authentication","subs":[]},{"id":"T1056","name":"Input Capture","subs":[{"id":"T1056.001","name":"Keylogging"},{"id":"T1056.002","name":"GUI Input Capture"},{"id":"T1056.003","name":"Web Portal Capture"},{"id":"T1056.004","name":"Credential API Hooking"}]},{"id":"T1111","name":"Multi-Factor Authentication Interception","subs":[]},{"id":"T1556","name":"Modify Authentication Process","subs":[{"id":"T1556.001","name":"Domain Controller Authentication"},{"id":"T1556.002","name":"Password Filter DLL"},{"id":"T1556.003","name":"Pluggable Authentication Modules"},{"id":"T1556.004","name":"Network Device Authentication"},{"id":"T1556.005","name":"Reversible Encryption"},{"id":"T1556.006","name":"Multi-Factor Authentication"},{"id":"T1556.007","name":"Hybrid Identity"},{"id":"T1556.008","name":"Network Provider DLL"},{"id":"T1556.009","name":"Conditional Access Policies"}]}]},{"id":"TA0007","order":10,"name":"Discovery","src":"TA0007","techniques":[{"id":"T1033","name":"System Owner/User Discovery","subs":[]},{"id":"T1613","name":"Container and Resource Discovery","subs":[]},{"id":"T1069","name":"Permission Groups Discovery","subs":[{"id":"T1069.001","name":"Local Groups"},{"id":"T1069.002","name":"Domain Groups"},{"id":"T1069.003","name":"Cloud Groups"}]},{"id":"T1615","name":"Group Policy Discovery","subs":[]},{"id":"T1652","name":"Device Driver Discovery","subs":[]},{"id":"T1007","name":"System Service Discovery","subs":[]},{"id":"T1040","name":"Network Sniffing","subs":[]},{"id":"T1135","name":"Network Share Discovery","subs":[]},{"id":"T1120","name":"Peripheral Device Discovery","subs":[]},{"id":"T1082","name":"System Information Discovery","subs":[]},{"id":"T1010","name":"Application Window Discovery","subs":[]},{"id":"T1580","name":"Cloud Infrastructure Discovery","subs":[]},{"id":"T1217","name":"Browser Information Discovery","subs":[]},{"id":"T1673","name":"Virtual Machine Discovery","subs":[]},{"id":"T1016","name":"System Network Configuration Discovery","subs":[{"id":"T1016.001","name":"Internet Connection Discovery"},{"id":"T1016.002","name":"Wi-Fi Discovery"}]},{"id":"T1087","name":"Account Discovery","subs":[{"id":"T1087.001","name":"Local Account"},{"id":"T1087.002","name":"Domain Account"},{"id":"T1087.003","name":"Email Account"},{"id":"T1087.004","name":"Cloud Account"}]},{"id":"T1482","name":"Domain Trust Discovery","subs":[]},{"id":"T1083","name":"File and Directory Discovery","subs":[]},{"id":"T1049","name":"System Network Connections Discovery","subs":[]},{"id":"T1497","name":"Virtualization/Sandbox Evasion","subs":[{"id":"T1497.001","name":"System Checks"},{"id":"T1497.002","name":"User Activity Based Checks"},{"id":"T1497.003","name":"Time Based Checks"}]},{"id":"T1619","name":"Cloud Storage Object Discovery","subs":[]},{"id":"T1654","name":"Log Enumeration","subs":[]},{"id":"T1057","name":"Process Discovery","subs":[]},{"id":"T1201","name":"Password Policy Discovery","subs":[]},{"id":"T1012","name":"Query Registry","subs":[]},{"id":"T1614","name":"System Location Discovery","subs":[{"id":"T1614.001","name":"System Language Discovery"}]},{"id":"T1526","name":"Cloud Service Discovery","subs":[]},{"id":"T1018","name":"Remote System Discovery","subs":[]},{"id":"T1046","name":"Network Service Discovery","subs":[]},{"id":"T1518","name":"Software Discovery","subs":[{"id":"T1518.001","name":"Security Software Discovery"},{"id":"T1518.002","name":"Backup Software Discovery"}]},{"id":"T1538","name":"Cloud Service Dashboard","subs":[]},{"id":"T1622","name":"Debugger Evasion","subs":[]},{"id":"T1680","name":"Local Storage Discovery","subs":[]},{"id":"T1124","name":"System Time Discovery","subs":[]}]},{"id":"TA0008","order":11,"name":"Lateral Movement","src":"TA0008","techniques":[{"id":"T1080","name":"Taint Shared Content","subs":[]},{"id":"T1091","name":"Replication Through Removable Media","subs":[]},{"id":"T1550","name":"Use Alternate Authentication Material","subs":[{"id":"T1550.001","name":"Application Access Token"},{"id":"T1550.002","name":"Pass the Hash"},{"id":"T1550.003","name":"Pass the Ticket"},{"id":"T1550.004","name":"Web Session Cookie"}]},{"id":"T1021","name":"Remote Services","subs":[{"id":"T1021.001","name":"Remote Desktop Protocol"},{"id":"T1021.002","name":"SMB/Windows Admin Shares"},{"id":"T1021.003","name":"Distributed Component Object Model"},{"id":"T1021.004","name":"SSH"},{"id":"T1021.005","name":"VNC"},{"id":"T1021.006","name":"Windows Remote Management"},{"id":"T1021.007","name":"Cloud Services"},{"id":"T1021.008","name":"Direct Cloud VM Connections"}]},{"id":"T1563","name":"Remote Service Session Hijacking","subs":[{"id":"T1563.001","name":"SSH Hijacking"},{"id":"T1563.002","name":"RDP Hijacking"}]},{"id":"T1072","name":"Software Deployment Tools","subs":[]},{"id":"T1210","name":"Exploitation of Remote Services","subs":[]},{"id":"T1534","name":"Internal Spearphishing","subs":[]},{"id":"T1570","name":"Lateral Tool Transfer","subs":[]}]},{"id":"TA0009","order":12,"name":"Collection","src":"TA0009","techniques":[{"id":"T1113","name":"Screen Capture","subs":[]},{"id":"T1557","name":"Adversary-in-the-Middle","subs":[{"id":"T1557.001","name":"Name Resolution Poisoning and SMB Relay"},{"id":"T1557.002","name":"ARP Cache Poisoning"},{"id":"T1557.003","name":"DHCP Spoofing"},{"id":"T1557.004","name":"Evil Twin"}]},{"id":"T1602","name":"Data from Configuration Repository","subs":[{"id":"T1602.001","name":"SNMP (MIB Dump)"},{"id":"T1602.002","name":"Network Device Configuration Dump"}]},{"id":"T1123","name":"Audio Capture","subs":[]},{"id":"T1114","name":"Email Collection","subs":[{"id":"T1114.001","name":"Local Email Collection"},{"id":"T1114.002","name":"Remote Email Collection"},{"id":"T1114.003","name":"Email Forwarding Rule"}]},{"id":"T1025","name":"Data from Removable Media","subs":[]},{"id":"T1119","name":"Automated Collection","subs":[]},{"id":"T1115","name":"Clipboard Data","subs":[]},{"id":"T1530","name":"Data from Cloud Storage","subs":[]},{"id":"T1005","name":"Data from Local System","subs":[]},{"id":"T1560","name":"Archive Collected Data","subs":[{"id":"T1560.001","name":"Archive via Utility"},{"id":"T1560.002","name":"Archive via Library"},{"id":"T1560.003","name":"Archive via Custom Method"}]},{"id":"T1185","name":"Browser Session Hijacking","subs":[]},{"id":"T1125","name":"Video Capture","subs":[]},{"id":"T1074","name":"Data Staged","subs":[{"id":"T1074.001","name":"Local Data Staging"},{"id":"T1074.002","name":"Remote Data Staging"}]},{"id":"T1039","name":"Data from Network Shared Drive","subs":[]},{"id":"T1056","name":"Input Capture","subs":[{"id":"T1056.001","name":"Keylogging"},{"id":"T1056.002","name":"GUI Input Capture"},{"id":"T1056.003","name":"Web Portal Capture"},{"id":"T1056.004","name":"Credential API Hooking"}]},{"id":"T1213","name":"Data from Information Repositories","subs":[{"id":"T1213.001","name":"Confluence"},{"id":"T1213.002","name":"Sharepoint"},{"id":"T1213.003","name":"Code Repositories"},{"id":"T1213.004","name":"Customer Relationship Management Software"},{"id":"T1213.005","name":"Messaging Applications"},{"id":"T1213.006","name":"Databases"}]}]},{"id":"TA0011","order":13,"name":"Command and Control","src":"TA0011","techniques":[{"id":"T1071","name":"Application Layer Protocol","subs":[{"id":"T1071.001","name":"Web Protocols"},{"id":"T1071.002","name":"File Transfer Protocols"},{"id":"T1071.003","name":"Mail Protocols"},{"id":"T1071.004","name":"DNS"},{"id":"T1071.005","name":"Publish/Subscribe Protocols"}]},{"id":"T1219","name":"Remote Access Tools","subs":[{"id":"T1219.001","name":"IDE Tunneling"},{"id":"T1219.002","name":"Remote Desktop Software"},{"id":"T1219.003","name":"Remote Access Hardware"}]},{"id":"T1659","name":"Content Injection","subs":[]},{"id":"T1205","name":"Traffic Signaling","subs":[{"id":"T1205.001","name":"Port Knocking"},{"id":"T1205.002","name":"Socket Filters"}]},{"id":"T1572","name":"Protocol Tunneling","subs":[]},{"id":"T1092","name":"Communication Through Removable Media","subs":[]},{"id":"T1090","name":"Proxy","subs":[{"id":"T1090.001","name":"Internal Proxy"},{"id":"T1090.002","name":"External Proxy"},{"id":"T1090.003","name":"Multi-hop Proxy"},{"id":"T1090.004","name":"Domain Fronting"}]},{"id":"T1568","name":"Dynamic Resolution","subs":[{"id":"T1568.001","name":"Fast Flux DNS"},{"id":"T1568.002","name":"Domain Generation Algorithms"},{"id":"T1568.003","name":"DNS Calculation"}]},{"id":"T1102","name":"Web Service","subs":[{"id":"T1102.001","name":"Dead Drop Resolver"},{"id":"T1102.002","name":"Bidirectional Communication"},{"id":"T1102.003","name":"One-Way Communication"}]},{"id":"T1104","name":"Multi-Stage Channels","subs":[]},{"id":"T1001","name":"Data Obfuscation","subs":[{"id":"T1001.001","name":"Junk Data"},{"id":"T1001.002","name":"Steganography"},{"id":"T1001.003","name":"Protocol or Service Impersonation"}]},{"id":"T1571","name":"Non-Standard Port","subs":[]},{"id":"T1573","name":"Encrypted Channel","subs":[{"id":"T1573.001","name":"Symmetric Cryptography"},{"id":"T1573.002","name":"Asymmetric Cryptography"}]},{"id":"T1095","name":"Non-Application Layer Protocol","subs":[]},{"id":"T1132","name":"Data Encoding","subs":[{"id":"T1132.001","name":"Standard Encoding"},{"id":"T1132.002","name":"Non-Standard Encoding"}]},{"id":"T1105","name":"Ingress Tool Transfer","subs":[]},{"id":"T1665","name":"Hide Infrastructure","subs":[]},{"id":"T1008","name":"Fallback Channels","subs":[]}]},{"id":"TA0010","order":14,"name":"Exfiltration","src":"TA0010","techniques":[{"id":"T1567","name":"Exfiltration Over Web Service","subs":[{"id":"T1567.001","name":"Exfiltration to Code Repository"},{"id":"T1567.002","name":"Exfiltration to Cloud Storage"},{"id":"T1567.003","name":"Exfiltration to Text Storage Sites"},{"id":"T1567.004","name":"Exfiltration Over Webhook"}]},{"id":"T1029","name":"Scheduled Transfer","subs":[]},{"id":"T1011","name":"Exfiltration Over Other Network Medium","subs":[{"id":"T1011.001","name":"Exfiltration Over Bluetooth"}]},{"id":"T1020","name":"Automated Exfiltration","subs":[{"id":"T1020.001","name":"Traffic Duplication"}]},{"id":"T1041","name":"Exfiltration Over C2 Channel","subs":[]},{"id":"T1048","name":"Exfiltration Over Alternative Protocol","subs":[{"id":"T1048.001","name":"Exfiltration Over Symmetric Encrypted Non-C2 Protocol"},{"id":"T1048.002","name":"Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"},{"id":"T1048.003","name":"Exfiltration Over Unencrypted Non-C2 Protocol"}]},{"id":"T1030","name":"Data Transfer Size Limits","subs":[]},{"id":"T1537","name":"Transfer Data to Cloud Account","subs":[]},{"id":"T1052","name":"Exfiltration Over Physical Medium","subs":[{"id":"T1052.001","name":"Exfiltration over USB"}]}]},{"id":"TA0040","order":15,"name":"Impact","src":"TA0040","techniques":[{"id":"T1561","name":"Disk Wipe","subs":[{"id":"T1561.001","name":"Disk Content Wipe"},{"id":"T1561.002","name":"Disk Structure Wipe"}]},{"id":"T1489","name":"Service Stop","subs":[]},{"id":"T1491","name":"Defacement","subs":[{"id":"T1491.001","name":"Internal Defacement"},{"id":"T1491.002","name":"External Defacement"}]},{"id":"T1657","name":"Financial Theft","subs":[]},{"id":"T1565","name":"Data Manipulation","subs":[{"id":"T1565.001","name":"Stored Data Manipulation"},{"id":"T1565.002","name":"Transmitted Data Manipulation"},{"id":"T1565.003","name":"Runtime Data Manipulation"}]},{"id":"T1531","name":"Account Access Removal","subs":[]},{"id":"T1486","name":"Data Encrypted for Impact","subs":[]},{"id":"T1667","name":"Email Bombing","subs":[]},{"id":"T1499","name":"Endpoint Denial of Service","subs":[{"id":"T1499.001","name":"OS Exhaustion Flood"},{"id":"T1499.002","name":"Service Exhaustion Flood"},{"id":"T1499.003","name":"Application Exhaustion Flood"},{"id":"T1499.004","name":"Application or System Exploitation"}]},{"id":"T1496","name":"Resource Hijacking","subs":[{"id":"T1496.001","name":"Compute Hijacking"},{"id":"T1496.002","name":"Bandwidth Hijacking"},{"id":"T1496.003","name":"SMS Pumping"},{"id":"T1496.004","name":"Cloud Service Hijacking"}]},{"id":"T1485","name":"Data Destruction","subs":[{"id":"T1485.001","name":"Lifecycle-Triggered Deletion"}]},{"id":"T1498","name":"Network Denial of Service","subs":[{"id":"T1498.001","name":"Direct Network Flood"},{"id":"T1498.002","name":"Reflection Amplification"}]},{"id":"T1495","name":"Firmware Corruption","subs":[]},{"id":"T1490","name":"Inhibit System Recovery","subs":[]},{"id":"T1529","name":"System Shutdown/Reboot","subs":[]}]}]};

var CODE_VERSION = 'v31-20261106';          // muda a cada alteração de lógica
var RULE_CACHE_KEY = 'coverage_' + CODE_VERSION; // chave carimbada -> versões não se misturam
var CACHE_TTL_SEC = 30 * 60; // 30 min (alinhado ao auto-reload da página)

function props_() { return PropertiesService.getScriptProperties(); }

/** Busca todas as regras de detecção do Elastic (paginado). */
function fetchRules_() {
  var p = props_();
  var base = p.getProperty('KIBANA_URL');
  var apiKey = p.getProperty('ES_API_KEY');
  var space = p.getProperty('KIBANA_SPACE');
  if (!base || !apiKey) throw new Error('Defina KIBANA_URL e ES_API_KEY nas Propriedades do script.');
  var prefix = (space && space !== 'default') ? ('/s/' + space) : '';
  var perPage = 200, page = 1, all = [], total = Infinity;
  var headers = { 'Authorization': 'ApiKey ' + apiKey, 'kbn-xsrf': 'true', 'Content-Type': 'application/json' };
  while (all.length < total) {
    var url = base + prefix + '/api/detection_engine/rules/_find?per_page=' + perPage + '&page=' + page;
    var res = UrlFetchApp.fetch(url, { method: 'get', headers: headers, muteHttpExceptions: true });
    var code = res.getResponseCode();
    if (code !== 200) throw new Error('Elastic HTTP ' + code + ': ' + res.getContentText().slice(0, 300));
    var body = JSON.parse(res.getContentText());
    total = body.total || 0;
    (body.data || []).forEach(function (r) { all.push(r); });
    if (!body.data || body.data.length === 0) break;
    page++;
    if (page > 100) break; // trava de segurança
  }
  return all;
}

/** DIAGNÓSTICO — rode no editor (selecione debugMonth -> Executar) e veja o Registro de execução. */
function debugMonth() {
  var rules = fetchRules_();
  var now = new Date(), cy = now.getUTCFullYear(), cm = now.getUTCMonth();
  var withDate = 0, matches = 0, noField = 0, sample = [];
  rules.forEach(function (r) {
    if (!r.created_at) { noField++; return; }
    withDate++;
    var c = new Date(r.created_at);
    if (c.getUTCFullYear() === cy && c.getUTCMonth() === cm) matches++;
    sample.push({ n: r.name, e: r.enabled, d: r.created_at });
  });
  sample.sort(function (a, b) { return (b.d || '').localeCompare(a.d || ''); });
  Logger.log('Mês atual (UTC): %s-%s', cy, ('0' + (cm + 1)).slice(-2));
  Logger.log('Total regras: %s | com created_at: %s | sem o campo: %s', rules.length, withDate, noField);
  Logger.log('>> Criadas no mês atual: %s', matches);
  Logger.log('10 mais recentes (created_at | enabled | nome):');
  sample.slice(0, 10).forEach(function (s) { Logger.log('  %s | %s | %s', s.d, s.e, s.n); });
  return matches;
}

/** Calcula a cobertura (regras HABILITADAS) contra o catálogo. */
function computeCoverage_(rules) {
  // Mês corrente no fuso do Brasil (não UTC) — "mês" = mês do calendário local.
  var _curYM = Utilities.formatDate(new Date(), 'America/Sao_Paulo', 'yyyy-MM');
  var _ymBR = function (d) { return Utilities.formatDate(d, 'America/Sao_Paulo', 'yyyy-MM'); };
  var isSept = function (r) {
    var c = r.created_at ? new Date(r.created_at) : null;
    return !!(c && _ymBR(c) === _curYM);
  };
  // índice: cov[srcTid][techId] = {gen:Set, subs:{subId:Set}, gensep, subsep:{}}
  var cov = {};
  function slot(tid, tech) {
    cov[tid] = cov[tid] || {};
    cov[tid][tech] = cov[tid][tech] || { gen: {}, subs: {}, gensep: false, subsep: {} };
    return cov[tid][tech];
  }
  rules.forEach(function (r) {
    if (!r.enabled) return;
    var nm = r.name, sp = isSept(r);
    (r.threat || []).forEach(function (th) {
      if (!th.tactic) return;
      var tid = th.tactic.id;
      (th.technique || []).forEach(function (tech) {
        var s = slot(tid, tech.id);
        if (tech.subtechnique && tech.subtechnique.length) {
          tech.subtechnique.forEach(function (su) {
            s.subs[su.id] = s.subs[su.id] || {};
            s.subs[su.id][nm] = 1;
            if (sp) s.subsep[su.id] = true;
          });
        } else {
          s.gen[nm] = 1;
          if (sp) s.gensep = true;
        }
      });
    });
  });
  function keys(o) { return o ? Object.keys(o) : []; }

  var out = { tactics: [] }, allTech = {}, allSub = {};
  CATALOG.tactics.forEach(function (t) {
    var techs = [];
    t.techniques.forEach(function (te) {
      var c = (cov[t.src] && cov[t.src][te.id]) ? cov[t.src][te.id] : null;
      var gen = c ? keys(c.gen) : [];
      var scov = c ? c.subs : {};
      var ncov = 0;
      var subs = te.subs.map(function (s) {
        var rl = keys(scov[s.id] || {});
        if (rl.length) ncov++;
        return { id: s.id, name: s.name, cov: rl.length > 0, rules: rl.slice(0, 6),
                 sep: !!(c && c.subsep[s.id]) };
      });
      var ntot = te.subs.length, has = gen.length > 0 || keys(scov).length > 0;
      var status = (ntot === 0 && has) ? 'existing'
        : (ntot > 0 && ncov >= ntot && ncov > 0) ? 'existing'
        : (ntot > 0 && ncov > 0) ? 'partial' : 'none';
      var sepAny = !!(c && (c.gensep || Object.keys(c.subsep).length > 0));
      techs.push({ id: te.id, name: te.name, status: status, st: ntot, sc: ncov,
                   sep: sepAny, gen: gen.slice(0, 6), subs: subs });
    });
    var tcov = techs.filter(function (x) { return x.status !== 'none'; }).length;
    out.tactics.push({ id: t.id, name: t.name, tech_total: techs.length, tech_cov: tcov, techniques: techs });
  });

  // distintos p/ os KPIs
  var dTech = {}, dSub = {}, enabled = 0;
  rules.forEach(function (r) {
    if (!r.enabled) return; enabled++;
    (r.threat || []).forEach(function (th) {
      (th.technique || []).forEach(function (tech) {
        dTech[tech.id] = 1;
        (tech.subtechnique || []).forEach(function (su) { dSub[su.id] = 1; });
      });
    });
  });
  var totTech = 0, totSub = 0;
  CATALOG.tactics.forEach(function (t) {
    t.techniques.forEach(function (te) { });
  });
  // universo do catálogo (técnicas/subs distintas)
  var uT = {}, uS = {};
  CATALOG.tactics.forEach(function (t) {
    t.techniques.forEach(function (te) { uT[te.id] = 1; te.subs.forEach(function (s) { uS[s.id] = 1; }); });
  });
  function inter(a, b) { return Object.keys(a).filter(function (k) { return b[k]; }).length; }
  // Casos do mês = SUAS regras (custom) criadas no mês corrente (BRT).
  // Custom = immutable:false OU rule_source.type == "internal". Prebuilt do Elastic
  // (immutable:true / "external") NUNCA conta, habilitada ou não.
  var _isCustom = function (r) {
    if (r.immutable === true) return false;
    if (r.rule_source && r.rule_source.type === 'external') return false;
    if (r.immutable === false) return true;
    if (r.rule_source && r.rule_source.type === 'internal') return true;
    return true; // sem os campos: assume custom (fallback)
  };
  // Histograma mês a mês das SUAS regras (custom) criadas, agrupadas por mês BRT.
  var _MN = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];
  var _mlabel = function (ym) { var p = ym.split('-'); return _MN[(+p[1]) - 1] + '/' + p[0]; };
  var byMonth = {}; // ym -> [ {name,type,created,ym,maps} ]
  rules.forEach(function (r) {
    if (!r.enabled) return;
    if (!_isCustom(r)) return;
    var c = r.created_at ? new Date(r.created_at) : null;
    if (!c) return;
    var ym = _ymBR(c);
    var maps = [];
    (r.threat || []).forEach(function (th) {
      if (!th.tactic) return;
      (th.technique || []).forEach(function (tech) {
        maps.push({
          tactic: th.tactic.name || th.tactic.id,
          tech: tech.id + (tech.name ? ' ' + tech.name : ''),
          subs: (tech.subtechnique || []).map(function (s) { return s.id + (s.name ? ' ' + s.name : ''); })
        });
      });
    });
    (byMonth[ym] || (byMonth[ym] = [])).push({
      name: r.name, type: r.type, ym: ym,
      created: Utilities.formatDate(c, 'America/Sao_Paulo', 'dd/MM/yyyy'), maps: maps
    });
  });
  var _months = Object.keys(byMonth).sort();
  var created_by_month = _months.map(function (ym) { return { ym: ym, label: _mlabel(ym), count: byMonth[ym].length }; });
  var septRules = byMonth[_curYM] || [];

  out.summary = {
    rules_enabled: enabled,
    dist_tech_cov: inter(dTech, uT), dist_tech_total: Object.keys(uT).length,
    dist_sub_cov: inter(dSub, uS), dist_sub_total: Object.keys(uS).length,
    updated: Utilities.formatDate(new Date(), 'America/Sao_Paulo', "dd/MM/yyyy HH:mm"),
    month_label: Utilities.formatDate(new Date(), 'America/Sao_Paulo', 'MM/yyyy'),
    cur_ym: _curYM,
    created_month_count: septRules.length,
    sept_rules: septRules,
    created_by_month: created_by_month,
    created_month_rules: byMonth
  };
  return out;
}

/** Cache fragmentado (limite de ~100KB por chave no CacheService). */
var CHUNK = 90000;
function putChunked_(cache, str) {
  var n = Math.ceil(str.length / CHUNK), parts = {};
  for (var i = 0; i < n; i++) parts[RULE_CACHE_KEY + '_' + i] = str.substr(i * CHUNK, CHUNK);
  parts[RULE_CACHE_KEY + '_n'] = String(n);
  cache.putAll(parts, CACHE_TTL_SEC);
}
function getChunked_(cache) {
  var nStr = cache.get(RULE_CACHE_KEY + '_n');
  if (!nStr) return null;
  var n = parseInt(nStr, 10), ids = [];
  for (var i = 0; i < n; i++) ids.push(RULE_CACHE_KEY + '_' + i);
  var got = cache.getAll(ids), out = '';
  for (var j = 0; j < n; j++) { var s = got[RULE_CACHE_KEY + '_' + j]; if (s == null) return null; out += s; }
  return out;
}

/** Retorna cobertura (usa cache fragmentado; recalcula se expirado). */
function getCoverage_(forceRefresh) {
  var cache = CacheService.getScriptCache();
  if (!forceRefresh) {
    var hit = getChunked_(cache);
    if (hit) {
      try {
        var obj = JSON.parse(hit);
        if (obj && obj.code_version === CODE_VERSION) return obj; // só aceita cache da MESMA versão
      } catch (e) {}
    }
  }
  var data = computeCoverage_(fetchRules_());
  data.code_version = CODE_VERSION;
  try { putChunked_(cache, JSON.stringify(data)); } catch (e) {}
  return data;
}

/** Gatilho de tempo: aquece o cache. */
function refreshCache() { getCoverage_(true); }

/**
 * Controle de acesso SEM edição de código:
 *  - Defina em Propriedades do script UMA das duas:
 *      ALLOWED_GROUP  = soc-panel@example.com   (grupo do Google; gerencie o time pelo grupo)
 *      ALLOWED_EMAILS = a@example.com,b@example.com  (lista fixa, separada por vírgula)
 *  - Se nenhuma estiver definida, mantém o comportamento atual (qualquer pessoa na organização).
 *  Depois de definido, o acesso é gerido pelo grupo/propriedade — nunca mais pelo código.
 */
// Comparação EXATA de e-mail (ponto é significativo na organização), mas robusta contra
// lixo de colagem: minúsculas, remove zero-width/nbsp, mailto:, < >, aspas e espaços.
function _normEmail_(e) {
  return (e || '')
    .replace(/[​-‍﻿ ]/g, '') // zero-width + non-breaking space
    .replace(/^mailto:/i, '')
    .replace(/[<>"']/g, '')
    .trim()
    .toLowerCase();
}

function isAuthorized_() {
  var p = props_();
  var group = (p.getProperty('ALLOWED_GROUP') || '').trim();
  var email = _normEmail_(Session.getActiveUser().getEmail());
  // Modo planilha "Acessos" (padrão a partir da v16). ACCESS_MODE=legacy força o modo antigo.
  if ((p.getProperty('ACCESS_MODE') || '').toLowerCase() !== 'legacy') {
    var mem = null;
    try { mem = accMembers_(); } catch (e) { mem = null; console.error('isAuthorized_: planilha de Acessos indisponível, usando regra antiga: ' + e); }
    if (mem && mem.length) {
      if (!email) return false;
      var me = accFindUser_(mem, email);
      if (me) return me.ativo;              // cadastro manda: desativado = bloqueado
      if (group) { try { if (GroupsApp.getGroupByEmail(group).hasUser(email)) return true; } catch (e) {} }
      return false;
    }
  }
  return isAuthorizedLegacy_(email, group);
}

/* Regra antiga (ALLOWED_EMAILS / ALLOWED_GROUP). Usada só se a planilha estiver indisponível. */
function isAuthorizedLegacy_(email, group) {
  var p = props_();
  var list = (p.getProperty('ALLOWED_EMAILS') || '').trim();
  if (!group && !list) return true; // não configurado -> não bloqueia (evita se trancar)
  if (!email) return false; // deploy não expõe o e-mail (ver whoami)
  if (list) {
    var allow = list.split(/[,;\s]+/).map(_normEmail_).filter(String);
    if (allow.indexOf(email) !== -1) return true;
  }
  if (group) {
    try { if (GroupsApp.getGroupByEmail(group).hasUser(email)) return true; } catch (e) {}
  }
  return false;
}

/* ================== FLUXO DE SOLICITAÇÃO / APROVAÇÃO DE ACESSO ==================
 * Propriedades do script:
 *   APPROVER_EMAILS = john.doe@example.com,jane.roe@example.com
 *      (quem pode aprovar; se vazio, cai em ALLOWED_EMAILS como aprovadores)
 * Fluxo:
 *   1. Barrado clica "Solicitar acesso" -> requestAccess() guarda pendência e e-maila o aprovador.
 *   2. Aprovador clica o link Aprovar/Negar do e-mail -> doGet(?approve|?deny=token).
 *   3. Ao aprovar, o e-mail é adicionado ao ALLOWED_EMAILS (runtime, sem redeploy).
 */
function _approvers_() {
  // Modo planilha: aprovadores = Admins ativos. Legado: APPROVER_EMAILS (ou ALLOWED_EMAILS).
  try {
    var adm = accMembers_().filter(function (m) { return m.ativo && m.papel === 'Admin'; }).map(function (m) { return m.email; });
    if (adm.length) return adm;
  } catch (e) {}
  var p = props_();
  var a = (p.getProperty('APPROVER_EMAILS') || p.getProperty('ALLOWED_EMAILS') || '');
  return a.split(/[,;\s]+/).map(_normEmail_).filter(String);
}
function _isApprover_(email) { return _approvers_().indexOf(_normEmail_(email)) !== -1; }

function _pendingAll_() {
  try { return JSON.parse(props_().getProperty('PENDING_REQUESTS') || '{}'); } catch (e) { return {}; }
}
function _pendingSave_(obj) { props_().setProperty('PENDING_REQUESTS', JSON.stringify(obj)); }

function _addEmailToAllowed_(email) {
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var p = props_();
    var cur = (p.getProperty('ALLOWED_EMAILS') || '').split(/[,;\s]+/).map(_normEmail_).filter(String);
    var e = _normEmail_(email);
    if (cur.indexOf(e) === -1) cur.push(e);
    p.setProperty('ALLOWED_EMAILS', cur.join(','));
  } finally { lock.releaseLock(); }
}

/** Chamado pela tela de bloqueio (google.script.run). Registra pendência e avisa o aprovador. */
function requestAccess(justificativa) {
  var requester = Session.getActiveUser().getEmail() || '';
  if (!requester) return { ok: false, msg: 'Não foi possível identificar seu e-mail (verifique o deploy). Fale com o responsável.' };
  if (isAuthorized_()) return { ok: false, msg: 'Você já tem acesso — recarregue a página.' };
  var approvers = _approvers_();
  if (!approvers.length) return { ok: false, msg: 'Nenhum aprovador configurado (defina APPROVER_EMAILS). Fale com o responsável.' };

  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var pend = _pendingAll_();
    // reaproveita pendência do mesmo e-mail
    for (var k in pend) { if (_normEmail_(pend[k].email) === _normEmail_(requester)) return { ok: true, msg: 'Sua solicitação já está pendente de aprovação.' }; }
    var token = Utilities.getUuid();
    pend[token] = { email: requester, just: (justificativa || '').slice(0, 300), ts: new Date().toISOString() };
    _pendingSave_(pend);
  } finally { lock.releaseLock(); }
  try { accAudit_(_normEmail_(requester), 'solicitar_acesso', _normEmail_(requester), (justificativa || '').slice(0, 300)); } catch (e) {}

  var base = ScriptApp.getService().getUrl();
  var approveUrl = base + '?approve=' + token;
  var denyUrl = base + '?deny=' + token;
  var subject = '[Painel SOC/CSIRT] Solicitação de acesso: ' + requester;
  var body = // fallback texto puro (clientes sem HTML)
    requester + ' solicitou acesso ao painel KPI SOC/CSIRT.\n\n' +
    (justificativa ? 'Justificativa: ' + justificativa + '\n\n' : '') +
    'APROVAR:  ' + approveUrl + '\n' +
    'REPROVAR: ' + denyUrl + '\n\n' +
    '(Só um aprovador autenticado consegue concluir a ação.)';
  var btn = function (url, label, color) {
    return '<a href="' + url + '" style="display:inline-block;background:' + color + ';color:#ffffff;' +
      'text-decoration:none;font:600 14px Segoe UI,Arial,sans-serif;padding:12px 26px;border-radius:8px;margin:0 8px">' + label + '</a>';
  };
  var esc = function (s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;'); };
  var htmlBody =
    '<div style="font-family:Segoe UI,Arial,sans-serif;color:#1B2733;max-width:560px;margin:auto">' +
    '<h2 style="margin:0 0 4px">Solicitação de acesso — Painel SOC/CSIRT</h2>' +
    '<p style="color:#5B6B78;margin:0 0 16px">Um usuário pediu acesso ao painel KPI.</p>' +
    '<table style="border-collapse:collapse;font-size:14px;margin-bottom:20px">' +
    '<tr><td style="color:#5B6B78;padding:2px 12px 2px 0">Solicitante</td><td><b>' + esc(requester) + '</b></td></tr>' +
    (justificativa ? '<tr><td style="color:#5B6B78;padding:2px 12px 2px 0;vertical-align:top">Justificativa</td><td>' + esc(justificativa) + '</td></tr>' : '') +
    '</table>' +
    '<div style="text-align:center;margin:24px 0">' + btn(approveUrl, '✓ Aprovar', '#2E7D32') + btn(denyUrl, '✕ Reprovar', '#C62828') + '</div>' +
    '<p style="color:#8A9BA8;font-size:12px;text-align:center">Ao aprovar, o e-mail é adicionado automaticamente à lista de acesso.<br>Só um aprovador autenticado da organização consegue concluir a ação.</p>' +
    '</div>';
  try { MailApp.sendEmail({ to: approvers.join(','), subject: subject, body: body, htmlBody: htmlBody }); }
  catch (e) { return { ok: false, msg: 'Falha ao enviar e-mail ao aprovador: ' + e.message }; }
  return { ok: true, msg: 'Solicitação enviada para aprovação. Você será avisado por e-mail quando for liberada.' };
}

/** Processa o clique do aprovador em Aprovar/Negar. */
function handleApproval_(e) {
  var page = function (title, msg, color) {
    return HtmlService.createHtmlOutput(
      '<div style="font-family:Segoe UI,system-ui,sans-serif;background:#0E1621;color:#E8EDF2;min-height:100vh;margin:0;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px">' +
      '<div style="max-width:560px"><h2 style="color:' + (color || '#E8EDF2') + '">' + title + '</h2>' +
      '<p style="color:#8A9BA8">' + msg + '</p></div></div>'
    ).setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  };
  var approver = Session.getActiveUser().getEmail() || '';
  if (!approver) return page('Não autenticado', 'Abra este link logado na conta de aprovador da organização.', '#F2C14E');
  if (!_isApprover_(approver)) return page('Sem permissão', 'Apenas aprovadores designados podem aprovar solicitações. Você entrou como ' + approver + '.', '#E5484D');

  var token = e.parameter.approve || e.parameter.deny;
  var isApprove = !!e.parameter.approve;
  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  var req;
  try {
    var pend = _pendingAll_();
    req = pend[token];
    if (!req) return page('Solicitação inválida', 'Este pedido não existe ou já foi processado.', '#F2C14E');
    delete pend[token];
    _pendingSave_(pend);
  } finally { lock.releaseLock(); }

  _decide_(req, isApprove, _normEmail_(approver), 'link do e-mail');
  if (isApprove) return page('Acesso aprovado ✅', req.email + ' foi adicionado como Membro. Aprovado por ' + approver + '.', '#46A758');
  return page('Solicitação negada', 'O pedido de ' + req.email + ' foi recusado.', '#E5484D');
}

/* Efeitos de aprovar/negar (usado pelo link do e-mail e pelo portal). */
function _decide_(req, approve, actor, via) {
  if (approve) {
    var ok = false;
    try { accUpsert_(req.email, '', 'Membro', true, actor, 'aprovar_acesso', via + (req.just ? ' · justificativa: ' + req.just : '')); ok = true; } catch (e) {}
    if (!ok) _addEmailToAllowed_(req.email); // planilha indisponível -> legado
    try { MailApp.sendEmail(req.email, '[Painel SOC/CSIRT] Acesso liberado', 'Seu acesso ao painel KPI SOC/CSIRT foi aprovado por ' + actor + '. Já pode acessar: ' + ScriptApp.getService().getUrl()); } catch (e2) {}
  } else {
    try { accAudit_(actor, 'negar_acesso', req.email, via); } catch (e) {}
    try { MailApp.sendEmail(req.email, '[Painel SOC/CSIRT] Solicitação de acesso negada', 'Sua solicitação de acesso ao painel foi negada por ' + actor + '. Fale com o time em caso de dúvida.'); } catch (e2) {}
  }
}

function denied_() {
  var raw = Session.getActiveUser().getEmail() || '';
  var esc = function (s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;'); };
  var canRequest = !!raw; // só oferece solicitar se o app enxerga o e-mail
  return HtmlService.createHtmlOutput(
    '<div style="font-family:Segoe UI,system-ui,sans-serif;background:#0E1621;color:#E8EDF2;min-height:100vh;margin:0;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px">' +
    '<div style="max-width:520px"><div style="font-size:44px">🔒</div><h2>Acesso restrito</h2>' +
    '<p style="color:#8A9BA8">Este painel é exclusivo do time de SOC/CSIRT.</p>' +
    (raw ? '<p style="color:#5C6B7A;font-size:13px">Você entrou como <b>' + esc(raw) + '</b></p>' :
           '<p style="color:#F2C14E;font-size:13px">O app não conseguiu identificar seu e-mail (verifique o deploy).</p>') +
    (canRequest ?
      '<textarea id="just" placeholder="Justificativa (opcional): por que precisa de acesso?" style="width:100%;box-sizing:border-box;margin-top:16px;background:#0A1119;border:1px solid #1E2A38;border-radius:8px;color:#E8EDF2;padding:10px;font:14px Segoe UI,sans-serif;min-height:64px"></textarea>' +
      '<button id="btn" style="margin-top:12px;background:#2F81F7;color:#fff;border:0;border-radius:8px;padding:12px 20px;font:600 14px Segoe UI,sans-serif;cursor:pointer">Solicitar acesso</button>' +
      '<div id="st" style="margin-top:14px;color:#8A9BA8;font-size:14px"></div>'
      : '') +
    '</div>' +
    '<script>' +
    'var b=document.getElementById("btn");' +
    'if(b){b.onclick=function(){b.disabled=true;b.textContent="Enviando…";' +
    'google.script.run.withSuccessHandler(function(r){document.getElementById("st").innerHTML=r.msg;' +
    'if(r.ok){b.style.display="none";}else{b.disabled=false;b.textContent="Solicitar acesso";}})' +
    '.withFailureHandler(function(e){document.getElementById("st").innerHTML="Erro: "+e.message;b.disabled=false;b.textContent="Solicitar acesso";})' +
    '.requestAccess(document.getElementById("just").value);};}' +
    '</script>'
  ).setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/* ================== GESTÃO DE ACESSO — planilha "Acessos" (v16) ==================
 * Fonte de verdade de quem acessa o portal, com papel e auditoria.
 *  - Na 1ª execução cria a planilha "KPI SOC/CSIRT — Acessos" no Drive do dono do script
 *    e grava o ID em ACCESS_SHEET_ID (ou defina ACCESS_SHEET_ID para usar uma planilha sua).
 *  - Migração automática: quem está em ALLOWED_EMAILS vira membro ativo; o dono do script e
 *    os aprovadores (APPROVER_EMAILS) viram Admin. Ninguém perde acesso.
 *  - Abas: "Membros" (email, nome, papel, ativo, idioma, tema, ...) e "Auditoria".
 *  - Admin: vê a Administração e aprova pedidos. Membro: só os dashboards.
 *  - Escape: ACCESS_MODE=legacy volta à regra antiga (ALLOWED_EMAILS/ALLOWED_GROUP).
 */
var ACC_TAB_M = 'Membros', ACC_TAB_A = 'Auditoria';
var ACC_HDR = ['email', 'nome', 'papel', 'ativo', 'idioma', 'tema', 'criado_em', 'criado_por', 'atualizado_em'];
var AUD_HDR = ['data_hora', 'ator', 'acao', 'alvo', 'detalhe'];
var ACC_CKEY = 'acc_members_v1', ACC_CTTL = 300; // cache de 5 min para a checagem de acesso
var ACC_EMAIL_RX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

function _me_() { return _normEmail_(Session.getActiveUser().getEmail()); }
function _bool_(v) { return v === true || /^(true|verdadeiro|sim|1|x)$/i.test(String(v).trim()); }
function _nameFromEmail_(e) {
  var l = String(e || '').split('@')[0].replace(/[._-]+/g, ' ').trim();
  return l.replace(/\b\w/g, function (c) { return c.toUpperCase(); });
}

/** Abre a planilha de acessos (cria na 1ª vez). Se ACCESS_SHEET_ID existe mas não abre, falha (não recria). */
function accSheet_() {
  var p = props_(), id = p.getProperty('ACCESS_SHEET_ID'), ss;
  if (id) {
    ss = SpreadsheetApp.openById(id); // lança se sem permissão -> isAuthorized_ cai no legado
  } else {
    var lock = LockService.getScriptLock(); lock.waitLock(15000);
    try {
      id = p.getProperty('ACCESS_SHEET_ID');
      if (id) ss = SpreadsheetApp.openById(id);
      else { ss = SpreadsheetApp.create('KPI SOC/CSIRT — Acessos'); p.setProperty('ACCESS_SHEET_ID', ss.getId()); }
    } finally { lock.releaseLock(); }
  }
  var m = ss.getSheetByName(ACC_TAB_M);
  if (!m) {
    m = ss.getSheets()[0]; m.setName(ACC_TAB_M);
    m.getRange(1, 1, 1, ACC_HDR.length).setValues([ACC_HDR]).setFontWeight('bold'); m.setFrozenRows(1);
  }
  var a = ss.getSheetByName(ACC_TAB_A);
  if (!a) {
    a = ss.insertSheet(ACC_TAB_A);
    a.getRange(1, 1, 1, AUD_HDR.length).setValues([AUD_HDR]).setFontWeight('bold'); a.setFrozenRows(1);
  }
  return { ss: ss, m: m, a: a };
}

/** Lê a aba Membros (sem cache). */
function accRead_(S) {
  S = S || accSheet_();
  var v = S.m.getDataRange().getValues(), out = [];
  for (var i = 1; i < v.length; i++) {
    var r = v[i]; if (!r[0]) continue;
    out.push({
      email: _normEmail_(r[0]), nome: String(r[1] || ''),
      papel: String(r[2]).trim().toLowerCase() === 'admin' ? 'Admin' : 'Membro',
      ativo: _bool_(r[3]), idioma: String(r[4] || ''), tema: String(r[5] || ''),
      criado_em: _fmtCell_(r[6]),
      criado_por: String(r[7] || ''), _row: i + 1
    });
  }
  return out;
}
function _fmtCell_(v) {
  if (!v) return '';
  try { var d = (v instanceof Date) ? v : new Date(v); if (!isNaN(d.getTime())) return Utilities.formatDate(d, 'America/Sao_Paulo', 'yyyy-MM-dd HH:mm'); } catch (e) {}
  return String(v);
}
function accFind_(list, email) { email = _normEmail_(email); for (var i = 0; i < list.length; i++) if (list[i].email === email) return list[i]; return null; }
/** E-mails da pessoa no diretório (principal + aliases). Cache 6h. Vazio se a People API não estiver ativa. */
function accDirEmails_(email) {
  email = _normEmail_(email);
  var c = CacheService.getScriptCache(), k = 'dire_' + Utilities.base64EncodeWebSafe(email).slice(0, 200);
  var hit = c.get(k); if (hit) { try { return JSON.parse(hit); } catch (e) {} }
  var out = { primary: '', all: [] };
  try {
    if (typeof People !== 'undefined' && email) {
      var r = People.People.searchDirectoryPeople({ query: email, readMask: 'emailAddresses', sources: ['DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE'], pageSize: 5 });
      (r && r.people || []).forEach(function (p) {
        var ems = (p.emailAddresses || []).map(function (x) { return { v: _normEmail_(x.value), pri: !!(x.metadata && x.metadata.primary) }; });
        if (ems.some(function (x) { return x.v === email; })) {
          out.all = ems.map(function (x) { return x.v; });
          var pr = ems.filter(function (x) { return x.pri; })[0];
          out.primary = pr ? pr.v : email;
        }
      });
    }
  } catch (e) { console.warn('accDirEmails_: ' + e); }
  try { c.put(k, JSON.stringify(out), 6 * 3600); } catch (e) {}
  return out;
}
/** Acha o cadastro da pessoa: e-mail exato ou qualquer alias dela no diretório. */
function accFindUser_(list, email) {
  var m = accFind_(list, email); if (m) return m;
  var al = accDirEmails_(email).all;
  for (var i = 0; i < al.length; i++) { m = accFind_(list, al[i]); if (m) return m; }
  return null;
}
/** Mantém ALLOWED_EMAILS = membros ativos (compatível com links/implantações antigas e com o fallback). */
function accSyncAllowed_() {
  try {
    var act = accRead_().filter(function (m) { return m.ativo; }).map(function (m) { return m.email; });
    if (act.length) props_().setProperty('ALLOWED_EMAILS', act.join(','));
  } catch (e) { console.warn('accSyncAllowed_: ' + e); }
}
function accInvalidate_() { try { CacheService.getScriptCache().remove(ACC_CKEY); } catch (e) {} }

/** Membros com cache (usado em toda checagem de acesso). Faz a migração na 1ª vez. */
function accMembers_() {
  var c = CacheService.getScriptCache(), hit = c.get(ACC_CKEY);
  if (hit) { try { return JSON.parse(hit); } catch (e) {} }
  var S = accSheet_(), list = accRead_(S);
  if (!list.length) { accSeed_(S); list = accRead_(S); }
  try { c.put(ACC_CKEY, JSON.stringify(list), ACC_CTTL); } catch (e) {}
  return list;
}

/** Migração: ALLOWED_EMAILS -> membros; dono + aprovadores -> Admin. */
function accSeed_(S) {
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    if (accRead_(S).length) return; // outro processo já semeou
    var p = props_(), split = function (s) { return (s || '').split(/[,;\s]+/).map(_normEmail_).filter(String); };
    var owner = _normEmail_(Session.getEffectiveUser().getEmail());
    var approvers = split(p.getProperty('APPROVER_EMAILS'));
    var allowed = split(p.getProperty('ALLOWED_EMAILS'));
    if (!approvers.length) approvers = allowed.slice(); // regra antiga: sem APPROVER_EMAILS, a lista aprovava
    var seen = {}, rows = [], now = new Date();
    var add = function (e, papel) {
      if (!e || seen[e]) return; seen[e] = 1;
      var nm = ''; try { nm = accDirectory_(e).name; } catch (x) {}
      rows.push([e, nm || _nameFromEmail_(e), papel, true, '', '', now, 'migração', now]);
    };
    if (owner) add(owner, 'Admin');
    approvers.forEach(function (e) { add(e, 'Admin'); });
    allowed.forEach(function (e) { add(e, 'Membro'); });
    if (rows.length) {
      S.m.getRange(2, 1, rows.length, ACC_HDR.length).setValues(rows);
      S.a.appendRow([now, owner || 'sistema', 'migracao', rows.length + ' membro(s)', 'ALLOWED_EMAILS/APPROVER_EMAILS -> planilha Acessos']);
    }
  } finally { lock.releaseLock(); }
}

function accAudit_(actor, acao, alvo, detalhe) {
  var S = accSheet_();
  S.a.appendRow([new Date(), actor || '', acao, alvo || '', detalhe || '']);
}

/** Cria ou atualiza um membro (usado na aprovação). */
function accUpsert_(email, nome, papel, ativo, actor, acao, detalhe) {
  email = _normEmail_(email);
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    var S = accSheet_(), list = accRead_(S), cur = accFind_(list, email), now = new Date();
    if (cur) {
      S.m.getRange(cur._row, 4).setValue(!!ativo);
      S.m.getRange(cur._row, 9).setValue(now);
    } else {
      if (!nome) { try { nome = accDirectory_(email).name; } catch (x) {} }
      S.m.appendRow([email, nome || _nameFromEmail_(email), papel || 'Membro', !!ativo, '', '', now, actor || '', now]);
    }
    S.a.appendRow([now, actor || '', acao || 'adicionar_membro', email, detalhe || '']);
  } finally { lock.releaseLock(); accInvalidate_(); }
  accSyncAllowed_();
}

/** Nome e foto do diretório do Google Workspace (People API, serviço avançado "People"). Cache 6h. */
function accDirectory_(email, nocache) {
  email = _normEmail_(email);
  var c = CacheService.getScriptCache(), k = 'dir_' + Utilities.base64EncodeWebSafe(email).slice(0, 200);
  if (!nocache) { var hit = c.get(k); if (hit) { try { return JSON.parse(hit); } catch (e) {} } }
  var out = { name: '', photo: '', photoUrl: '', dbg: '' };
  try {
    if (typeof People === 'undefined') { out.dbg = 'People API não ativada'; }
    else {
      var r = People.People.searchDirectoryPeople({
        query: email, readMask: 'names,photos,emailAddresses',
        sources: ['DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE'], pageSize: 5
      });
      var ps = (r && r.people) || [], pp = null;
      ps.forEach(function (x) { (x.emailAddresses || []).forEach(function (em) { if (_normEmail_(em.value) === email) pp = x; }); });
      if (!pp) { out.dbg = 'pessoa não encontrada no diretório'; }
      else {
        if (pp.names && pp.names.length) out.name = pp.names[0].displayName || '';
        var phs = pp.photos || [], ph = phs.filter(function (f) { return !f['default']; })[0], steps = [];
        steps.push('diretório: ' + (ph ? 'tem foto' : (phs.length ? 'só a foto padrão' : 'sem foto')));
        // Sem foto no diretório: tenta a foto do PERFIL da conta Google (é a que a pessoa vê no Gmail/Drive)
        if (!ph && pp.resourceName) {
          try {
            var full = People.People.get(pp.resourceName, { personFields: 'photos', sources: ['READ_SOURCE_TYPE_PROFILE', 'READ_SOURCE_TYPE_DOMAIN_CONTACT'] });
            var fp = (full && full.photos) || [];
            ph = fp.filter(function (f) { return !f['default']; })[0];
            steps.push('perfil da conta: ' + (ph ? 'tem foto' : (fp.length ? 'só a foto padrão' : 'sem foto')));
          } catch (e2) { steps.push('perfil da conta: erro ' + e2.message); }
        }
        if (!ph) { out.dbg = steps.join(' · '); }
        else {
          var url = /=s\d+(-c)?$/.test(ph.url) ? ph.url.replace(/=s\d+(-c)?$/, '=s96-c') : ph.url;
          out.photoUrl = url;
          var host = (url.match(/^https:\/\/([^\/?#]+)/) || [])[1] || '';
          var googleHost = /(^|\.)googleusercontent\.com$|(^|\.)google\.com$/.test(host);
          // 1º sem credencial; 2º com o token do dono do script (só para hosts de imagem do Google)
          var tries = [{}]; if (googleHost) tries.push({ Authorization: 'Bearer ' + ScriptApp.getOAuthToken() });
          var log = [];
          tries.some(function (h, n) {
            try {
              var resp = UrlFetchApp.fetch(url, { muteHttpExceptions: true, followRedirects: true, headers: h });
              var code = resp.getResponseCode(), b = resp.getBlob(), ct = String(b.getContentType() || '');
              log.push((n ? 'com token ' : 'sem token ') + code + ' ' + ct);
              if (code === 200 && /^image\//i.test(ct)) {
                out.photo = 'data:' + ct + ';base64,' + Utilities.base64Encode(b.getBytes()); return true;
              }
            } catch (e) { log.push((n ? 'com token ' : 'sem token ') + 'erro ' + e.message); }
            return false;
          });
          out.dbg = steps.join(' · ') + ' · download: ' + log.join(' | ');
        }
      }
    }
  } catch (e) { out.dbg = 'erro na People API: ' + e.message; }
  try { c.put(k, JSON.stringify(out), out.photo ? 6 * 3600 : 1800); } catch (e) {}
  return out;
}

/** DIAGNÓSTICO DA FOTO — rode no editor (troque o e-mail se quiser testar outra pessoa). */
function debugFoto(email) {
  email = _normEmail_(email || Session.getEffectiveUser().getEmail());
  var d = accDirectory_(email, true);
  Logger.log('E-mail: %s', email);
  Logger.log('Nome no diretório: %s', d.name || '(vazio)');
  Logger.log('URL da foto: %s', d.photoUrl || '(nenhuma)');
  Logger.log('Resultado: %s', d.photo ? 'FOTO OK (' + Math.round(d.photo.length / 1024) + ' KB)' : 'sem foto no servidor');
  Logger.log('Detalhe: %s', d.dbg || '-');
  // Teste de controle: a própria conta do dono do script (sempre pode ler a própria foto, se o escopo existir)
  try {
    var me = People.People.get('people/me', { personFields: 'photos' }), mp = (me && me.photos) || [];
    var real = mp.filter(function (f) { return !f['default']; })[0];
    Logger.log('Controle (people/me, sua própria conta): %s', real ? 'TEM foto -> ' + real.url : (mp.length ? 'só a foto padrão' : 'sem foto'));
  } catch (e) { Logger.log('Controle (people/me): erro %s', e.message); }
}

/** DIAGNÓSTICO — edite o e-mail e rode no editor: mostra por que a pessoa entra ou não. */
function debugAcesso(email) {
  email = _normEmail_(email || 'nome@example.com');
  accInvalidate_();
  var list = accRead_(), exact = accFind_(list, email), dir = accDirEmails_(email), viaAlias = accFindUser_(list, email);
  Logger.log('E-mail testado: %s', email);
  Logger.log('Cadastro exato: %s', exact ? (exact.papel + (exact.ativo ? ' · ativo' : ' · INATIVO')) : '(não)');
  Logger.log('Diretório: principal=%s · todos=%s', dir.primary || '(?)', dir.all.join(', ') || '(People API inativa ou não achou)');
  Logger.log('Cadastro por alias: %s', viaAlias ? (viaAlias.email + ' · ' + viaAlias.papel + (viaAlias.ativo ? ' · ativo' : ' · INATIVO')) : '(não)');
  var local = email.split('@')[0].slice(0, 4);
  Logger.log('Parecidos na planilha: %s', list.filter(function (m) { return m.email.indexOf(local) === 0; }).map(function (m) { return m.email; }).join(', ') || '(nenhum)');
  Logger.log('ACCESS_MODE=%s · ALLOWED_GROUP=%s', props_().getProperty('ACCESS_MODE') || 'planilha', props_().getProperty('ALLOWED_GROUP') || '(não)');
}

/** RODE UMA VEZ NO EDITOR (v16): cria/migra a planilha de Acessos e testa a foto do diretório. */
function setupAcessos() {
  accInvalidate_();
  var me = _normEmail_(Session.getEffectiveUser().getEmail());
  try { CacheService.getScriptCache().remove('dir_' + Utilities.base64EncodeWebSafe(me).slice(0, 200)); } catch (e) {}
  var list = accMembers_(), S = accSheet_();
  accSyncAllowed_();
  Logger.log('Planilha de Acessos: %s', S.ss.getUrl());
  Logger.log('Membros: %s · admins ativos: %s', list.length, list.filter(function (m) { return m.ativo && m.papel === 'Admin'; }).length);
  list.forEach(function (m) { Logger.log('  %s | %s | %s | %s', m.email, m.nome, m.papel, m.ativo ? 'ativo' : 'INATIVO'); });
  var d = accDirectory_(me);
  Logger.log('People API: %s · nome no diretório: %s · foto: %s', typeof People !== 'undefined' ? 'ativa' : 'NÃO ativada (iniciais no lugar da foto)', d.name || '(vazio)', d.photo ? 'ok' : '(sem foto) — ' + (d.dbg || ''));
  return S.ss.getUrl();
}

/* ---------- Endpoints chamados pelo portal (google.script.run) ---------- */

/** Sessão do usuário logado: nome, papel, foto e preferências. */
function getSession() {
  if (!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  var email = _me_(), mem = null;
  try { mem = accFindUser_(accMembers_(), email); } catch (e) {}
  var dir = { name: '', photo: '' };
  try { dir = accDirectory_(email); } catch (e) {}
  return {
    email: email,
    name: (mem && mem.nome) || dir.name || _nameFromEmail_(email),
    role: mem ? mem.papel : 'Membro',
    isAdmin: !!(mem && mem.ativo && mem.papel === 'Admin'),
    photo: dir.photo || '',
    photoUrl: dir.photo ? '' : (dir.photoUrl || ''), // o navegador tenta direto, com o login da própria pessoa
    lang: (mem && mem.idioma) || '',
    theme: (mem && mem.tema) || ''
  };
}

/** Salva idioma/tema do usuário na planilha (acompanha a pessoa em qualquer computador). */
function savePrefs(lang, theme) {
  if (!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  lang = (lang === 'en') ? 'en' : 'pt';
  theme = ({ dark: 1, light: 1, system: 1 })[theme] ? theme : 'system';
  var email = _me_();
  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var S = accSheet_(), cur = accFindUser_(accRead_(S), email);
    if (!cur) return { ok: false }; // acesso via grupo, sem cadastro: fica só no navegador
    S.m.getRange(cur._row, 5, 1, 2).setValues([[lang, theme]]);
  } finally { lock.releaseLock(); accInvalidate_(); }
  return { ok: true };
}

function _requireAdmin_() {
  var me = _me_(), m = null;
  try { m = accFindUser_(accMembers_(), me); } catch (e) {}
  if (!m || !m.ativo || m.papel !== 'Admin') throw new Error('Apenas administradores podem fazer isso.');
  return m.email; // e-mail como está no cadastro (pode ser alias do principal)
}
function _adminsActiveExcept_(list, email) {
  return list.filter(function (m) { return m.ativo && m.papel === 'Admin' && m.email !== email; }).length;
}

/** Lista membros e pedidos pendentes (só Admin). */
function adminList() {
  var me = _requireAdmin_();
  var members = accRead_().map(function (m) { var o = {}; for (var k in m) if (k !== '_row') o[k] = m[k]; return o; });
  members.sort(function (a, b) { return a.nome.localeCompare(b.nome); });
  var pend = _pendingAll_(), pending = [];
  for (var t in pend) pending.push({ email: _normEmail_(pend[t].email), just: pend[t].just || '', ts: pend[t].ts || '' });
  pending.sort(function (a, b) { return String(b.ts).localeCompare(String(a.ts)); });
  return { me: me, members: members, pending: pending, sheetUrl: accSheet_().ss.getUrl() };
}

/** Aprova/nega pedido pendente pelo portal (o link do e-mail continua valendo). */
function adminDecide(email, approve) {
  var me = _requireAdmin_(); email = _normEmail_(email);
  var req = null, lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var pend = _pendingAll_();
    for (var t in pend) { if (_normEmail_(pend[t].email) === email) { req = pend[t]; delete pend[t]; } }
    if (req) _pendingSave_(pend);
  } finally { lock.releaseLock(); }
  if (!req) throw new Error('Esse pedido não existe mais (talvez já tenha sido decidido pelo e-mail).');
  _decide_(req, !!approve, me, 'portal');
  return adminList();
}

/** Alterações em membro: papel, ativo, remover. Regras: não altera a si mesmo; sempre ≥1 Admin ativo. */
function _adminMutate_(email, fn) {
  var me = _requireAdmin_(); email = _normEmail_(email);
  if (email === me) throw new Error('Você não pode alterar o próprio acesso.');
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    var S = accSheet_(), list = accRead_(S), cur = accFind_(list, email);
    if (!cur) throw new Error('Membro não encontrado: ' + email);
    fn(S, list, cur, me);
  } finally { lock.releaseLock(); accInvalidate_(); }
  accSyncAllowed_();
  return adminList();
}
function adminSetRole(email, papel) {
  papel = (papel === 'Admin') ? 'Admin' : 'Membro';
  return _adminMutate_(email, function (S, list, cur, me) {
    if (cur.papel === papel) return;
    if (cur.papel === 'Admin' && cur.ativo && !_adminsActiveExcept_(list, cur.email)) throw new Error('Precisa existir ao menos um admin ativo.');
    S.m.getRange(cur._row, 3).setValue(papel); S.m.getRange(cur._row, 9).setValue(new Date());
    S.a.appendRow([new Date(), me, 'alterar_papel', cur.email, cur.papel + ' -> ' + papel]);
  });
}
function adminSetActive(email, ativo) {
  ativo = !!ativo;
  return _adminMutate_(email, function (S, list, cur, me) {
    if (cur.ativo === ativo) return;
    if (!ativo && cur.papel === 'Admin' && !_adminsActiveExcept_(list, cur.email)) throw new Error('Precisa existir ao menos um admin ativo.');
    S.m.getRange(cur._row, 4).setValue(ativo); S.m.getRange(cur._row, 9).setValue(new Date());
    S.a.appendRow([new Date(), me, ativo ? 'reativar_membro' : 'desativar_membro', cur.email, '']);
  });
}
function adminRemove(email) {
  return _adminMutate_(email, function (S, list, cur, me) {
    if (cur.papel === 'Admin' && cur.ativo && !_adminsActiveExcept_(list, cur.email)) throw new Error('Precisa existir ao menos um admin ativo.');
    S.m.deleteRow(cur._row);
    S.a.appendRow([new Date(), me, 'remover_membro', cur.email, 'papel ' + cur.papel + (cur.ativo ? '' : ' (estava inativo)')]);
  });
}
function adminAdd(nome, email, papel) {
  var me = _requireAdmin_(); email = _normEmail_(email); nome = String(nome || '').trim().slice(0, 120);
  papel = (papel === 'Admin') ? 'Admin' : 'Membro';
  if (!ACC_EMAIL_RX.test(email)) throw new Error('E-mail inválido: ' + email);
  var lock = LockService.getScriptLock(); lock.waitLock(15000);
  try {
    var S = accSheet_(), typed = email, dir = accDirEmails_(email);
    if (dir.primary) email = dir.primary; // grava o e-mail principal (é o que o Google informa no login)
    var dup = accFind_(accRead_(S), email) || (dir.all || []).map(function (x) { return accFind_(accRead_(S), x); }).filter(Boolean)[0];
    if (dup) throw new Error(dup.email + ' já é membro. Use a lista para reativar ou mudar o papel.');
    var now = new Date();
    if (!nome) { try { nome = accDirectory_(email).name; } catch (x) {} }
    S.m.appendRow([email, nome || _nameFromEmail_(email), papel, true, '', '', now, me, now]);
    S.a.appendRow([now, me, 'adicionar_membro', email, 'papel ' + papel + (typed !== email ? ' · digitado como ' + typed : '')]);
  } finally { lock.releaseLock(); accInvalidate_(); }
  accSyncAllowed_();
  try { MailApp.sendEmail(email, '[Painel SOC/CSIRT] Você recebeu acesso', me + ' liberou seu acesso ao painel KPI SOC/CSIRT (' + papel + '). Acesse: ' + ScriptApp.getService().getUrl()); } catch (e) {}
  return adminList();
}

/** Endpoint web — serve o HTML puro; os dados são buscados via google.script.run. */
function doGet(e) {
  // Diagnóstico: /exec?whoami=1 mostra o e-mail que o app enxerga e se autoriza.
  if (e && e.parameter && e.parameter.whoami) {
    var em = Session.getActiveUser().getEmail() || '(VAZIO — deploy não expõe o e-mail)';
    var p = props_();
    return HtmlService.createHtmlOutput(
      '<pre style="font:14px Consolas,monospace;padding:16px">' +
      'getActiveUser().getEmail() = ' + em + '\n' +
      'ALLOWED_EMAILS            = ' + (p.getProperty('ALLOWED_EMAILS') || '(não definido)') + '\n' +
      'ALLOWED_GROUP             = ' + (p.getProperty('ALLOWED_GROUP') || '(não definido)') + '\n' +
      'isAuthorized_()           = ' + isAuthorized_() + '\n' +
      'ACCESS_SHEET_ID           = ' + (p.getProperty('ACCESS_SHEET_ID') || '(será criada no 1º acesso)') + '\n' +
      'ACCESS_MODE               = ' + (p.getProperty('ACCESS_MODE') || 'planilha') + '\n' +
      'versão do código          = ' + CODE_VERSION + '\n' +
      'cadastro                  = ' + (function () { try { var m = accFindUser_(accMembers_(), em); return m ? (m.email + ' · ' + m.papel + (m.ativo ? ' · ativo' : ' · INATIVO')) : '(sem cadastro)'; } catch (x) { return 'ERRO ao ler a planilha: ' + x.message; } })() + '\n' +
      'e-mails no diretório      = ' + (function () { try { return accDirEmails_(em).all.join(', ') || '(não encontrado / People API inativa)'; } catch (x) { return 'erro: ' + x.message; } })() + '\n' +
      'People API (foto)         = ' + (typeof People !== 'undefined' ? 'ativa' : 'não ativada') + '</pre>'
    ).setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  }
  // Aprovação/negação de acesso (link do e-mail do aprovador).
  if (e && e.parameter && (e.parameter.approve || e.parameter.deny)) return handleApproval_(e);
  if (!isAuthorized_()) return denied_();
  return HtmlService.createHtmlOutputFromFile('Index')
    .setTitle('KPI CSIRT — SIEM & MITRE')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/** Chamado pelo cliente (google.script.run) para obter a cobertura. */
function getCoverage() {
  if (!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  return getCoverage_(false);
}

/* ================== KPI OPERACIONAL (Eng. Detecção) — 100% API, sem planilha (v27) ==================
 * Regras: Kibana Detection Engine (fetchRules_) · Alertas: Kibana signals/search (CMDB × SIEM fica só na aba Inventário)
 * Fontes de log: _search em logs-* (24h) · Licença: API de Billing do Elastic Cloud (teto = EC_ECU_CAP, padrão 11000).
 * Histórico de regras/MITRE: retrato gravado a cada execução no mês corrente (OP_HIST); mês sem retrato é
 *   reconstruído pela created_at das regras habilitadas hoje (aproximado).
 * Notas de Melhorias/Próximas ações: Propriedade OP_NOTA_<AAAA-MM>, editadas na tela por Admin (salvarNotaOp).
 */
var OP_KEY = 'op_data_v10'; // v10: lic[].ds.cong/tarde (mês fechado congelado) · v9: lic[].ds.top[].ev (tem detalhe de eventos) · v8: lic[].ds (top 5 datasources por GB) · v7: cats com fixo/pph/h/det (máquinas × uso) · v6: lic[].cats (categorias), itens com máquinas (price) · v5: lic[].dep/itens/ia, sem projeção · v3: tudo pela API (elastic[].ym/fonte, highlights[].fatos/sug, errs) · v4: CMDB 30d, fontes de log
var OP_TTL = 2 * 60 * 60; // 2h

function _mlab(d){var M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];return M[d.getMonth()]+'/'+(''+d.getFullYear()).slice(-2);}
function _mkey(d){return d.getFullYear()*12+d.getMonth();}

function opPut_(cache,str){var n=Math.ceil(str.length/CHUNK),p={};for(var i=0;i<n;i++)p[OP_KEY+'_'+i]=str.substr(i*CHUNK,CHUNK);p[OP_KEY+'_n']=String(n);cache.putAll(p,OP_TTL);}
function opGet_(cache){var ns=cache.get(OP_KEY+'_n');if(!ns)return null;var n=parseInt(ns,10),ids=[];for(var i=0;i<n;i++)ids.push(OP_KEY+'_'+i);var got=cache.getAll(ids),o='';for(var j=0;j<n;j++){var s=got[OP_KEY+'_'+j];if(s==null)return null;o+=s;}return o;}

function buildOperational_(){
  var months=_opMeses_(),errs={};
  var rules=fetchRules_(),R=_opRules_(rules,months),cur=R.elastic[R.elastic.length-1];
  try{_opHistSave_(cur);}catch(e){errs.hist=e.message;}

  // Criticidade / tipo (regras habilitadas hoje)
  var en=rules.filter(function(r){return r.enabled;}),cc={},tipo={};
  en.forEach(function(r){var k=OP_SEV[String(r.severity||'').toLowerCase()]||'—';cc[k]=(cc[k]||0)+1;var t=r.type||'—';tipo[t]=(tipo[t]||0)+1;});
  var criticidade=['Crítica','Alta','Média','Baixa'].map(function(k){return {k:k,v:cc[k]||0};});
  var tipo_top=Object.keys(tipo).map(function(k){return {k:k,v:tipo[k]};}).sort(function(a,b){return b.v-a.v;}).slice(0,6);

  var al={},alertsByMonth=[];
  try{al=_opAlerts_(months[0].start);}catch(e){errs.alertas=e.message;}
  months.forEach(function(mm){var a=al[mm.ym];if(a)alertsByMonth.push({m:mm.m,total:a.total,top:a.top.slice(0,8)});});
  var logs=[];try{logs=_opLogs_();}catch(e){errs.fontes=e.message;}

  // Licença: consumo pela API de Billing; teto = EC_ECU_CAP
  var cap=parseFloat(props_().getProperty('EC_ECU_CAP'))||11000,lic=[],licSrc={api:false};
  if(props_().getProperty('EC_BILLING_API_KEY')){
    try{var bl=_billing_(),dsv={};try{dsv=_opDatasources_(bl.months);}catch(e){errs.datasources=e.message;}dsv=_dsCongela_(bl.months,dsv);
      lic=bl.months.map(function(a){var l={m:a.m,total:cap,cons:a.cons,src:'api',dep:a.dep};if(a.itens){l.itens=a.itens;l.cats=a.cats;l.ia=a.ia;}if(a.part){l.part=true;l.ate=a.ate;}if(dsv[a.k])l.ds=dsv[a.k];return l;});licSrc={api:true,via:bl.via,at:bl.at};}
    catch(e){licSrc={api:false,err:String(e.message||e).slice(0,200)};errs.billing=e.message;}}
  else errs.billing='EC_BILLING_API_KEY não definida';

  var highlights=_opHighlights_(rules,months,R,al);
  for(var k in errs)Logger.log('operacional · %s: %s',k,errs[k]);
  return {elastic:R.elastic,techByMonth:R.techByMonth,criticidade:criticidade,crit_total:en.length,
    alertsByMonth:alertsByMonth,logs:logs,lic:lic,lic_src:licSrc,highlights:highlights,tipo_top:tipo_top,
    errs:errs,fonte:'api',updated:Utilities.formatDate(new Date(),'America/Sao_Paulo','dd/MM/yyyy HH:mm')};
}

var OP_SEV={critical:'Crítica',high:'Alta',medium:'Média',low:'Baixa'};
/* Tecnologia da regra: prefixo do nome "[XXX]" → tag "Data Source: …" → índice/consulta → tipo. */
var OP_TEC_PREF={'WIN-EVT':'Event Viewer (Windows)','WIN':'Event Viewer (Windows)','FW':'Firewall','NDR':'NDR Gigamon','CORR':'Correlação de Data Sources',
  'CTI':'CTI Tempest','XDR':'Cortex XDR','CORTEX':'Cortex XDR','VISIONONE':'Trend Micro','TREND':'Trend Micro','SO':'SO','WAF':'WAF','DEFENDER':'Defender',
  'NETSKOPE':'Netskope','NTSKP':'Netskope','BD':'Banco de Dados','DB':'Banco de Dados','SQL':'Banco de Dados','IDM':'IDM','AD':'Active Directory',
  'LINUX':'Rsyslog (Linux)','LNX':'Rsyslog (Linux)','GUARDICORE':'Guardicore (Health)'};
// tag "Data Source: …" das regras prebuilt → mesmo nome das próprias
var OP_TEC_TAG={'PowerShell Logs':'Event Viewer (Windows)','Windows Security Event Logs':'Event Viewer (Windows)','Sysmon':'Event Viewer (Windows)','Windows':'Event Viewer (Windows)','Active Directory':'Active Directory'};
var OP_TEC_IDX=[[/endpoint|elastic_defend/,'Elastic Defend'],[/windows|winlog/,'Event Viewer (Windows)'],[/panw|fortinet|firewall|checkpoint|cisco_asa/,'Firewall'],
  [/gigamon|zeek|suricata|ndr/,'NDR Gigamon'],[/cortex|xdr/,'Cortex XDR'],[/trend|visionone|deepsecurity/,'Trend Micro'],[/m365_defender|microsoft_defender/,'Defender'],
  [/netskope/,'Netskope'],[/auditd|linux|syslog/,'Rsyslog (Linux)'],[/waf|imperva/,'WAF'],[/ti_|threat_intel/,'CTI Tempest']];
function _opTec_(r){
  var m=/^\s*\[([^\]]+)\]/.exec(r.name||'');if(m){var k=m[1].trim().toUpperCase();return OP_TEC_PREF[k]||m[1].trim();}
  var t=(r.tags||[]).filter(function(x){return /^Data Source:/i.test(x);})[0];if(t){t=t.replace(/^Data Source:\s*/i,'');return OP_TEC_TAG[t]||t;}
  var ix=((r.index||[]).join(' ')+' '+String(r.query||'').slice(0,400)).toLowerCase();
  for(var i=0;i<OP_TEC_IDX.length;i++)if(OP_TEC_IDX[i][0].test(ix))return OP_TEC_IDX[i][1];
  return r.type==='machine_learning'?'Machine Learning':'Outros';
}
function _opCustom_(r){if(r.immutable===true)return false;if(r.rule_source&&r.rule_source.type==='external')return false;return true;}
/* Meses de jan do ano anterior até o mês corrente (fuso de Brasília). */
function _opMeses_(){
  var ym=Utilities.formatDate(new Date(),'America/Sao_Paulo','yyyy-MM').split('-'),Y=+ym[0],M=+ym[1]-1,out=[];
  for(var y=Y-1;y<=Y;y++)for(var mo=0;mo<12;mo++){if(y===Y&&mo>M)break;
    out.push({ym:y+'-'+('0'+(mo+1)).slice(-2),m:_mlab(new Date(y,mo,15)),start:Date.UTC(y,mo,1,3),end:Date.UTC(y,mo+1,1,3),cur:(y===Y&&mo===M)});}
  return out;
}
/* Casos em produção / cobertura MITRE / tecnologia por mês. Mês com retrato gravado (OP_HIST) usa o retrato;
 * sem retrato, reconstrói pela created_at das regras habilitadas hoje (não enxerga regra desligada/apagada depois). */
function _opRules_(rules,months){
  var uT={},uS={};CATALOG.tactics.forEach(function(t){t.techniques.forEach(function(te){uT[te.id]=te.name;te.subs.forEach(function(s){uS[s.id]=1;});});});
  var en=rules.filter(function(r){return r.enabled;}).map(function(r){var T={},S={},A={};
    (r.threat||[]).forEach(function(th){if(th.tactic)A[th.tactic.id]=1;(th.technique||[]).forEach(function(te){if(uT[te.id])T[te.id]=1;(te.subtechnique||[]).forEach(function(s){if(uS[s.id])S[s.id]=1;});});});
    return {c:r.created_at?Date.parse(r.created_at):0,T:T,S:S,A:A,tec:_opTec_(r)};});
  var hist=_opHistLoad_(),out=[],techByMonth={},sets={};
  months.forEach(function(mm){var T={},S={},A={},n=0,tc={},k;
    en.forEach(function(x){if(x.c>=mm.end)return;n++;for(k in x.T)T[k]=1;for(k in x.S)S[k]=1;for(k in x.A)A[k]=1;tc[x.tec]=(tc[x.tec]||0)+1;});
    var rec={m:mm.m,ym:mm.ym,prod:n,taticas:Object.keys(A).length,tecCov:Object.keys(T).length,tecTot:Object.keys(uT).length,
      subCov:Object.keys(S).length,subTot:Object.keys(uS).length,fonte:mm.cur?'atual':'reconstruido'};
    var h=hist[mm.ym];if(h&&!mm.cur){rec.prod=h.prod;rec.taticas=h.taticas;rec.tecCov=h.tecCov;rec.subCov=h.subCov;rec.fonte='retrato';}
    out.push(rec);sets[mm.ym]=T;
    techByMonth[mm.m]=Object.keys(tc).map(function(k){return {k:k,v:tc[k]};}).sort(function(a,b){return b.v-a.v;});});
  return {elastic:out,techByMonth:techByMonth,sets:sets,uT:uT};
}
function _opHistLoad_(){try{return JSON.parse(props_().getProperty('OP_HIST')||'{}');}catch(e){return {};}}
function _opHistSave_(rec){var h=_opHistLoad_();h[rec.ym]={prod:rec.prod,taticas:rec.taticas,tecCov:rec.tecCov,subCov:rec.subCov,at:new Date().toISOString()};
  var ks=Object.keys(h).sort();while(ks.length>36)delete h[ks.shift()];props_().setProperty('OP_HIST',JSON.stringify(h));}
/* Alertas do espaço (todos, inclusive building block — igual à antiga aba Alertas) por mês + top regras. */
function kbAlertsSearch_(body){
  var p=props_(),base=p.getProperty('KIBANA_URL'),key=p.getProperty('ES_API_KEY'),sp=p.getProperty('KIBANA_SPACE');
  if(!base||!key)throw new Error('Defina KIBANA_URL e ES_API_KEY nas Propriedades do script.');
  var url=base.replace(/\/+$/,'')+((sp&&sp!=='default')?'/s/'+sp:'')+'/api/detection_engine/signals/search';
  var res=UrlFetchApp.fetch(url,{method:'post',headers:{'Authorization':'ApiKey '+key,'kbn-xsrf':'true','Content-Type':'application/json'},payload:JSON.stringify(body),muteHttpExceptions:true});
  var code=res.getResponseCode();if(code!==200)throw new Error('Kibana signals/search HTTP '+code+': '+res.getContentText().slice(0,300));
  return JSON.parse(res.getContentText());
}
function _opAlerts_(from){
  var body={size:0,query:{range:{'@timestamp':{gte:new Date(from).toISOString()}}},
    aggs:{m:{date_histogram:{field:'@timestamp',calendar_interval:'month',time_zone:'America/Sao_Paulo',format:'yyyy-MM',min_doc_count:1},aggs:{r:{terms:{field:'kibana.alert.rule.name',size:40}}}}}};
  var r;try{r=kbAlertsSearch_(body);}
  catch(e){var sp=props_().getProperty('KIBANA_SPACE')||'default';Logger.log('signals/search falhou (%s); tentando _search direto',e.message);r=esSearch_('.alerts-security.alerts-'+sp,body);}
  var out={};(((r.aggregations||{}).m||{}).buckets||[]).forEach(function(b){
    out[b.key_as_string]={total:b.doc_count,top:((b.r&&b.r.buckets)||[]).map(function(x){return {k:x.key,v:x.doc_count};})};});
  return out;
}
/* Fontes de log coletadas (24h): hosts distintos por integração (máx. entre os datasets da mesma integração). */
var OP_FONTE={system:'Windows / Linux (System)',windows:'Windows',winlog:'Windows',auditd:'Linux (Auditd)',tcp:'Syslog',udp:'Syslog',panw:'Firewall Palo Alto',
  endpoint:'Elastic Defend',elastic_agent:'Elastic Agent',panw_cortex_xdr:'Cortex XDR',trend_micro_vision_one:'Vision One',cyberark_pta:'CyberArk',cyberarkpas:'CyberArk',
  claroty_xdome:'Claroty',tenable_io:'Tenable',tenable_sc:'Tenable'};
// Integrações que reportam ATIVOS de terceiros (host.name = ativo escaneado/protegido, não quem envia log): contam como 1 fonte.
var OP_FONTE_TERC=/^(tenable|guardicore|claroty|panw_cortex_xdr|trend_micro|qualys|rapid7|ti_)/;
function _opLogs_(){
  var r=esSearch_(INV_SIEM,{size:0,query:{bool:{filter:[{range:{'@timestamp':{gte:'now-24h'}}}]}},aggs:{d:{terms:{field:'data_stream.dataset',size:300},aggs:{h:{cardinality:{field:'host.name'}}}}}});
  var acc={};(((r.aggregations||{}).d||{}).buckets||[]).forEach(function(b){var it=String(b.key).split('.')[0],k=OP_FONTE[it]||(/^guardicore/.test(it)?'Guardicore':it),h=OP_FONTE_TERC.test(it)?1:((b.h&&b.h.value)||0);if(h>(acc[k]||0))acc[k]=h;});
  return Object.keys(acc).filter(function(k){return acc[k]>0;}).map(function(k){return {k:k,v:acc[k],prev:acc[k]};}).sort(function(a,b){return b.v-a.v;});
}
/* Melhorias / Próximas ações: fatos do Elastic no mês + nota do Admin (Propriedade OP_NOTA_<AAAA-MM>). */
function _opHighlights_(rules,months,R,al){
  var out={},cust=rules.filter(_opCustom_),uT=R.uT,YY=months[months.length-1].ym.slice(0,4);
  // gaps: técnicas do catálogo sem cobertura, com mais subtécnicas expostas
  var subsOf={};CATALOG.tactics.forEach(function(t){t.techniques.forEach(function(te){subsOf[te.id]=te.subs.length;});});
  months.forEach(function(mm,i){if(mm.ym.slice(0,4)!==YY)return;
    var inM=function(s){var t=s?Date.parse(s):0;return t>=mm.start&&t<mm.end;};
    var criadas=cust.filter(function(r){return r.enabled&&inM(r.created_at);}).map(function(r){return r.name;});
    var alteradas=cust.filter(function(r){return r.enabled&&inM(r.updated_at)&&!inM(r.created_at);}).map(function(r){return r.name;});
    var desligadas=cust.filter(function(r){return !r.enabled&&inM(r.updated_at);}).map(function(r){return r.name;});
    var prev=i?R.sets[months[i-1].ym]:{},curS=R.sets[mm.ym]||{};
    var tecNovas=Object.keys(curS).filter(function(k){return !prev[k];}).sort().map(function(k){return k+' '+uT[k];});
    var a=al[mm.ym],pa=i?al[months[i-1].ym]:null,tuning=[];
    if(a&&pa&&!mm.cur){var now={};a.top.forEach(function(x){now[x.k]=x.v;});
      pa.top.forEach(function(x){var v=now[x.k]||0;if(x.v>=50&&v<=x.v*0.5)tuning.push({k:x.k,de:x.v,para:v});});
      tuning.sort(function(p,q){return (q.de-q.para)-(p.de-p.para);});}
    var gaps=Object.keys(uT).filter(function(k){return !curS[k];}).sort(function(p,q){return subsOf[q]-subsOf[p];}).slice(0,3).map(function(k){return k+' '+uT[k]+(subsOf[k]?' ('+subsOf[k]+' subtéc.)':'');});
    var nota={};try{nota=JSON.parse(props_().getProperty('OP_NOTA_'+mm.ym)||'{}');}catch(e){}
    out[mm.m]={ym:mm.ym,mel:nota.mel||'',prox:nota.prox||'',by:nota.by||'',at:nota.at||'',
      fatos:{criadas:criadas.slice(0,20),nCriadas:criadas.length,alteradas:alteradas.slice(0,10),nAlteradas:alteradas.length,
        desligadas:desligadas.slice(0,10),nDesligadas:desligadas.length,tecNovas:tecNovas.slice(0,12),tuning:tuning.slice(0,5)},
      sug:{ruidosas:a?a.top.slice(0,3):[],gaps:gaps}};
  });
  return out;
}

/* ================== BILLING — consumo de ECU pela API do Elastic Cloud (v26) ==================
 * Propriedades: EC_BILLING_API_KEY = API key do Elastic Cloud (cloud.elastic.co → Organization → API keys,
 *   papel Billing admin; NÃO é a ES_API_KEY). EC_ORG_ID = ID da organização (opcional: sem ela usa a 1ª da chave).
 *   EC_API_URL opcional (padrão https://api.elastic-cloud.com).
 * Soma o custo (ECU) de todos os deployments/projetos da organização, mês a mês (UTC), últimos 12 meses.
 * Por mês: deployments (dos próprios buckets) e, no ano corrente, itens de cobrança (ecItems_) com a parte de IA.
 * Mês corrente = parcial (consumo real até agora, sem projeção).
 */
var EC_API='https://api.elastic-cloud.com';
function ecFetch_(path){
  var p=props_(),key=p.getProperty('EC_BILLING_API_KEY');if(!key)throw new Error('Defina EC_BILLING_API_KEY nas Propriedades do script.');
  var base=(p.getProperty('EC_API_URL')||EC_API).replace(/\/+$/,'');
  var res=UrlFetchApp.fetch(base+path,{method:'get',headers:{'Authorization':'ApiKey '+key,'Accept':'application/json'},muteHttpExceptions:true});
  var code=res.getResponseCode();
  if(code!==200){var e=new Error('Elastic Cloud '+path.split('?')[0]+' HTTP '+code+': '+res.getContentText().slice(0,300));e.code=code;throw e;}
  return JSON.parse(res.getContentText());
}
function ecOrg_(){var id=props_().getProperty('EC_ORG_ID');if(id)return id.trim();
  var r=ecFetch_('/api/v1/organizations'),o=(r.organizations||[])[0];
  if(!o||!o.id)throw new Error('Defina EC_ORG_ID (a chave não listou organizações).');return o.id;}
/* Série mensal (buckets) — tenta a API v2 (hosted + serverless) e cai para a v1 se não existir. */
function ecCharts_(org,from,to){
  var q='?from='+encodeURIComponent(from)+'&to='+encodeURIComponent(to)+'&bucketing_strategy=monthly';
  var paths=['/api/v2/billing/organizations/'+org+'/costs/charts'+q,'/api/v1/billing/costs/'+org+'/charts'+q],last;
  var errs=[];
  for(var i=0;i<paths.length;i++){try{return {via:i?'v1':'v2',r:ecFetch_(paths[i])};}catch(e){last=e;errs.push(e.message);if(e.code!==404&&e.code!==400)throw e;}}
  throw new Error(errs.join(' | ')+' — confira EC_ORG_ID (ID numérico da organização no Elastic Cloud, não o ID da API key).');
}
function _ecTs_(t){if(typeof t==='number')return new Date(t<1e12?t*1000:t);return new Date(t);}
function _ecVal_(b){if(b.values&&b.values.length){var s=0;b.values.forEach(function(v){s+=parseFloat(v.value)||0;});return s;}return parseFloat(b.value!=null?b.value:b.cost)||0;}
function _billing_(){
  var now=new Date(),y=now.getUTCFullYear(),mo=now.getUTCMonth(),org=ecOrg_();
  var from=new Date(Date.UTC(y,mo-11,1)).toISOString();
  var c=ecCharts_(org,from,now.toISOString()),acc={},dep={};
  ((c.r&&c.r.data)||[]).forEach(function(b){var d=_ecTs_(b.timestamp);if(isNaN(d))return;
    var k=d.getUTCFullYear()*12+d.getUTCMonth();acc[k]=(acc[k]||0)+_ecVal_(b);
    (b.values||[]).forEach(function(v){var n=v.name||v.id||'—';(dep[k]||(dep[k]={}))[n]=((dep[k]||{})[n]||0)+(parseFloat(v.value)||0);});});
  var curK=y*12+mo,top=function(o){return Object.keys(o||{}).map(function(n){return {k:n,v:Math.round(o[n])};}).filter(function(x){return x.v>0;}).sort(function(p,q){return q.v-p.v;}).slice(0,6);};
  var months=Object.keys(acc).map(Number).sort(function(a,b){return a-b;}).map(function(k){
    var r={k:k,m:_mlab(new Date(Math.floor(k/12),k%12,15)),cons:Math.round(acc[k]),dep:top(dep[k])};
    if(Math.floor(k/12)===y){ // itens só no ano corrente (1 chamada por mês)
      try{var it=ecItems_(org,new Date(Date.UTC(Math.floor(k/12),k%12,1)).toISOString(),(k===curK?now:new Date(Date.UTC(Math.floor(k/12),k%12+1,1))).toISOString());
      r.itens=it.slice(0,8);r.cats=_ecCats_(it,r.cons);r.ia=Math.round(it.filter(function(x){return x.ia;}).reduce(function(s,x){return s+x.v;},0));}catch(e){Logger.log('billing itens %s: %s',r.m,e.message);}}
    if(k===curK){r.part=true;r.ate=now.toISOString();}return r;});
  return {months:months,via:c.via,at:now.toISOString()};
}
/* Itens de cobrança do período (por produto/recurso), somados por nome. Lê só as "folhas" da resposta (objetos com
 * nome + custo, sem filhos com custo) para servir tanto à v1 quanto à v2; "dimensions" (resumo por tipo) é ignorado. */
var EC_IA_RX=/\b(llm|inference|inferência|ai|genai|gen ai|tokens?|eis|elser|e5|rerank|openai|anthropic|claude|gemini|bedrock|assistant|agent builder)\b/i;
function ecItems_(org,from,to){
  var q='?from='+encodeURIComponent(from)+'&to='+encodeURIComponent(to),r,last;
  var paths=['/api/v1/billing/costs/'+org+'/items'+q,'/api/v2/billing/organizations/'+org+'/costs/items'+q];
  for(var i=0;i<paths.length&&!r;i++){try{r=ecFetch_(paths[i]);}catch(e){last=e;if(e.code!==404&&e.code!==400)throw e;}}
  if(!r)throw last;
  var leaves=[];_ecLeaves_(r,leaves,'');var acc={};
  leaves.forEach(function(x){var a=acc[x.k]||(acc[x.k]={v:0,h:0,pph:null});a.v+=x.v;if(x.h!=null){a.h+=x.h;a.pph=x.pph;}});
  return Object.keys(acc).map(function(k){var a=acc[k],r={k:k,v:Math.round(a.v),ia:EC_IA_RX.test(k)};if(a.pph!=null){r.h=a.h;r.pph=a.pph;}return r;}).filter(function(x){return x.v>0;}).sort(function(a,b){return b.v-a.v;});
}
/* Categoria em linguagem simples de cada item de cobrança (a 1ª regra que casar). */
var EC_CATS=[[EC_IA_RX,'IA'],[/inter-?node/i,'Tráfego interno'],[/transfer out|egress/i,'Saída de dados'],[/transfer in\b|data in\b/i,'Entrada de dados'],
  [/snapshot/i,'Backup (snapshots)'],[/storage/i,'Armazenamento'],[/\.ml\.|\bml\b|machine.?learning/i,'Machine Learning'],[/kibana/i,'Kibana'],
  [/integrations?.?server|\bapm\b|fleet/i,'Fleet / APM'],[/frozen/i,'Elasticsearch · frozen'],[/cold/i,'Elasticsearch · cold'],[/warm/i,'Elasticsearch · warm'],
  [/hot|content/i,'Elasticsearch · hot'],[/\.es\.|elasticsearch|master|coordinat/i,'Elasticsearch · outros nós']];
/* Soma os itens por categoria; o que faltar para o total do mês (gráfico de custos) vira "Não detalhado pela API". */
/* Máquinas (fixo = cobradas por hora): pph = ECU/hora somado, h = horas da maior máquina, det = tamanho ("64GB × 2 zonas"). */
function _ecCats_(it,tot){var a={},s=0;
  it.forEach(function(x){var c='Outros itens';for(var i=0;i<EC_CATS.length;i++)if(EC_CATS[i][0].test(x.k)){c=EC_CATS[i][1];break;}
    var g=a[c]||(a[c]={v:0});g.v+=x.v;s+=x.v;
    if(x.pph!=null){g.fixo=true;g.pph=Math.round(((g.pph||0)+x.pph)*1e4)/1e4;g.h=Math.max(g.h||0,x.h||0);var z=String(x.k).match(/(\d+)\s*GB,\s*(\d+)\s*AZ/i);if(z)g.det=(g.det?g.det+' + ':'')+z[1]+' GB × '+z[2]+(z[2]==='1'?' zona':' zonas');}});
  var o=Object.keys(a).map(function(k){var g=a[k],r={k:k,v:Math.round(g.v),ia:k==='IA'};if(g.fixo){r.fixo=true;r.pph=g.pph;r.h=g.h;if(g.det)r.det=g.det;}return r;}).filter(function(x){return x.v>0;});
  if(tot-s>tot*0.01)o.push({k:'Não detalhado pela API',v:Math.round(tot-s)});
  return o.sort(function(p,q){return q.v-p.v;});}
function _ecLeaves_(o,out,key){
  if(key==='dimensions')return 0;
  if(Array.isArray(o)){var n0=0;o.forEach(function(x){n0+=_ecLeaves_(x,out,'');});return n0;}
  if(!o||typeof o!=='object')return 0;
  var kids=0;for(var k in o){var v=o[k];if(v&&typeof v==='object')kids+=_ecLeaves_(v,out,k);}
  var c=parseFloat(o.cost!=null?o.cost:(o.total_cost!=null?o.total_cost:o.price)),nm=o.name||o.display_name||o.sku; // price = máquinas (resources)
  if(!kids&&!isNaN(c)&&typeof nm==='string'){out.push({k:nm,v:c,h:o.hours,pph:o.price_per_hour});return 1;} // hours/price_per_hour = máquinas
  return kids;
}
/* GET no Elasticsearch (mesmas credenciais do esSearch_). */
function _esGet_(path){
  var p=props_(),apiKey=p.getProperty('ES_API_KEY'),esUrl=p.getProperty('ES_URL'),kb=p.getProperty('KIBANA_URL');
  if(!apiKey) throw new Error('Defina ES_API_KEY nas Propriedades do script.');
  if(!esUrl&&kb&&kb.indexOf('.kb.')>-1) esUrl=kb.replace('.kb.','.es.');
  var headers={'Authorization':'ApiKey '+apiKey},url;
  if(esUrl) url=esUrl.replace(/\/+$/,'')+path;
  else{ if(!kb) throw new Error('Defina ES_URL ou KIBANA_URL.'); headers['kbn-xsrf']='true'; url=kb.replace(/\/+$/,'')+'/api/console/proxy?path='+encodeURIComponent(path)+'&method=GET'; }
  var res=UrlFetchApp.fetch(url,{method:esUrl?'get':'post',headers:headers,muteHttpExceptions:true}),code=res.getResponseCode();
  if(code!==200) throw new Error('Elastic '+path.split('?')[0]+' HTTP '+code+': '+res.getContentText().slice(0,200));
  return JSON.parse(res.getContentText());
}
/* Top 5 datasources por mês: a API de Billing não separa por fonte, então o volume vem do tamanho dos índices (_cat/indices).
 * Cada índice de backing é rateado entre os meses em que esteve ativo (da sua criação até a criação do próximo do mesmo stream).
 * Precisa do privilégio "monitor" nos índices. Devolve {k do mês: {top:[{k,gb,pc}], tot, parc}}; parc = retenção não cobre o mês todo. */
var OP_DS_NOME={'system.security':'Windows Security','system.system':'Windows System','system.application':'Windows Application','panw.panos':'Firewall Palo Alto','endpoint.events.process':'Elastic Defend · processos','endpoint.events.file':'Elastic Defend · arquivos','endpoint.events.network':'Elastic Defend · rede','citrix_adc.log':'Citrix NetScaler','cisco_ise.log':'Cisco ISE','tcp.lnx.rsyslog':'Syslog Linux (rsyslog)','udp.lnx.rsyslog':'Syslog Linux (rsyslog)','lnx.rsyslog':'Syslog Linux (rsyslog)','netskope.alerts':'Netskope · alertas','netskope.events':'Netskope · eventos','akamai.siem':'Akamai SIEM'};
function _dsNome_(d){if(OP_DS_NOME[d])return OP_DS_NOME[d];var it=d.split('.'),b=OP_FONTE[it[0]];if(it.length>1&&OP_DS_NOME[it.slice(1).join('.')])return OP_DS_NOME[it.slice(1).join('.')];return b?(it[1]?b+' · '+it.slice(1).join('.'):b):d;}
function _opDatasources_(meses){
  var rows=_esGet_('/_cat/indices/logs-*,metrics-*?format=json&bytes=b&expand_wildcards=open,hidden&h=index,creation.date,pri.store.size,dataset.size');
  var st={},now=Date.now();
  rows.forEach(function(r){var m=String(r.index).match(/^(?:partial-|restored-)?\.ds-(?:logs|metrics)-(.+)-\d{4}\.\d{2}\.\d{2}-\d+$/);if(!m)return;
    var sz=Math.max(parseFloat(r['pri.store.size'])||0,parseFloat(r['dataset.size'])||0),c=parseFloat(r['creation.date']);if(!sz||!c)return;(st[m[1]]||(st[m[1]]=[])).push({c:c,sz:sz});});
  var acc={},maior=null,mz=0;
  Object.keys(st).forEach(function(n){var L=st[n].sort(function(a,b){return a.c-b.c;}),tot=0,d=n.lastIndexOf('-')>0?n.slice(0,n.lastIndexOf('-')):n,nm=_dsNome_(d);
    L.forEach(function(x,i){tot+=x.sz;var ini=x.c,fim=i<L.length-1?L[i+1].c:now,dur=Math.max(fim-ini,1);
      meses.forEach(function(mm){var a=Date.UTC(Math.floor(mm.k/12),mm.k%12,1),b=Date.UTC(Math.floor(mm.k/12),mm.k%12+1,1),ov=Math.min(fim,b)-Math.max(ini,a);if(ov>0){var o=acc[mm.k]||(acc[mm.k]={});o[nm]=(o[nm]||0)+x.sz*ov/dur;}});});
    if(tot>mz){mz=tot;maior=L[0].c;}});
  var out={};
  meses.forEach(function(mm){var o=acc[mm.k];if(!o)return;var tot=0;Object.keys(o).forEach(function(k){tot+=o[k];});if(!tot)return;
    var G=1073741824,top=Object.keys(o).sort(function(a,b){return o[b]-o[a];}).slice(0,5).map(function(k){var t={k:k,gb:Math.round(o[k]/G*10)/10,pc:Math.round(o[k]/tot*1000)/10};if(OP_DS_EVT[k])t.ev=1;return t;});
    out[mm.k]={top:top,tot:Math.round(tot/G*10)/10,parc:maior>Date.UTC(Math.floor(mm.k/12),mm.k%12,1)};});
  return out;
}
/* Mês fechado não muda: o tamanho dos índices muda com o tempo, então o 1º cálculo depois da virada fica gravado em OP_DS_MES_<AAAA-MM> e é o que vale dali em diante.
 * cong = quando congelou; tarde = congelou mais de 3 dias depois do fechamento (pode diferir do valor original). */
function _dsCongela_(meses,dsv){
  var now=new Date(),kn=now.getUTCFullYear()*12+now.getUTCMonth(),p=props_(),out={};
  meses.forEach(function(m){var d=dsv[m.k];if(m.k>=kn){if(d)out[m.k]=d;return;}
    var y=Math.floor(m.k/12),pk='OP_DS_MES_'+y+'-'+('0'+(m.k%12+1)).slice(-2),s=p.getProperty(pk),f=null;if(s){try{f=JSON.parse(s);}catch(e){}}
    if(!f&&d){f={top:d.top.map(function(x){return {k:x.k,gb:x.gb,pc:x.pc};}),tot:d.tot,parc:d.parc,cong:now.toISOString(),tarde:now.getTime()-Date.UTC(y,m.k%12+1,1)>3*864e5};try{p.setProperty(pk,JSON.stringify(f));}catch(e){Logger.log('congelar %s: %s',pk,e.message);}}
    if(f){f.top.forEach(function(x){if(OP_DS_EVT[x.k])x.ev=1;else delete x.ev;});out[m.k]=f;}});
  return out;
}
/* Eventos que mais geram log em cada datasource do Top 5: contagem exata dos últimos DS_EV_DIAS dias, sem o frozen, que é lento.
 * Só nomes desta lista são aceitos: a tela nunca escolhe índice nem campo. Conta eventos, não GB. Ordem: do mais rápido ao mais lento (Firewall ~190 s).
 * refreshDsEventos (gatilho diário) grava o resultado na Propriedade OP_DSEV_<nome>; a tela só lê. Sem resultado gravado, calcula na hora e grava. */
var DS_EV_DIAS=7;
var OP_DS_EVT={
  'Cisco ISE':{ix:'logs-cisco_ise.log-*',f:'event.action',rot:['Evento','Event']},
  'Citrix NetScaler':{ix:'logs-citrix_adc.log-*',f:'citrix.name',rot:['Evento','Event']},
  'Syslog Linux (rsyslog)':{ix:'logs-tcp.lnx.rsyslog-*,logs-udp.lnx.rsyslog-*,logs-lnx.rsyslog-*',f:'log.syslog.appname',rot:['Aplicação','Application']},
  'Windows Security':{ix:'logs-system.security-*',f:'event.code',a:'event.action',rot:['Evento','Event']},
  'Firewall Palo Alto':{ix:'logs-panw.panos-*',f:'rule.name',a:'event.action',rot:['Regra','Rule'],sem:['Sem regra (ex.: logs USERID e SYSTEM)','No rule (e.g. USERID and SYSTEM logs)']}
};
function _dsEvBuild_(nome){
  var c=OP_DS_EVT[nome],SEM='__sem__',aggs={e:{terms:{field:c.f,size:5,shard_size:5000,missing:SEM}}};  // shard_size acima do nº de regras/eventos: contagem sem margem de erro
  if(c.a)aggs.e.aggs={a:{terms:{field:c.a,size:1,missing:SEM}}};
  var r=esSearch_(c.ix,{size:0,track_total_hits:true,query:{bool:{filter:[{range:{'@timestamp':{gte:'now-'+DS_EV_DIAS+'d'}}}],must_not:[{term:{_tier:'data_frozen'}}]}},aggs:aggs});
  var tot=(r.hits&&r.hits.total&&r.hits.total.value)||0,ag=(r.aggregations||{}).e||{},bk=ag.buckets||[];
  var top=bk.map(function(b){var ab=(b.a&&b.a.buckets&&b.a.buckets[0])||null;return {k:b.key===SEM?null:String(b.key),a:ab&&ab.key!==SEM?String(ab.key):null,n:b.doc_count,pc:tot?Math.round(b.doc_count/tot*1000)/10:0};});
  return {top:top,tot:tot,rot:c.rot,sem:c.sem||null,dias:DS_EV_DIAS,at:new Date().toISOString(),erro:ag.doc_count_error_upper_bound||0,parc:!!(r.timed_out||(r._shards&&r._shards.failed))};
}
function _dsEvProp_(nome){return 'OP_DSEV_'+Utilities.base64EncodeWebSafe(nome);}
function getDsEventos(nome){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  nome=String(nome);if(!Object.prototype.hasOwnProperty.call(OP_DS_EVT,nome)) throw new Error('Datasource sem detalhe de eventos: '+nome);
  var p=props_(),k=_dsEvProp_(nome),s=p.getProperty(k);if(s){try{return JSON.parse(s);}catch(e){}}
  var d=_dsEvBuild_(nome);try{p.setProperty(k,JSON.stringify(d));}catch(e){}
  return d;
}
/* Gatilho diário (e diagnóstico no editor): refaz a contagem exata e grava; se uma fonte falhar, mantém o último resultado dela. Leva ~5 min. */
function refreshDsEventos(){
  Object.keys(OP_DS_EVT).forEach(function(nome){var t=Date.now();
    try{var d=_dsEvBuild_(nome);props_().setProperty(_dsEvProp_(nome),JSON.stringify(d));Logger.log('%s · %s s · total %s%s · %s',nome,Math.round((Date.now()-t)/100)/10,d.tot,(d.parc?' (parcial)':'')+(d.erro?' (margem '+d.erro+')':' (sem margem)'),d.top.map(function(x){return (x.k||'(sem nome)')+(x.a?' ['+x.a+']':'')+' '+x.pc+'%';}).join(' | '));}
    catch(e){Logger.log('%s · %s s · ERRO: %s',nome,Math.round((Date.now()-t)/100)/10,e.message);}});
}
/* DIAGNÓSTICO — rode no editor: confere o Top 5 de datasources (e se a chave tem o privilégio "monitor"). */
function debugDatasources(){
  var now=new Date(),k=now.getUTCFullYear()*12+now.getUTCMonth(),mm=[{k:k-2},{k:k-1},{k:k}],r=_opDatasources_(mm);
  mm.forEach(function(x){Logger.log(Math.floor(x.k/12)+'-'+('0'+(x.k%12+1)).slice(-2)+' · '+JSON.stringify(r[x.k]||'sem dados'));});
  return r;
}
/* DIAGNÓSTICO — rode no editor: mostra o formato da resposta da API de Billing (não registra a chave). */
function debugBilling(){
  try{var os=ecFetch_('/api/v1/organizations').organizations||[];Logger.log('Organizações visíveis pela chave: %s',os.map(function(o){return o.id+' ('+o.name+')';}).join(', ')||'(nenhuma)');}
  catch(e){Logger.log('Listar organizações falhou: %s',e.message);}
  var org=ecOrg_();Logger.log('Organização usada: %s%s',org,props_().getProperty('EC_ORG_ID')?' (EC_ORG_ID)':' (1ª da chave)');
  var now=new Date(),from=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth()-2,1)).toISOString();
  var c=ecCharts_(org,from,now.toISOString()),d=(c.r&&c.r.data)||[];
  Logger.log('Endpoint %s · chaves da resposta: %s · buckets: %s',c.via,Object.keys(c.r||{}).join(', '),d.length);
  if(d[0])Logger.log('1º bucket: %s',JSON.stringify(d[0]).slice(0,1500));
  var b=_billing_();
  b.months.forEach(function(m){Logger.log('%s · %s ECU%s · deployments %s · IA %s · itens %s',m.m,m.cons,m.part?' (parcial)':'',JSON.stringify(m.dep),m.ia,JSON.stringify(m.itens||[]));Logger.log('   categorias: %s',JSON.stringify(m.cats||[]));});
  var pm=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth()-1,1)).toISOString(),pe=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),1)).toISOString();
  try{var q='?from='+encodeURIComponent(pm)+'&to='+encodeURIComponent(pe);Logger.log('items (bruto, mês anterior): %s',JSON.stringify(ecFetch_('/api/v1/billing/costs/'+org+'/items'+q)).slice(0,2500));}catch(e){Logger.log('items v1: %s',e.message);}
  return b;
}
/* DIAGNÓSTICO — rode no editor: confere cada fonte da Eng. Detecção e lista as regras sem tecnologia ("Outros"). */
function debugOperacional(){
  var d=buildOperational_();
  Logger.log('Erros por fonte: %s',JSON.stringify(d.errs));
  d.elastic.slice(-4).forEach(function(e){Logger.log('%s · %s regras · técnicas %s/%s · subtéc. %s/%s · %s',e.m,e.prod,e.tecCov,e.tecTot,e.subCov,e.subTot,e.fonte);});
  d.alertsByMonth.slice(-4).forEach(function(a){Logger.log('Alertas %s: %s (top: %s)',a.m,a.total,a.top[0]?a.top[0].k+' '+a.top[0].v:'—');});
  Logger.log('Tecnologias (%s): %s',d.elastic[d.elastic.length-1].m,JSON.stringify(d.techByMonth[d.elastic[d.elastic.length-1].m]));
  var outros=fetchRules_().filter(function(r){return r.enabled&&_opTec_(r)==='Outros';}).map(function(r){return r.name+' {idx: '+(r.index||[]).join(',')+' · tags: '+(r.tags||[]).join(',')+'}';});
  Logger.log('Regras sem tecnologia (%s): %s',outros.length,outros.slice(0,40).join(' | '));
  Logger.log('Servidores: %s · Fontes de log (top 10): %s',JSON.stringify(d.inv),JSON.stringify(d.logs.slice(0,10)));
  Logger.log('Criticidade: %s · Licença: %s',JSON.stringify(d.criticidade),JSON.stringify(d.lic.slice(-2)));
  return d;
}
function _isAdminMe_(){try{var mem=accFindUser_(accMembers_(),_me_());return !!(mem&&mem.ativo&&mem.papel==='Admin');}catch(e){return false;}}
/** Chamado pelo cliente — salva a nota de Melhorias/Próximas ações do mês (só Admin). Vazio apaga. */
function salvarNotaOp(ym,mel,prox){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  if(!_isAdminMe_()) throw new Error('Só Admin edita as notas.');
  if(!/^\d{4}-\d{2}$/.test(String(ym))) throw new Error('Mês inválido.');
  mel=String(mel||'').trim();prox=String(prox||'').trim();
  var k='OP_NOTA_'+ym,rec={mel:mel,prox:prox,by:_me_(),at:new Date().toISOString()},s=JSON.stringify(rec);
  if(Utilities.newBlob(s).getBytes().length>8500) throw new Error('Nota longa demais (limite ~8 KB por mês). Encurte o texto.');
  if(!mel&&!prox)props_().deleteProperty(k);else props_().setProperty(k,s);
  try{CacheService.getScriptCache().remove(OP_KEY+'_n');}catch(e){}
  return rec;
}
/* MIGRAÇÃO (rode uma vez no editor): copia a aba Highlights da planilha antiga (SHEET_ID) para as notas do portal.
 * Não sobrescreve nota que já exista. Depois disso a planilha pode ser desligada. */
function importarNotasDaPlanilha(){
  var id=props_().getProperty('SHEET_ID');if(!id)throw new Error('SHEET_ID não definida.');
  var v=SpreadsheetApp.openById(id).getSheetByName('Highlights').getDataRange().getValues(),n=0,pulou=[];
  for(var i=1;i<v.length;i++){if(!(v[i][0] instanceof Date))continue;
    var ym=Utilities.formatDate(v[i][0],'America/Sao_Paulo','yyyy-MM'),k='OP_NOTA_'+ym;if(props_().getProperty(k)){pulou.push(ym);continue;}
    var rec={mel:String(v[i][1]||'').trim(),prox:String(v[i][2]||'').trim(),by:'planilha',at:new Date().toISOString()};if(!rec.mel&&!rec.prox)continue;
    var s=JSON.stringify(rec);if(Utilities.newBlob(s).getBytes().length>8500){Logger.log('%s: texto longo demais, cortado',ym);rec.mel=rec.mel.slice(0,2500);rec.prox=rec.prox.slice(0,1200);s=JSON.stringify(rec);}
    props_().setProperty(k,s);n++;}
  try{CacheService.getScriptCache().remove(OP_KEY+'_n');}catch(e){}
  Logger.log('Notas importadas: %s · já existiam (mantidas): %s',n,pulou.join(', ')||'—');
}

function getOperational(){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  var cache=CacheService.getScriptCache();
  var hit=opGet_(cache); if(hit){try{return JSON.parse(hit);}catch(e){}}
  var data=buildOperational_();
  try{opPut_(cache,JSON.stringify(data));}catch(e){}
  return data;
}

/* Gatilho de tempo: aquece o cache do operacional (agende a cada 2h). */
function refreshOperational(){var data=buildOperational_();try{opPut_(CacheService.getScriptCache(),JSON.stringify(data));}catch(e){}}

/* ================== KPIs CSIRT — lê Triage_AI e Detalhados_INC (Google Sheets) ==================
 * Propriedades do script:
 *   SHEET_TRIAGE_ID    = <id da planilha Google "Triage_AI_Consolidado">
 *   SHEET_DETALHADO_ID = <id da planilha Google "Detalhados_INC_Consolidado">
 *   (aba "Consolidado" em ambas)
 * Métricas:
 *   MTTD AI      = coluna "MTTA" do Triage (offense iniciado -> criado/detectado pela IA), em min
 *   MTTA CSIRT   = coluna "mtta" do Detalhado, em min
 *   MTTR CSIRT   = coluna "mttr" do Detalhado, em min
 *   Funil        = Triage: total, IA (Human Review?=falso), N1 (Human Review?=verdadeiro), CSIRT=incidentes
 *   Incidentes   = Detalhado por mês x severidade (linhas com severidade válida)
 */
var CS_KEY = 'csirt_data_v5'; // v5: + drill-down de IA/N1 (troca a chave p/ não servir cache sem os campos novos)
// MTTA N1 = Criado -> N1 assumiu. A coluna ainda não vem no export da triagem; o primeiro destes
// nomes que existir na aba Consolidado é usado. Sem nenhum, mtta_n1 volta vazio.
var N1_ACK_COLS = ['N1 Assumido', 'Assumido em', 'Assigned at', 'Acknowledged at', 'Acknowledged'];
var CS_TTL = 2 * 60 * 60; // 2h
var CS_SEV = ['Critical','High','Medium','Low'];

function csPut_(cache,str){var n=Math.ceil(str.length/CHUNK),p={};for(var i=0;i<n;i++)p[CS_KEY+'_'+i]=str.substr(i*CHUNK,CHUNK);p[CS_KEY+'_n']=String(n);cache.putAll(p,CS_TTL);}
function csGet_(cache){var ns=cache.get(CS_KEY+'_n');if(!ns)return null;var n=parseInt(ns,10),ids=[];for(var i=0;i<n;i++)ids.push(CS_KEY+'_'+i);var got=cache.getAll(ids),o='';for(var j=0;j<n;j++){var s=got[CS_KEY+'_'+j];if(s==null)return null;o+=s;}return o;}

/* "HH:MM:SS" ou "HHHH:MM:SS" -> minutos (número) */
function _cmin(v){
  if(v==null||v==='') return null;
  // Date: o Sheets converteu "HH:MM:SS" em valor de tempo/duração (base 1899-12-30).
  // Extrai H:M:S pelos componentes (cobre durações < 24h; nosso dado é minutos/horas).
  if(Object.prototype.toString.call(v)==='[object Date]' && !isNaN(v.getTime())){
    return v.getHours()*60 + v.getMinutes() + v.getSeconds()/60;
  }
  // Número: fração do dia (duração serializada) -> minutos.
  if(typeof v==='number' && isFinite(v)) return v*24*60;
  var s=String(v).trim();
  var m=s.match(/^(\d+):(\d{2}):(\d{2})/);           // "H:MM:SS" ou "HHHH:MM:SS"
  if(m) return (+m[1])*60 + (+m[2]) + (+m[3])/60;
  var m2=s.match(/^(\d+):(\d{2})$/);                  // "H:MM" sem segundos
  if(m2) return (+m2[1])*60 + (+m2[2]);
  return null;
}
function _avg(a){var s=0,n=0;for(var i=0;i<a.length;i++){if(a[i]!=null&&!isNaN(a[i])){s+=a[i];n++;}}return n?s/n:null;}
function _r2(x){return x==null?null:Math.round(x*100)/100;}

/* Lê uma planilha (aba Consolidado) e devolve {header, rows} com índice por nome de coluna */
function _readSheet_(id, propName){
  if(!id) throw new Error('Defina '+propName+' (id da planilha Google) nas Propriedades do script.');
  var ss=SpreadsheetApp.openById(id);
  var sh=ss.getSheetByName('Consolidado')||ss.getSheets()[0];
  // getDisplayValues() devolve o TEXTO exibido (ex.: "00:02:50", "VERDADEIRO"),
  // evitando que o Sheets converta tempos em Date (bug de fuso na época 1899)
  // ou booleanos em tipos que o parser não reconhece.
  var vals=sh.getDataRange().getDisplayValues();
  var hdr=vals[0].map(function(h){return String(h).trim();});
  var idx={}; hdr.forEach(function(h,i){idx[h]=i;});
  return {idx:idx, rows:vals.slice(1)};
}

function buildCsirt_(){
  var p=props_();
  var T=_readSheet_(p.getProperty('SHEET_TRIAGE_ID'),'SHEET_TRIAGE_ID');
  var D=_readSheet_(p.getProperty('SHEET_DETALHADO_ID'),'SHEET_DETALHADO_ID');

  function col(o,name){ if(o.idx[name]==null) throw new Error('Coluna "'+name+'" não encontrada.'); return o.idx[name]; }

  // ---- agrupa por Competência (YYYY-MM) ----
  var tC=col(T,'Competência'), tL=col(T,'Mês_Ref'), tSev=col(T,'Severidade'), tHR=col(T,'Human Review?'), tMt=col(T,'MTTA');
  var tAV=col(T,'AI Veredict'), tTec=col(T,'Tecnologia'), tTit=col(T,'Título');
  var dC=col(D,'Competência'), dL=col(D,'Mês_Ref'), dSev=col(D,'Severidade'), dA=col(D,'mtta'), dR=col(D,'mttr');
  function colOpt(o,name){ return (o.idx[name]==null)?-1:o.idx[name]; }  // drill-down: opcionais
  var dVet=colOpt(D,'Vetor'), dPlat=colOpt(D,'platforma'), dTax=colOpt(D,'Taxonomia'),
      dTipo=colOpt(D,'Tipo da taxonomia'), dTit=colOpt(D,'Título'), dOid=colOpt(D,'offense id');
  var _isManual=function(r){ if(dOid<0)return false; return /^WB-\d+-\d{8}-\d+$/.test(String(r[dOid]||'').trim()); };
  // ---- Eficiência: colunas extras + parser de data/hora (getDisplayValues => string) ----
  var tImp=colOpt(T,'Impacto'), tCri=colOpt(T,'Criado'), tRes=colOpt(T,'Resolvido'), tAck=-1, tAckName=null;
  N1_ACK_COLS.forEach(function(n){ if(tAck<0&&T.idx[n]!=null){tAck=T.idx[n];tAckName=n;} });
  var dCriE=colOpt(D,'Criado em'), dDet=colOpt(D,'Detectado em'), dRep=colOpt(D,'Reportado em'), dCat=colOpt(D,'Categorização');
  function _dt(v){
    if(v==null||v==='')return null;
    if(Object.prototype.toString.call(v)==='[object Date]'&&!isNaN(v.getTime()))return v;
    var s=String(v).trim(),m=s.match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
    if(m)return new Date(+m[1],+m[2]-1,+m[3],+m[4],+m[5],+(m[6]||0));
    m=s.match(/(\d{2})\/(\d{2})\/(\d{4})[ ,]+(\d{2}):(\d{2})(?::(\d{2}))?/);
    if(m)return new Date(+m[3],+m[2]-1,+m[1],+m[4],+m[5],+(m[6]||0));
    var d=new Date(s);return isNaN(d.getTime())?null:d;
  }
  function _diffMin(a,b){var da=_dt(a),db=_dt(b);return (da&&db)?(db.getTime()-da.getTime())/60000:null;}
  var _DOW=['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'], _ORD=['Seg','Ter','Qua','Qui','Sex','Sáb','Dom'], _BK=['00-06','06-12','12-18','18-24'];
  function _bk(h){return h<6?0:h<12?1:h<18?2:3;}
  var eff_imp=[], eff_prec=[], eff_heat=[], eff_tc=[], eff_td=[];

  // Normaliza a Competência para "YYYY-MM" mesmo que o Sheets a tenha convertido em
  // data ("2026-09-01", "01/09/2026") ou que só reste o rótulo "Set/2026".
  var _MONPT={jan:'01',fev:'02',mar:'03',abr:'04',mai:'05',jun:'06',jul:'07',ago:'08',set:'09',out:'10',nov:'11',dez:'12'};
  function _ym(c,label){
    var s=String(c==null?'':c).trim();
    var m=s.match(/(\d{4})[-\/.](\d{2})/); if(m) return m[1]+'-'+m[2];          // 2026-09 / 2026-09-01
    m=s.match(/(\d{2})[\/.-](\d{2})[\/.-](\d{4})/); if(m) return m[3]+'-'+m[2];  // 01/09/2026
    var ml=String(label==null?'':label).trim().toLowerCase().match(/^([a-z]{3})\.?\/?\s*(\d{4})/);
    if(ml&&_MONPT[ml[1]]) return ml[2]+'-'+_MONPT[ml[1]];                        // "Set/2026"
    return s;
  }
  var comps={}; // YYYY-MM -> {label, tri:[], det:[]}
  // Rótulo do mês sempre "Out/2026", montado da Competência (a importação do Sheets pode virar "out./2026" ou data).
  var _MLAB=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  function _lab(c,l){ var m=String(c).match(/^(\d{4})-(\d{2})$/); return m?_MLAB[+m[2]-1]+'/'+m[1]:String(l); }
  function bucket(c,l){ if(!comps[c]) comps[c]={comp:c,label:_lab(c,l),tri:[],det:[]}; return comps[c]; }
  T.rows.forEach(function(r){ var c=r[tC],l=r[tL]; if((c==null||c==='')&&(l==null||l===''))return; bucket(_ym(c,l),String(l)).tri.push(r); });
  D.rows.forEach(function(r){ var c=r[dC],l=r[dL]; if((c==null||c==='')&&(l==null||l===''))return; bucket(_ym(c,l),String(l)).det.push(r); });

  var order=Object.keys(comps).sort();
  var months=[], incidents=[], mttd=[], mtta=[], mttr=[], mttaN1=[], mttrN1=[], funnels=[], inc_detail=[], tri_detail=[];
  // "Human Review?" robusto a locale/tipo: boolean, "true/false", "VERDADEIRO/FALSO", "sim/não", "1/0".
  var _HRTRUE={'true':1,'verdadeiro':1,'v':1,'sim':1,'s':1,'yes':1,'y':1,'1':1};
  var N=order.length, _hr=function(r){var h=r[tHR]; if(h===true)return true; return !!_HRTRUE[String(h).trim().toLowerCase()];};
  // ---- Falsos Positivos (por mês) ----
  var fp_pm=[], fpTech={}, fpHeat={}, ruleMap={};
  function _ens(obj,k){ if(!obj[k]){obj[k]=[];for(var i=0;i<N;i++)obj[k].push(0);} return obj[k]; }
  function _ensH(k){ if(!fpHeat[k]){fpHeat[k]={};CS_SEV.forEach(function(s){fpHeat[k][s]=[];for(var i=0;i<N;i++)fpHeat[k][s].push(0);});} return fpHeat[k]; }

  function sevSeries(rows, sevIdx, valFn){
    var o={}; CS_SEV.forEach(function(s){o[s]=[];});
    rows.forEach(function(r){ var s=r[sevIdx]; if(CS_SEV.indexOf(s)<0)return; var v=valFn(r); if(v!=null)o[s].push(v); });
    var out={}; CS_SEV.forEach(function(s){ out[s]=_r2(_avg(o[s])); }); return out;
  }

  order.forEach(function(c,mi){
    var g=comps[c], ml=g.label; months.push(ml);
    // incidentes por severidade (severidade válida)
    var cnt={}; CS_SEV.forEach(function(s){cnt[s]=0;}); var tot=0;
    g.det.forEach(function(r){ var s=r[dSev]; if(CS_SEV.indexOf(s)>=0){cnt[s]++;tot++;} });
    incidents.push({m:ml, Critical:cnt.Critical, High:cnt.High, Medium:cnt.Medium, Low:cnt.Low, total:tot});
    // ---- Drill-down de incidentes do mês (dimensões) ----
    var dd={vetor:{},plat:{},tax:{},tipo:{},origem:{Manual:0,'Automático':0},titulos:{}};
    function _inc(o,k){ k=(k==null||String(k).trim()==='')?'—':String(k).trim(); o[k]=(o[k]||0)+1; }
    g.det.forEach(function(r){
      if(CS_SEV.indexOf(r[dSev])<0)return;                 // só incidentes válidos (igual ao card)
      if(dVet>=0)_inc(dd.vetor,r[dVet]);
      if(dPlat>=0)_inc(dd.plat,r[dPlat]);
      if(dTax>=0)_inc(dd.tax,r[dTax]);
      if(dTipo>=0)_inc(dd.tipo,r[dTipo]);
      dd.origem[_isManual(r)?'Manual':'Automático']++;
      if(dTit>=0)_inc(dd.titulos,r[dTit]);
    });
    inc_detail.push({m:ml, dims:dd});
    // MTTD AI (triage MTTA col)
    var triVals=g.tri.map(function(r){return _cmin(r[tMt]);});
    var o1=sevSeries(g.tri,tSev,function(r){return _cmin(r[tMt]);}); o1.m=ml; o1.ov=_r2(_avg(triVals)); mttd.push(o1);
    // MTTR N1 (triage, só alertas com revisão humana): Criado -> Resolvido
    var n1min=function(r){ if(!_hr(r)||tCri<0||tRes<0)return null; var v=_diffMin(r[tCri],r[tRes]); return (v!=null&&v>=0)?v:null; };
    var o4=sevSeries(g.tri,tSev,n1min); o4.m=ml; o4.ov=_r2(_avg(g.tri.map(n1min))); mttrN1.push(o4);
    // MTTA N1: Criado -> N1 assumiu (vazio enquanto o export não trouxer a coluna)
    var n1ack=function(r){ if(!_hr(r)||tCri<0||tAck<0)return null; var v=_diffMin(r[tCri],r[tAck]); return (v!=null&&v>=0)?v:null; };
    var o5=sevSeries(g.tri,tSev,n1ack); o5.m=ml; o5.ov=_r2(_avg(g.tri.map(n1ack))); mttaN1.push(o5);
    // MTTA / MTTR CSIRT (detalhado)
    var detA=g.det.map(function(r){return _cmin(r[dA]);}), detR=g.det.map(function(r){return _cmin(r[dR]);});
    var o2=sevSeries(g.det,dSev,function(r){return _cmin(r[dA]);}); o2.m=ml; o2.ov=_r2(_avg(detA)); mtta.push(o2);
    var o3=sevSeries(g.det,dSev,function(r){return _cmin(r[dR]);}); o3.m=ml; o3.ov=_r2(_avg(detR)); mttr.push(o3);
    // funil do mês + quebra por criticidade. Só conta linhas com severidade válida (o export traz
    // algumas linhas vazias); o CSIRT separa os incidentes abertos manualmente (WB-…), que não vêm do funil.
    var ftot=0, fia=0, fn1=0, fman=0, fsev={};
    CS_SEV.forEach(function(s){ fsev[s]={ia:0,n1:0,cs:cnt[s]}; });
    g.tri.forEach(function(r){ var s=r[tSev]; if(!fsev[s])return; ftot++; if(_hr(r)){fn1++;fsev[s].n1++;} else {fia++;fsev[s].ia++;} });
    g.det.forEach(function(r){ if(CS_SEV.indexOf(r[dSev])>=0&&_isManual(r))fman++; });
    // drill-down de IA e N1 do mês (mesma ideia do drill de incidentes, com as colunas da triagem);
    // títulos limitados aos 100 mais frequentes de cada etapa no mês, para não pesar o cache
    var _tdd=function(){return {tec:{},sev:{},ver:{},imp:{},titulos:{}};}, tdd={ia:_tdd(),n1:_tdd()};
    g.tri.forEach(function(r){ if(!fsev[r[tSev]])return; var o=_hr(r)?tdd.n1:tdd.ia;
      _inc(o.tec,r[tTec]); _inc(o.sev,r[tSev]); _inc(o.ver,r[tAV]); if(tImp>=0)_inc(o.imp,r[tImp]); _inc(o.titulos,r[tTit]); });
    ['ia','n1'].forEach(function(k){ var t=tdd[k].titulos, top={};
      Object.keys(t).sort(function(a,b){return t[b]-t[a];}).slice(0,100).forEach(function(x){top[x]=t[x];}); tdd[k].titulos=top; });
    tri_detail.push({m:ml, ia:tdd.ia, n1:tdd.n1});
    funnels.push({m:ml,total:ftot,ia:fia,n1:fn1,csirt:tot,csirt_manual:fman,sev:fsev,
      ia_pct:ftot?Math.round(fia/ftot*10000)/100:0, n1_pct:ftot?Math.round(fn1/ftot*10000)/100:0, csirt_pct:ftot?Math.round(tot/ftot*10000)/100:0});
    // ---- FP do mês ----
    var nfp=0,ntp=0,nauto=0,automin=0;
    g.tri.forEach(function(r){
      var ver=String(r[tAV]||''); var isFP=(ver==='False Positive'); if(ver==='True Positive')ntp++;
      if(!isFP)return; nfp++;
      if(!_hr(r)){nauto++; var mm=_cmin(r[tMt]); if(mm!=null)automin+=mm;}
      var tec=String(r[tTec]||'—').trim()||'—'; _ens(fpTech,tec)[mi]++;
      var sv=r[tSev]; if(CS_SEV.indexOf(sv)<0)sv='Low'; _ensH(tec)[sv][mi]++;
      var tit=String(r[tTit]||'—').trim()||'—';
      if(!ruleMap[tit])ruleMap[tit]={tech:{},pm:[]};
      if(!ruleMap[tit].pm.length)for(var z=0;z<N;z++)ruleMap[tit].pm.push(0);
      ruleMap[tit].pm[mi]++; ruleMap[tit].tech[tec]=(ruleMap[tit].tech[tec]||0)+1;
    });
    fp_pm.push({m:ml,total:ftot,fp:nfp,tp:ntp,fp_auto:nauto,auto_min:Math.round(automin)});

    // ===== Eficiência (por mês) =====
    // 1) Impacto real + 2) Precisão por tecnologia + 5) Heatmap dia×hora (Triage)
    var impW=0,impT=0,impSev={},prec={},grid=[];
    CS_SEV.forEach(function(s){impSev[s]={w:0,t:0};});
    for(var gi=0;gi<7;gi++){grid.push([0,0,0,0]);}
    g.tri.forEach(function(r){
      var wi=String(r[tImp]||'').trim().toLowerCase()==='with impact';
      impT++; if(wi)impW++;
      var sv=r[tSev]; if(CS_SEV.indexOf(sv)>=0){impSev[sv].t++; if(wi)impSev[sv].w++;}
      var tec=String(r[tTec]||'—').trim()||'—'; if(!prec[tec])prec[tec]={tp:0,fp:0};
      var av=String(r[tAV]||''); if(av==='True Positive')prec[tec].tp++; else if(av==='False Positive')prec[tec].fp++;
      if(tCri>=0){var dt=_dt(r[tCri]); if(dt){var di=_ORD.indexOf(_DOW[dt.getDay()]); if(di>=0)grid[di][_bk(dt.getHours())]++;}}
    });
    eff_imp.push({m:ml,w:impW,t:impT,sev:impSev});
    eff_prec.push({m:ml,tech:prec});
    eff_heat.push({m:ml,grid:grid});
    // 3) tempo + 4) SLA + 6) Threat×Compliance (Detalhados)
    var tc={threat:0,comp:0}, td=[];
    g.det.forEach(function(r){
      if(CS_SEV.indexOf(r[dSev])<0)return;
      var cat=String(r[dCat]||'').trim(); if(cat==='Threat')tc.threat++; else if(cat==='Compliance')tc.comp++;
      td.push({s:String(r[dSev]),
        det:(dCriE>=0&&dDet>=0)?_diffMin(r[dCriE],r[dDet]):null,
        rep:(dDet>=0&&dRep>=0)?_diffMin(r[dDet],r[dRep]):null,
        mttr:_cmin(r[dR])});
    });
    eff_tc.push({m:ml,threat:tc.threat,comp:tc.comp});
    eff_td.push({m:ml,rows:td});
  });

  // funil do último mês = o mesmo cálculo mensal acima (antes era refeito aqui com outra regra)
  var funnel=funnels[funnels.length-1];

  var cur={mttd:mttd.length?mttd[mttd.length-1].ov:null, mtta:mtta.length?mtta[mtta.length-1].ov:null, mttr:mttr.length?mttr[mttr.length-1].ov:null,
    n1:mttrN1.length?mttrN1[mttrN1.length-1].ov:null, n1a:mttaN1.length?mttaN1[mttaN1.length-1].ov:null};

  // ---- Pontos Chave / Pontos de Atenção (derivados) ----
  var key=[], att=[];
  var L=mttr.length-1, P=L-1;
  if(funnel.ia_pct>=60) key.push('Automação por IA em '+funnel.ia_pct+'% dos alertas triados ('+funnel.ia+' de '+funnel.total+') — só '+funnel.csirt_pct+'% escalaram ao CSIRT.');
  if(P>=0 && mttr[L].ov!=null && mttr[P].ov!=null){
    var d=mttr[L].ov-mttr[P].ov, pc=mttr[P].ov?Math.round(Math.abs(d)/mttr[P].ov*100):0;
    (d<=0?key:att).push('MTTR '+(d<=0?'caiu':'subiu')+' de '+mttr[P].ov+' para '+mttr[L].ov+' min ('+pc+'%) vs '+mttr[P].m+'.');
  }
  if(P>=0){ var di=incidents[L].total-incidents[P].total;
    (di<=0?key:att).push('Incidentes '+(di<=0?'reduziram':'aumentaram')+' de '+incidents[P].total+' para '+incidents[L].total+' vs '+incidents[P].m+'.'); }
  if(cur.mtta!=null && cur.mtta<5) key.push('MTTA CSIRT em '+cur.mtta+' min — dentro da meta de resposta.');
  // inversão: Low com MTTR > High (sinal de fila/priorização)
  var lastR=mttr[L];
  if(lastR && lastR.Low!=null && lastR.High!=null && lastR.Low>lastR.High)
    att.push('MTTR de severidade Low ('+lastR.Low+' min) acima de High ('+lastR.High+' min) — revisar priorização de fila.');
  if(cur.mttr!=null && cur.mttr>60) att.push('MTTR CSIRT em '+cur.mttr+' min no mês — acima de 1h; avaliar gargalos de contenção.');
  if(!key.length) key.push('Sem destaques positivos calculados para o período.');
  if(!att.length) att.push('Nenhum ponto de atenção crítico no período.');

  // ---- monta objeto FP (top 40 regras, tecnologia dominante) ----
  var rules=[];
  for(var tit in ruleMap){ var r=ruleMap[tit]; var tot2=0; for(var i=0;i<r.pm.length;i++)tot2+=r.pm[i];
    var domT='—',domC=-1; for(var tk in r.tech){ if(r.tech[tk]>domC){domC=r.tech[tk];domT=tk;} }
    rules.push({title:tit, tech:domT, pm:r.pm, total:tot2}); }
  rules.sort(function(a,b){return b.total-a.total;}); rules=rules.slice(0,40);
  var fp={months:months, per_month:fp_pm, tech:fpTech, heat:fpHeat, rules:rules};

  return {updated:Utilities.formatDate(new Date(),'America/Sao_Paulo','dd/MM/yyyy HH:mm'),
    months:months, cur:cur, funnel:funnel, funnels:funnels, incidents:incidents,
    mttd_ai:mttd, mtta_n1:mttaN1, mtta_n1_col:tAckName, mttr_n1:mttrN1, mtta_csirt:mtta, mttr_csirt:mttr, key_points:key, attention:att, fp:fp, inc_detail:inc_detail, tri_detail:tri_detail,
    eff:{impacto:eff_imp, precisao:eff_prec, heat:eff_heat, threatcomp:eff_tc, tempo:eff_td, buckets:_BK, days:_ORD}};
}

function getCsirt(){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  var cache=CacheService.getScriptCache();
  var hit=csGet_(cache); if(hit){try{return JSON.parse(hit);}catch(e){}}
  var data=buildCsirt_();
  try{csPut_(cache,JSON.stringify(data));}catch(e){}
  return data;
}

/* Gatilho de tempo: aquece o cache do CSIRT (agende a cada 2h). */
function refreshCsirt(){var data=buildCsirt_();try{csPut_(CacheService.getScriptCache(),JSON.stringify(data));}catch(e){}}

/* ================== VAZAMENTO DE CREDENCIAIS — Tempest Resonant (DRP) ==================
 * Lê o data stream do Elastic (credenciais expostas), agrega por mês x grupo e serve ao portal.
 *
 * SETUP (Propriedades do script):
 *   ES_URL     = https://SEU-ELASTICSEARCH:9200   (recomendado; sem barra no final)
 *                A API key (ES_API_KEY) precisa de privilégio READ no índice abaixo.
 *   -- OU, se ES_URL não for definido, usa o console proxy do Kibana (KIBANA_URL + ES_API_KEY).
 *
 * Grupos: Corporativo = domínios *example* / *examplenet* / us-example.com, exceto shop.example.com
 *         Externo     = demais domínios (loja online, gmail, hotmail, terceiros…)
 */
var RZ_INDEX = 'logs-resonant_credentials_exposure-resonant';
var RZ_KEY   = 'resonant_data_' + CODE_VERSION;
var RZ_TTL   = 2 * 60 * 60; // 2h

/* Filtro reutilizável: domínios corporativos (exceto a Loja). */
function rzCorpQuery_(){
  return {bool:{
    must:[{bool:{minimum_should_match:1,should:[
      {wildcard:{'user.domain.keyword':'*example*'}},
      {wildcard:{'user.domain.keyword':'*examplenet*'}},
      {term:{'user.domain.keyword':'us-example.com'}}
    ]}}],
    must_not:[{term:{'user.domain.keyword':'shop.example.com'}}]
  }};
}

/* Executa _search no Elastic. Prefere ES_URL (direto); fallback = console proxy do Kibana. */
function rzSearch_(body){return esSearch_(RZ_INDEX,body);}
/* _search genérico (índice/padrão). Prefere ES_URL; deriva .kb.→.es.; fallback = console proxy do Kibana. */
function esSearch_(index,body){
  var p=props_();
  var apiKey=p.getProperty('ES_API_KEY');
  if(!apiKey) throw new Error('Defina ES_API_KEY nas Propriedades do script.');
  var esUrl=p.getProperty('ES_URL');
  var kb=p.getProperty('KIBANA_URL');
  // Elastic Cloud: o endpoint do ES é o do Kibana trocando ".kb." por ".es.".
  if(!esUrl && kb && kb.indexOf('.kb.')>-1) esUrl=kb.replace('.kb.','.es.');
  var headers={'Authorization':'ApiKey '+apiKey,'Content-Type':'application/json'};
  var url;
  if(esUrl){
    url=esUrl.replace(/\/+$/,'')+'/'+encodeURIComponent(index).replace(/%2C/g,',')+'/_search';
  }else{
    if(!kb) throw new Error('Defina ES_URL (recomendado) ou KIBANA_URL nas Propriedades do script.');
    headers['kbn-xsrf']='true';
    url=kb.replace(/\/+$/,'')+'/api/console/proxy?path='+encodeURIComponent(index+'/_search')+'&method=POST';
  }
  var res=UrlFetchApp.fetch(url,{method:'post',headers:headers,payload:JSON.stringify(body),muteHttpExceptions:true});
  var code=res.getResponseCode();
  if(code!==200) throw new Error('Elastic _search HTTP '+code+': '+res.getContentText().slice(0,300));
  return JSON.parse(res.getContentText());
}

/* Monta o snapshot de credenciais expostas (mês a mês + agregado). */
function buildResonant_(){
  var CORP=rzCorpQuery_(), EXT={bool:{must_not:[rzCorpQuery_()]}};
  var grpAggs={
    emails:{cardinality:{field:'user.email.keyword'}},
    senha:{filter:{term:{'credential.has_password':true}}},
    fraca:{filter:{range:{'credential.password_length':{lt:8}}}},
    cpf:{filter:{term:{'credential.national_id.has_cpf':true}}},
    cnpj:{filter:{term:{'credential.national_id.has_cnpj':true}}}
  };
  var body={
    size:0,
    query:{bool:{filter:[{exists:{field:'credential.created_at'}}]}},
    aggs:{
      meses:{date_histogram:{field:'credential.created_at',calendar_interval:'month',time_zone:'America/Sao_Paulo',min_doc_count:1,format:'yyyy-MM'},
        aggs:{
          grupos:{filters:{filters:{Corporativo:CORP,Externo:EXT}},aggs:grpAggs},
          fonte:{terms:{field:'resonant.source.keyword',size:12,missing:'N/D'}},
          stealer:{terms:{field:'resonant.stealer_family.keyword',size:10}},
          status:{terms:{field:'resonant.finding.status',size:6,missing:0}},
          senhafx:{filter:CORP,aggs:{faixa:{range:{field:'credential.password_length',ranges:[
            {key:'Fraca',to:8},{key:'Media',from:8,to:12},{key:'Forte',from:12}]}}}}
        }},
      gruposAll:{filters:{filters:{Corporativo:rzCorpQuery_(),Externo:{bool:{must_not:[rzCorpQuery_()]}}}},
        aggs:{emails:{cardinality:{field:'user.email.keyword'}}}}
    }
  };
  var resp=rzSearch_(body);
  var ag=resp.aggregations||{};
  var out={months:[],data:{},distAll:{corp:0,ext:0},updated:new Date().toISOString(),code_version:CODE_VERSION};
  function grp(b){return {creds:b.doc_count,emails:(b.emails&&b.emails.value)||0,senha:(b.senha&&b.senha.doc_count)||0,
    fraca:(b.fraca&&b.fraca.doc_count)||0,cpf:(b.cpf&&b.cpf.doc_count)||0,cnpj:(b.cnpj&&b.cnpj.doc_count)||0};}
  var mb=(ag.meses&&ag.meses.buckets)||[];
  mb.forEach(function(m){
    var key=m.key_as_string; out.months.push(key);
    var g=m.grupos.buckets;
    var st={Novo:0,Tratativa:0,Resolvido:0};
    ((m.status&&m.status.buckets)||[]).forEach(function(s){
      var k=String(s.key);
      if(k==='1') st.Tratativa+=s.doc_count; else if(k==='2') st.Resolvido+=s.doc_count; else st.Novo+=s.doc_count;
    });
    var fx={Forte:0,Media:0,Fraca:0};
    ((m.senhafx&&m.senhafx.faixa&&m.senhafx.faixa.buckets)||[]).forEach(function(r){fx[r.key]=r.doc_count;});
    out.data[key]={
      corp:grp(g.Corporativo), ext:grp(g.Externo),
      fonte:((m.fonte&&m.fonte.buckets)||[]).map(function(x){return [x.key,x.doc_count];}),
      stealer:((m.stealer&&m.stealer.buckets)||[]).map(function(x){return [x.key,x.doc_count];}),
      status:st, senha:fx
    };
  });
  var ga=(ag.gruposAll&&ag.gruposAll.buckets)||{};
  out.distAll.corp=(ga.Corporativo&&ga.Corporativo.emails.value)||0;
  out.distAll.ext=(ga.Externo&&ga.Externo.emails.value)||0;
  return out;
}

function rzPut_(cache,str){var n=Math.ceil(str.length/CHUNK),p={};for(var i=0;i<n;i++)p[RZ_KEY+'_'+i]=str.substr(i*CHUNK,CHUNK);p[RZ_KEY+'_n']=String(n);cache.putAll(p,RZ_TTL);}
function rzGet_(cache){var ns=cache.get(RZ_KEY+'_n');if(!ns)return null;var n=parseInt(ns,10),ids=[];for(var i=0;i<n;i++)ids.push(RZ_KEY+'_'+i);var got=cache.getAll(ids),o='';for(var j=0;j<n;j++){var s=got[RZ_KEY+'_'+j];if(s==null)return null;o+=s;}return o;}

/** Chamado pelo cliente (google.script.run) — snapshot de credenciais expostas. */
function getResonant(){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  var cache=CacheService.getScriptCache();
  var hit=rzGet_(cache); if(hit){try{return JSON.parse(hit);}catch(e){}}
  var data=buildResonant_();
  try{rzPut_(cache,JSON.stringify(data));}catch(e){}
  return data;
}

/* Gatilho de tempo: aquece o cache do Resonant (agende a cada 2–6h). */
function refreshResonant(){var data=buildResonant_();try{rzPut_(CacheService.getScriptCache(),JSON.stringify(data));}catch(e){}}

/* DIAGNÓSTICO — rode no editor para validar a conexão/consulta ao data stream. */
function debugResonant(){var d=buildResonant_();Logger.log('meses: %s', d.months.join(', '));Logger.log('distinct corp/ext: %s / %s', d.distAll.corp, d.distAll.ext);d.months.forEach(function(m){var x=d.data[m];Logger.log('%s | corp %s (%s ids) | ext %s (%s ids)', m, x.corp.creds, x.corp.emails, x.ext.creds, x.ext.emails);});return d;}


/* ================== CYBER OT — Claroty xDome (Elastic) ==================
 * Data streams: logs-claroty_xdome.{alert,event,vulnerability}-claroty
 * - Alertas: a integração re-consulta a API e regrava o estado → deduplica por claroty_xdome.alert.id
 *   e usa o documento mais recente (top_hits por @timestamp; empate → Resolved prevalece).
 * - Eventos: sem event.id → agregados por @timestamp (mês) × tipo origem × tipo destino × origem.
 * - Saúde: contagem de documentos de erro por classe (error.message) em cada data stream.
 * MITRE: ATT&CK for ICS (mitre_technique.ics.ids) + Enterprise (mitre_technique.enterprise.ids).
 */
var OT_ALERT = 'logs-claroty_xdome.alert-claroty';
var OT_EVENT = 'logs-claroty_xdome.event-claroty';
var OT_ALL   = 'logs-claroty_xdome.*-claroty';
var OT_KEY   = 'claroty_data_' + CODE_VERSION;
var OT_TTL   = 2 * 60 * 60; // 2h

function _ymSP_(iso){if(!iso)return '';var d=new Date(iso);if(isNaN(d))return String(iso).slice(0,7);return Utilities.formatDate(d,'America/Sao_Paulo','yyyy-MM');}
function _dSP_(iso){if(!iso)return '';var d=new Date(iso);if(isNaN(d))return String(iso).slice(0,10);return Utilities.formatDate(d,'America/Sao_Paulo','yyyy-MM-dd');}
function _arr_(v){return v==null?[]:(Array.isArray(v)?v:[v]);}
function _mp_(q){return {match_phrase:{'error.message':q}};}

function buildClaroty_(){
  /* 1) Alertas únicos (estado mais recente) */
  var SRC=['@timestamp','event.severity','claroty_xdome.alert.id','claroty_xdome.alert.friendly_name','claroty_xdome.alert.name',
    'claroty_xdome.alert.type_name','claroty_xdome.alert.category','claroty_xdome.alert.status','claroty_xdome.alert.detected_time',
    'claroty_xdome.alert.devices_count','claroty_xdome.alert.ot_devices_count','claroty_xdome.alert.it_devices_count','claroty_xdome.alert.iot_devices_count',
    'claroty_xdome.alert.mitre_technique.ics.ids','claroty_xdome.alert.mitre_technique.enterprise.ids'];
  var ra=esSearch_(OT_ALERT,{size:0,query:{bool:{filter:[{exists:{field:'claroty_xdome.alert.id'}}]}},
    aggs:{ids:{terms:{field:'claroty_xdome.alert.id',size:2000},aggs:{
      det:{min:{field:'claroty_xdome.alert.detected_time'}},
      sev:{max:{field:'event.severity'}},
      last:{top_hits:{size:3,sort:[{'@timestamp':{order:'desc'}}],_source:{includes:SRC}}}}}}});
  var alerts=[];
  (((ra.aggregations||{}).ids||{}).buckets||[]).forEach(function(b){
    var hits=(b.last&&b.last.hits&&b.last.hits.hits)||[];if(!hits.length)return;
    var top=hits[0]._source||{},ts=top['@timestamp'];
    var resolved=hits.some(function(h){var s=h._source||{};return s['@timestamp']===ts&&(((s.claroty_xdome||{}).alert||{}).status==='Resolved');});
    var a=(top.claroty_xdome||{}).alert||{},m=a.mitre_technique||{};
    var det=(b.det&&b.det.value_as_string)||a.detected_time;
    alerts.push({id:String(b.key),nm:a.friendly_name||a.name||String(b.key),tp:a.type_name||'',cat:a.category||'',
      st:resolved?'Resolved':(a.status||'Unresolved'),det:_dSP_(det),ym:_ymSP_(det),
      dv:a.devices_count!=null?a.devices_count:null,ot:a.ot_devices_count!=null?a.ot_devices_count:null,it:a.it_devices_count!=null?a.it_devices_count:null,
      sev:(b.sev&&b.sev.value!=null)?b.sev.value:((top.event||{}).severity||null),
      ics:_arr_((m.ics||{}).ids),ent:_arr_((m.enterprise||{}).ids),seen:_dSP_(ts)});
  });
  alerts.sort(function(x,y){return x.det<y.det?-1:(x.det>y.det?1:0);});

  /* 2) Eventos OT por mês × origem × destino */
  var re=esSearch_(OT_EVENT,{size:0,query:{bool:{filter:[{exists:{field:'claroty_xdome.event.type'}}]}},
    aggs:{m:{date_histogram:{field:'@timestamp',calendar_interval:'month',time_zone:'America/Sao_Paulo',format:'yyyy-MM',min_doc_count:1},aggs:{
      tp:{terms:{field:'claroty_xdome.event.type',size:20}},
      s:{terms:{field:'claroty_xdome.event.source.device.type',size:20,missing:'N/D'},aggs:{
        d:{terms:{field:'claroty_xdome.event.destination.device.type',size:20,missing:'N/D'},aggs:{
          n:{terms:{field:'claroty_xdome.event.source.device.name',size:200,missing:''}}}}}}}}}});
  var ev=[],evTypes=[];
  (((re.aggregations||{}).m||{}).buckets||[]).forEach(function(mb){var ym=mb.key_as_string;
    ((mb.tp&&mb.tp.buckets)||[]).forEach(function(t){evTypes.push([ym,t.key,t.doc_count]);});
    ((mb.s&&mb.s.buckets)||[]).forEach(function(sb){((sb.d&&sb.d.buckets)||[]).forEach(function(db){((db.n&&db.n.buckets)||[]).forEach(function(nb){
      ev.push([ym,sb.key,db.key,nb.key||null,nb.doc_count]);});});});});

  /* 3) Saúde da coleta por data stream */
  var CLS={
      ok:{bool:{must_not:[{exists:{field:'error.message'}}]}},
      cel:_mp_('no such overload'),
      api422:{bool:{minimum_should_match:1,should:[_mp_('422'),_mp_('valid dictionary')]}},
      auth:{bool:{minimum_should_match:1,should:[_mp_('1006'),_mp_('Invalid authentication')]}},
      transient:{bool:{minimum_should_match:1,should:[_mp_('502'),_mp_('503'),_mp_('504'),_mp_('timeout'),_mp_('Client.Timeout exceeded'),_mp_('deadline'),_mp_('Internal server error'),_mp_('Bad Gateway')]}},
      nodev:{bool:{filter:[{exists:{field:'claroty_xdome.alert.id'}}],must_not:[{exists:{field:'claroty_xdome.alert.device.name'}}]}}};
  var rh=esSearch_(OT_ALL,{size:0,aggs:{ds:{terms:{field:'data_stream.dataset',size:10},aggs:{
    first:{min:{field:'@timestamp'}},
    last:{max:{field:'@timestamp'}},
    lastok:{filter:CLS.ok,aggs:{t:{max:{field:'@timestamp'}}}},
    lasterr:{filter:{exists:{field:'error.message'}},aggs:{t:{max:{field:'@timestamp'}},
      top:{top_hits:{size:1,sort:[{'@timestamp':{order:'desc'}}],_source:{includes:['error.message','@timestamp']}}}}},
    cls:{filters:{filters:CLS}},
    r24:{filter:{range:{'@timestamp':{gte:'now-24h'}}},aggs:{cls:{filters:{filters:CLS}}}},
    r7:{filter:{range:{'@timestamp':{gte:'now-7d'}}},aggs:{cls:{filters:{filters:CLS}}}}}}}});
  function pack(total,c){var g=function(n){return (c&&c[n]&&c[n].doc_count)||0;};
    var h={total:total,ok:g('ok'),cel:g('cel'),api422:g('api422'),auth:g('auth'),transient:g('transient'),nodev:g('nodev')};
    h.other=Math.max(0,h.total-h.ok-h.cel-h.api422-h.auth-h.transient);return h;}
  var health={};
  (((rh.aggregations||{}).ds||{}).buckets||[]).forEach(function(b){
    var k=String(b.key).replace('claroty_xdome.','');
    var h=pack(b.doc_count,b.cls&&b.cls.buckets);
    h.first=(b.first&&b.first.value_as_string)||'';h.last=(b.last&&b.last.value_as_string)||'';
    h.lastOk=(b.lastok&&b.lastok.t&&b.lastok.t.value_as_string)||'';
    h.lastErr=(b.lasterr&&b.lasterr.t&&b.lasterr.t.value_as_string)||'';
    var th=b.lasterr&&b.lasterr.top&&b.lasterr.top.hits&&b.lasterr.top.hits.hits;
    h.lastErrMsg=th&&th.length?String(((th[0]._source||{}).error||{}).message||'').slice(0,240):'';
    h.r24=pack(b.r24?b.r24.doc_count:0,b.r24&&b.r24.cls&&b.r24.cls.buckets);
    h.r7=pack(b.r7?b.r7.doc_count:0,b.r7&&b.r7.cls&&b.r7.cls.buckets);
    health[k]=h;});

  return {alerts:alerts,ev:ev,evTypes:evTypes,health:health,updated:new Date().toISOString(),code_version:CODE_VERSION};
}

function otPut_(cache,str){var n=Math.ceil(str.length/CHUNK),p={};for(var i=0;i<n;i++)p[OT_KEY+'_'+i]=str.substr(i*CHUNK,CHUNK);p[OT_KEY+'_n']=String(n);cache.putAll(p,OT_TTL);}
function otGet_(cache){var ns=cache.get(OT_KEY+'_n');if(!ns)return null;var n=parseInt(ns,10),ids=[];for(var i=0;i<n;i++)ids.push(OT_KEY+'_'+i);var got=cache.getAll(ids),o='';for(var j=0;j<n;j++){var s=got[OT_KEY+'_'+j];if(s==null)return null;o+=s;}return o;}

/** Chamado pelo cliente (google.script.run) — snapshot Cyber OT (Claroty). */
function getClaroty(){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  var cache=CacheService.getScriptCache();
  var hit=otGet_(cache); if(hit){try{return JSON.parse(hit);}catch(e){}}
  var data=buildClaroty_();
  try{otPut_(cache,JSON.stringify(data));}catch(e){}
  return data;
}

/* Gatilho de tempo: aquece o cache do Claroty (agende a cada 2h). */
function refreshClaroty(){var data=buildClaroty_();try{otPut_(CacheService.getScriptCache(),JSON.stringify(data));}catch(e){}}

/* DIAGNÓSTICO — rode no editor para validar as consultas aos data streams do Claroty. */
function debugClaroty(){var d=buildClaroty_();
  Logger.log('alertas únicos: %s (abertos: %s)', d.alerts.length, d.alerts.filter(function(a){return a.st!=='Resolved';}).length);
  d.alerts.forEach(function(a){Logger.log('#%s %s | %s | %s | ICS %s', a.id, a.nm, a.det, a.st, a.ics.join(' '));});
  var tot=d.ev.reduce(function(s,r){return s+r[4];},0);Logger.log('eventos OT: %s em %s linhas', tot, d.ev.length);
  Object.keys(d.health).forEach(function(k){var h=d.health[k];Logger.log('saúde %s: total %s · ok %s · cel %s · 422 %s · auth %s · transit %s · outros %s · sem device %s', k,h.total,h.ok,h.cel,h.api422,h.auth,h.transient,h.other,h.nodev);Logger.log('   24h: %s docs · ok %s · erros %s | 7d: ok %s · erros %s | última OK %s | último erro %s: %s', h.r24.total,h.r24.ok,h.r24.total-h.r24.ok,h.r7.ok,h.r7.total-h.r7.ok,h.lastOk||'—',h.lastErr||'—',h.lastErrMsg);});
  return d;}
/* ================== INVENTÁRIO DE SERVIDORES — CMDB × Cortex XDR × SIEM (v25) ==================
 * CMDB  : logs-servicenow.event-servicenow_cmdb (classes de servidor). A carga completa é eventual e os dias seguintes
 *         trazem só os CIs alterados → janela INV_CMDB_WIN (30d) para pegar a última carga completa.
 * Cortex: índice lookup cortex_endpoints_lookup (Propriedade CORTEX_INDEX para trocar); só agentes tipo SERVER
 * SIEM  : hosts com TELEMETRIA PRÓPRIA na janela (Windows Event Log, Syslog, Elastic Agent, auditoria de BD).
 *         Menções em integrações de terceiros (Cortex alerts, Tenable, Guardicore…) não contam.
 * Chave de comparação: hostname em minúsculo, sem domínio (primeiro rótulo).
 */
var INV_CMDB  = 'logs-servicenow.event-servicenow_cmdb';
var INV_SIEM  = 'logs-*,-logs-ti_misp*';
var INV_CMDB_WIN = 'now-30d';
var INV_KEY   = 'inv_data_' + CODE_VERSION;
var INV_TTL   = 2 * 60 * 60; // 2h
var INV_OWN_PREFIX = ['system.','windows.','winlog.','tcp.','udp.','elastic_agent','endpoint.'];
var INV_OWN_EXACT  = ['ms_sql_audit','oracle.audit','generic'];
var INV_CX_FIELDS = {
  name:['endpoint_name','hostname','host_name','host.name','name','endpoint.name','cortex.endpoint_name'],
  type:['endpoint_type','type','endpoint.type','cortex.endpoint_type'],
  status:['endpoint_status','status','endpoint.status','cortex.endpoint_status'],
  os:['operating_system','os','os_name','host.os.name','endpoint.os'],
  ver:['endpoint_version','agent_version','version','endpoint.version'],
  op:['operational_status','endpoint.operational_status'],
  cs:['content_status','endpoint.content_status'],
  last:['last_seen','endpoint.last_seen']
};

function _invNorm_(h){if(h==null)return '';var s=String(h).trim().toLowerCase();if(!s)return '';s=s.split('\\').pop();return s.split('.')[0];}
function _invJunk_(n){return !n||n.indexOf('/')>=0||n==='unknown'||n==='localhost'||/^macbook/.test(n);}
function _get_(o,path){if(!o)return undefined;if(o[path]!==undefined)return o[path];var p=path.split('.'),c=o;for(var i=0;i<p.length;i++){if(c==null)return undefined;c=c[p[i]];}return c;}
function _pick_(src,cands){for(var i=0;i<cands.length;i++){var v=_get_(src,cands[i]);if(v!==undefined&&v!==null&&v!=='')return {f:cands[i],v:Array.isArray(v)?v[0]:v};}return null;}
function _invOwnFam_(ds){var out={};ds.forEach(function(x){
  if(/^(system|windows|winlog)\./.test(x))out['Windows']=1;else if(/^(tcp|udp)\./.test(x))out['Syslog']=1;
  else if(/^(elastic_agent|endpoint\.)/.test(x))out['Elastic Agent']=1;else if(x==='ms_sql_audit'||x==='oracle.audit')out['DB audit']=1;else out[x]=1;});
  return Object.keys(out).sort();}

function _invCmdb_(){
  var r=esSearch_(INV_CMDB,{size:0,query:{bool:{filter:[{range:{'@timestamp':{gte:INV_CMDB_WIN}}},{exists:{field:'servicenow.event.name.value'}}]}},
    aggs:{n:{terms:{field:'servicenow.event.name.value',size:20000},aggs:{c:{terms:{field:'servicenow.event.sys_class_name.display_value',size:1,missing:'Servidor'}},t:{max:{field:'@timestamp'}}}}}});
  var out={},last='';
  (((r.aggregations||{}).n||{}).buckets||[]).forEach(function(b){var n=_invNorm_(b.key);if(_invJunk_(n))return;
    var c=(b.c&&b.c.buckets&&b.c.buckets[0]&&b.c.buckets[0].key)||'Servidor';out[n]=c;var t=b.t&&b.t.value_as_string;if(t&&t>last)last=t;});
  return {map:out,last:last};
}
function _invCortex_(){
  var idx=props_().getProperty('CORTEX_INDEX')||'cortex_endpoints_lookup';
  var r=esSearch_(idx,{size:10000,track_total_hits:true,query:{match_all:{}}});
  var hits=(r.hits&&r.hits.hits)||[],out={},det={},hasType=false,total=hits.length,servers=0;
  hits.forEach(function(h){var s=h._source||{},rec={};
    Object.keys(INV_CX_FIELDS).forEach(function(k){var p=_pick_(s,INV_CX_FIELDS[k]);if(p){rec[k]=p.v;det[k]=det[k]||p.f;}});
    if(rec.type!=null)hasType=true;
    if(rec.type!=null&&String(rec.type).toUpperCase().indexOf('SERVER')<0)return;
    var n=_invNorm_(rec.name);if(_invJunk_(n))return;servers++;
    var st=String(rec.status||'').toUpperCase().replace(/^AGENT_STATUS_/,''),last=rec.last;
    if(typeof last==='number')last=new Date(last).toISOString();
    var cur={st:st||null,op:rec.op?String(rec.op).toUpperCase():null,os:rec.os||null,ver:rec.ver||null,cs:rec.cs?String(rec.cs).toUpperCase():null,last:last||''};
    var old=out[n];if(!old||String(cur.last)>String(old.last))out[n]=cur;});
  return {map:out,fields:det,typeFiltered:hasType,docs:total,servers:servers,index:idx};
}
function _invSiem_(win){
  var should=INV_OWN_PREFIX.map(function(p){return {prefix:{'data_stream.dataset':p}};}).concat([{terms:{'data_stream.dataset':INV_OWN_EXACT}}]);
  var r=esSearch_(INV_SIEM,{size:0,query:{bool:{filter:[{range:{'@timestamp':{gte:'now-'+win}}},{exists:{field:'host.name'}},{bool:{should:should,minimum_should_match:1}}]}},
    aggs:{h:{terms:{field:'host.name',size:20000},aggs:{t:{max:{field:'@timestamp'}},ds:{terms:{field:'data_stream.dataset',size:20}}}}}});
  var out={};
  (((r.aggregations||{}).h||{}).buckets||[]).forEach(function(b){var n=_invNorm_(b.key);if(_invJunk_(n))return;
    var o=out[n]||(out[n]={last:'',ds:{},docs:0});o.docs+=b.doc_count;var t=b.t&&b.t.value_as_string;if(t&&t>o.last)o.last=t;
    ((b.ds&&b.ds.buckets)||[]).forEach(function(d){o.ds[d.key]=1;});});
  return out;
}
function buildInventario_(win){
  win=(win==='7d')?'7d':'24h';
  var cm=_invCmdb_(),cx=_invCortex_(),sm=_invSiem_(win),names={};
  [cm.map,cx.map,sm].forEach(function(m){Object.keys(m).forEach(function(n){names[n]=1;});});
  var rows=Object.keys(names).sort().map(function(n){var c=cm.map[n]||null,x=cx.map[n]||null,s=sm[n]||null;
    return [n,c,x?x.st:null,x?x.op:null,x?x.os:null,x?x.ver:null,s?s.last:null,s?_invOwnFam_(Object.keys(s.ds)):[],s?s.docs:0,x?x.cs:null];});
  return {rows:rows,win:win,gen:new Date().toISOString(),cmdbLast:cm.last,cortex:{index:cx.index,docs:cx.docs,servers:cx.servers,fields:cx.fields,typeFiltered:cx.typeFiltered},code_version:CODE_VERSION};
}
function invPut_(cache,key,str){var n=Math.ceil(str.length/CHUNK),p={};for(var i=0;i<n;i++)p[key+'_'+i]=str.substr(i*CHUNK,CHUNK);p[key+'_n']=String(n);cache.putAll(p,INV_TTL);}
function invGet_(cache,key){var ns=cache.get(key+'_n');if(!ns)return null;var n=parseInt(ns,10),ids=[];for(var i=0;i<n;i++)ids.push(key+'_'+i);var got=cache.getAll(ids),o='';for(var j=0;j<n;j++){var s=got[key+'_'+j];if(s==null)return null;o+=s;}return o;}

/** Chamado pelo cliente — inventário de servidores (win: '24h' | '7d'). */
function getInventario(win){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  win=(win==='7d')?'7d':'24h';var key=INV_KEY+'_'+win,cache=CacheService.getScriptCache();
  var hit=invGet_(cache,key);if(hit){try{return JSON.parse(hit);}catch(e){}}
  var data=buildInventario_(win);try{invPut_(cache,key,JSON.stringify(data));}catch(e){}
  return data;
}
/* Gatilho de tempo: aquece o cache do inventário (agende a cada 2h). */
/** Chamado pelo botão ↻ do topo — refaz os dados da aba aberta, ignorando o cache. Refazer de novo em menos de 1 min devolve o que já está
 *  no cache (recente:true): evita gastar cota com cliques repetidos ou com várias pessoas clicando ao mesmo tempo. */
function forcarAtualizacao(aba,win){
  if(!isAuthorized_()) throw new Error('Acesso restrito ao time de SOC/CSIRT.');
  var c=CacheService.getScriptCache(),w=(win==='7d')?'7d':'24h',k='force_'+aba+(aba==='inv'?'_'+w:''),recente=!!c.get(k),d;
  var LE={soc:getCsirt,eng:getOperational,mitre:getCoverage,cred:getResonant,ot:getClaroty};
  if(aba!=='inv'&&!LE[aba]) throw new Error('Aba desconhecida: '+aba);
  if(recente) return {d:aba==='inv'?getInventario(w):LE[aba](),recente:true};
  c.put(k,'1',60);
  if(aba==='soc'){d=buildCsirt_();try{csPut_(c,JSON.stringify(d));}catch(e){}}
  else if(aba==='eng'){d=buildOperational_();try{opPut_(c,JSON.stringify(d));}catch(e){}}
  else if(aba==='mitre'){d=getCoverage_(true);}
  else if(aba==='cred'){d=buildResonant_();try{rzPut_(c,JSON.stringify(d));}catch(e){}}
  else if(aba==='ot'){d=buildClaroty_();try{otPut_(c,JSON.stringify(d));}catch(e){}}
  else{d=buildInventario_(w);try{invPut_(c,INV_KEY+'_'+w,JSON.stringify(d));}catch(e){}}
  return {d:d,recente:false};
}
function refreshInventario(){var c=CacheService.getScriptCache();['24h','7d'].forEach(function(w){try{invPut_(c,INV_KEY+'_'+w,JSON.stringify(buildInventario_(w)));}catch(e){Logger.log('refreshInventario %s: %s',w,e.message);}});}
/* DIAGNÓSTICO — valida as 3 fontes e mostra os campos detectados no índice do Cortex. */
function debugInventario(){
  var idx=props_().getProperty('CORTEX_INDEX')||'cortex_endpoints_lookup';
  try{var s=esSearch_(idx,{size:1});var h=(s.hits&&s.hits.hits&&s.hits.hits[0]);Logger.log('Cortex [%s] total: %s · campos do 1º doc: %s',idx,JSON.stringify(s.hits&&s.hits.total),h?Object.keys(h._source||{}).join(', '):'(vazio)');}
  catch(e){Logger.log('Cortex [%s] ERRO: %s',idx,e.message);}
  var d=buildInventario_('24h'),C=0,X=0,S=0,all=0;
  d.rows.forEach(function(r){var c=!!r[1],x=!!r[2],s=!!r[6];if(c)C++;if(x)X++;if(s)S++;if(c&&x&&s)all++;});
  Logger.log('universo %s · CMDB %s (última extração %s) · Cortex %s · SIEM 24h %s · nas 3 fontes %s',d.rows.length,C,d.cmdbLast,X,S,all);
  Logger.log('Cortex: %s docs, %s servidores · filtro por tipo: %s · campos usados: %s',d.cortex.docs,d.cortex.servers,d.cortex.typeFiltered,JSON.stringify(d.cortex.fields));
  return d;
}
