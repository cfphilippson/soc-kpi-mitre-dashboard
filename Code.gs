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

var CODE_VERSION = 'v14-20261002';          // muda a cada alteração de lógica
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
  var list = (p.getProperty('ALLOWED_EMAILS') || '').trim();
  if (!group && !list) return true; // não configurado -> não bloqueia (evita se trancar)
  var email = _normEmail_(Session.getActiveUser().getEmail());
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

  if (isApprove) {
    _addEmailToAllowed_(req.email);
    try { MailApp.sendEmail(req.email, '[Painel SOC/CSIRT] Acesso liberado', 'Seu acesso ao painel KPI SOC/CSIRT foi aprovado por ' + approver + '. Já pode acessar.'); } catch (e2) {}
    return page('Acesso aprovado ✅', req.email + ' foi adicionado à lista de acesso. Aprovado por ' + approver + '.', '#46A758');
  } else {
    try { MailApp.sendEmail(req.email, '[Painel SOC/CSIRT] Solicitação de acesso negada', 'Sua solicitação de acesso ao painel foi negada por ' + approver + '. Fale com o time em caso de dúvida.'); } catch (e2) {}
    return page('Solicitação negada', 'O pedido de ' + req.email + ' foi recusado.', '#E5484D');
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
      'isAuthorized_()           = ' + isAuthorized_() + '</pre>'
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

/* ================== KPI OPERACIONAL — lê a planilha (Google Sheet) do Drive ==================
 * Pré-requisito: a planilha "Gestão de SIEM" precisa estar como GOOGLE SHEETS (não .xlsx).
 *   No Drive: abra o .xlsx → Arquivo → Salvar como Planilhas Google. Copie o ID da URL.
 * Propriedade do script: SHEET_ID = <id da planilha Google>
 * Abas esperadas: Elastic, Caso de uso por tecnologia, Casos de uso em Prod, Alertas,
 *                 Origem do Log, Inventário SIEM, Licenciamento, Highlights
 */
var OP_KEY = 'op_data_v1';
var OP_TTL = 2 * 60 * 60; // 2h

function _mlab(d){var M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];return M[d.getMonth()]+'/'+(''+d.getFullYear()).slice(-2);}
function _mkey(d){return d.getFullYear()*12+d.getMonth();}

function opPut_(cache,str){var n=Math.ceil(str.length/CHUNK),p={};for(var i=0;i<n;i++)p[OP_KEY+'_'+i]=str.substr(i*CHUNK,CHUNK);p[OP_KEY+'_n']=String(n);cache.putAll(p,OP_TTL);}
function opGet_(cache){var ns=cache.get(OP_KEY+'_n');if(!ns)return null;var n=parseInt(ns,10),ids=[];for(var i=0;i<n;i++)ids.push(OP_KEY+'_'+i);var got=cache.getAll(ids),o='';for(var j=0;j<n;j++){var s=got[OP_KEY+'_'+j];if(s==null)return null;o+=s;}return o;}

function buildOperational_(){
  var id=props_().getProperty('SHEET_ID');
  if(!id) throw new Error('Defina SHEET_ID (planilha Google da Gestão de SIEM) nas Propriedades do script.');
  var ss=SpreadsheetApp.openById(id);
  function vals(n){var s=ss.getSheetByName(n); if(!s) throw new Error('Aba não encontrada: '+n); return s.getDataRange().getValues();}
  function num(x){var v=parseFloat(x);return isNaN(v)?0:v;}

  // Elastic
  var e=vals('Elastic'),elastic=[];
  for(var i=1;i<e.length;i++){var r=e[i]; if(!(r[0] instanceof Date))continue;
    elastic.push({m:_mlab(r[0]),prod:num(r[1]),homolog:num(r[2]),ajustes:num(r[3]),
      taticas:num(r[5]),tecCov:num(r[6]),tecTot:num(r[7]),subCov:num(r[8]),subTot:num(r[9])});}

  // Tecnologia por mês
  var t=vals('Caso de uso por tecnologia'),th=t[0],techByMonth={};
  for(var i=1;i<t.length;i++){var r=t[i]; if(!(r[0] instanceof Date))continue;
    var items=[]; for(var c=1;c<th.length;c++){var v=num(r[c]); if(v>0)items.push({k:String(th[c]),v:v});}
    items.sort(function(a,b){return b.v-a.v;}); techByMonth[_mlab(r[0])]=items;}

  // Criticidade / tipo (atual)
  var p=vals('Casos de uso em Prod'),cc={},tipo={},nP=0;
  for(var i=1;i<p.length;i++){if(p[i][0]===''||p[i][0]==null)continue; nP++;
    var k=String(p[i][3]||'—'); cc[k]=(cc[k]||0)+1; var tp=String(p[i][4]||'—'); tipo[tp]=(tipo[tp]||0)+1;}
  var critOrder=['Crítica','Alta','Média','Baixa'],criticidade=critOrder.map(function(k){return {k:k,v:cc[k]||0};});
  var tipo_top=Object.keys(tipo).map(function(k){return {k:k,v:tipo[k]};}).sort(function(a,b){return b.v-a.v;}).slice(0,6);

  // Alertas por mês + top regras
  var a=vals('Alertas'),perm={},tot={},keyOf={};
  for(var i=1;i<a.length;i++){var nm=a[i][0],m=a[i][1]; if(!(m instanceof Date))continue;
    var lbl=_mlab(m); keyOf[lbl]=_mkey(m); tot[lbl]=(tot[lbl]||0)+1;
    if(nm){perm[lbl]=perm[lbl]||{}; perm[lbl][nm]=(perm[lbl][nm]||0)+1;}}
  var alertsByMonth=Object.keys(tot).sort(function(x,y){return keyOf[x]-keyOf[y];}).map(function(lbl){
    var top=Object.keys(perm[lbl]||{}).map(function(k){return {k:k,v:perm[lbl][k]};}).sort(function(x,y){return y.v-x.v;}).slice(0,8);
    return {m:lbl,total:tot[lbl],top:top};});

  // Fontes de log / inventário / licença
  var lg=vals('Origem do Log'),logs=[];
  for(var i=1;i<lg.length;i++){if(lg[i][0]===''||lg[i][0]==null)continue; logs.push({k:String(lg[i][0]),v:num(lg[i][1]),prev:num(lg[i][2])});}
  logs.sort(function(a,b){return b.v-a.v;});
  var iv=vals('Inventário SIEM'),inv=[];
  for(var i=1;i<iv.length;i++){if(iv[i][0]===''||iv[i][0]==null)continue; inv.push({k:String(iv[i][0]),siem:num(iv[i][1]),cmdb:num(iv[i][2])});}
  var lc=vals('Licenciamento'),lic=[];
  for(var i=1;i<lc.length;i++){if(!(lc[i][0] instanceof Date))continue; lic.push({m:_mlab(lc[i][0]),total:num(lc[i][1]),cons:num(lc[i][2])});}

  // Highlights
  var hs=vals('Highlights'),highlights={};
  for(var i=1;i<hs.length;i++){if(!(hs[i][0] instanceof Date))continue; highlights[_mlab(hs[i][0])]={mel:String(hs[i][1]||'').trim(),prox:String(hs[i][2]||'').trim()};}

  return {elastic:elastic,techByMonth:techByMonth,criticidade:criticidade,crit_total:nP,
    alertsByMonth:alertsByMonth,logs:logs,inv:inv,lic:lic,highlights:highlights,tipo_top:tipo_top,
    updated:Utilities.formatDate(new Date(),'America/Sao_Paulo','dd/MM/yyyy HH:mm')};
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
var CS_KEY = 'csirt_data_v1';
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
  var tImp=colOpt(T,'Impacto'), tCri=colOpt(T,'Criado');
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
  function bucket(c,l){ if(!comps[c]) comps[c]={comp:c,label:l,tri:[],det:[]}; return comps[c]; }
  T.rows.forEach(function(r){ var c=r[tC],l=r[tL]; if((c==null||c==='')&&(l==null||l===''))return; bucket(_ym(c,l),String(l)).tri.push(r); });
  D.rows.forEach(function(r){ var c=r[dC],l=r[dL]; if((c==null||c==='')&&(l==null||l===''))return; bucket(_ym(c,l),String(l)).det.push(r); });

  var order=Object.keys(comps).sort();
  var months=[], incidents=[], mttd=[], mtta=[], mttr=[], funnels=[], inc_detail=[];
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
    // MTTA / MTTR CSIRT (detalhado)
    var detA=g.det.map(function(r){return _cmin(r[dA]);}), detR=g.det.map(function(r){return _cmin(r[dR]);});
    var o2=sevSeries(g.det,dSev,function(r){return _cmin(r[dA]);}); o2.m=ml; o2.ov=_r2(_avg(detA)); mtta.push(o2);
    var o3=sevSeries(g.det,dSev,function(r){return _cmin(r[dR]);}); o3.m=ml; o3.ov=_r2(_avg(detR)); mttr.push(o3);
    // funil do mês
    var ftot=g.tri.length, fia=0, fn1=0;
    g.tri.forEach(function(r){ if(_hr(r)) fn1++; else fia++; });
    funnels.push({m:ml,total:ftot,ia:fia,n1:fn1,csirt:tot,
      ia_pct:ftot?Math.round(fia/ftot*1000)/10:0, n1_pct:ftot?Math.round(fn1/ftot*1000)/10:0, csirt_pct:ftot?Math.round(tot/ftot*1000)/10:0});
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

  // funil do último mês
  var lc=order[order.length-1], g=comps[lc];
  var tot=g.tri.length, ia=0, n1=0;
  g.tri.forEach(function(r){ var hr=r[tHR]; if(hr===true||String(hr).toLowerCase()==='true'||String(hr).toLowerCase()==='sim') n1++; else ia++; });
  var csirt=incidents[incidents.length-1].total;
  var funnel={m:g.label,total:tot,ia:ia,n1:n1,csirt:csirt,
    ia_pct:tot?Math.round(ia/tot*1000)/10:0, n1_pct:tot?Math.round(n1/tot*1000)/10:0, csirt_pct:tot?Math.round(csirt/tot*1000)/10:0};

  var cur={mttd:mttd.length?mttd[mttd.length-1].ov:null, mtta:mtta.length?mtta[mtta.length-1].ov:null, mttr:mttr.length?mttr[mttr.length-1].ov:null};

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
    mttd_ai:mttd, mtta_csirt:mtta, mttr_csirt:mttr, key_points:key, attention:att, fp:fp, inc_detail:inc_detail,
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
