# Microsoft Word Spawning PowerShell

## What happened
A Microsoft Word process (winword.exe) launched powershell.exe as a child process.

## Why it's suspicious
Word is a narrow-purpose application, its only job is opening and editing documents. 
It has no legitimate reason to ever spawn PowerShell. This pattern is the signature 
of macro-based phishing: a victim opens a malicious document, enables macros, and 
the embedded VBA code shells out to PowerShell to download or execute the real 
payload. Because Word has no normal workflow that touches PowerShell, this detection 
carries very low noise, unlike detections built around general-purpose tools like 
PowerShell or cmd, which admins use constantly for legitimate work.

## Which logs detect it
Sysmon Event ID 1 (Process Creation), fields: ParentImage, Image

## False positives
Rare. Some enterprise macro-based automation tools exist but are uncommon. 
If seen in an environment with known legitimate macro workflows, cross-check 
against an approved script inventory before treating as benign.

## Investigation steps
1. Check the CommandLine of the PowerShell process, look for encoded (-EncodedCommand) 
   or obfuscated arguments, a strong sign of malicious intent
2. Identify the source document, file path, filename, where it came from (email 
   attachment, download, USB)
3. Check what PowerShell did next, network connections (likely payload download), 
   file writes, or further process spawns
4. Check if the user recalls enabling macros, correlate with email logs if available
