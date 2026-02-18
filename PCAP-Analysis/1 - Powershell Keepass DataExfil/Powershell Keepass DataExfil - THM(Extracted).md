**Executive Summary:**

An investigation was conducted on a packet capture file spanning approximately 2 minutes and 27 seconds. The analysis revealed a successful compromise of an internal host (10.10.45.95) by a malicious internal actor or compromised host (10.10.94.106).

The attacker utilized a PowerShell script to automate the theft of KeePass credentials. The script performed a memory dump of the running KeePass process and exfiltrated the encrypted database file. Data was obfuscated using XOR encryption and Base64 encoding before being exfiltrated over non-standard TCP ports.



**Capture Properties:**

Total packets : 53338

Duration : 2 min 27 sec

Capture Start: 2023-08-29 07:59:22

Capture End: 2023-08-29 8:01:50



**Protocol hierarchy:**

Sinec H1 protocol - 6 packets -- It is related to siemens ethernet industrial communication protocol 
Note: It is misidentified by wireshatk since traffic is over Non-standard ports. The traffic depicted as Sinec H1 is actually TCP/1338 Data Exfiltartion.

tcp/http(80) - 2 packets

tcp/Data - 29494 packets 



**Conversations:**

both are internal machines only. All traffic happened between these two machines.

10.10.45.95(victim)

10.10.94.106 (server - attacker)



Traffic is distribute on 3 destination ports - 1337(53314),1338(9),1339(11)



**http traffic investigation over port 1339:**



7:59:22 - Get request - 10.10.45.95 -> 10.10.94.106 on port 1339

Full URI : http://10.10.94.106:1339/xxxmmdcclxxxiv.ps1 -- A powershell Script raises suspicion

user agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.4720 -- The user agent string isn't the regular one and it indiactes a automated powershell agent.



7:59:22 - Powershell script payload Delivered -- Response 200

Hosting server : SimpleHTTP/0.6 Python/3.6.9 -- Simple python server raises suspicion

File transferred - 11195 Bytes(xxxmmdcclxxxiv.ps1)



**TCP traffic(Data Exfiltartion):**

From here all traffic shows TCP protocol and data is transferring 10.10.45.95 -> 10.10.94.106 On port 1337 and 1338 with TCP flags \[PSH,ACK]



**Analysis of Powershell Script:**

The script executes following actions:

1. check whether procdump is installed or not. 
2. If absent: Install it using GetBytes from Sysinternal suite.
3. Search if "keepass" is actually running on the system. If not, no action taken.
4. If it is running dump its entire process memory into a file.
5. Read every line in the file as a byte array, encode every byte using xor with key 0x41.
6. Encode again with base64 encoding.
7. Establish a channel To exfiltarte the data to 10.10.94.106 over port 1337 in 1024 byte chunks.
8. Read keepass.kbdx datbse file and encode every byte using xor with key 0x42.
9. Encode again with base64 encoding.
10. Establish a channel To exfiltarte the data to 10.10.94.106 over port 1338 in 1024 bye chunks.



**Indicators of compromise:**

Attacker IP : 10.10.94.106

Victim IP : 10.10.45.95

Payload Delivery/Staging Port : 1339/TCP(http)

Exfil Port 1 : 1337/TCP (memory dump)

Exfil Port 2 : 1338/TCP (database)

Attacker Server : SimpleHTTP/0.6 Python/3.6.9

Malicious Script : xxxmmdcclxxxiv.ps1

Tool Used : ProcDump(SysyInternals)

User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.4720






