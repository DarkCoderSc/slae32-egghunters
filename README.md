Student ID: **SLAE-1530**

# SLAE32 Assignment 3 - Egg Hunters

## Egg Hunter Principle (No Code Execution)

Demonstrate egg hunter technique without code execution. When an egg is found in memory it will dump memory content at given location.

`gcc egg-principle.c -o egg-principle`

`./egg-principle`

## Egg Hunter Shellcode Embedded (Code Execution)

(!) Requires ASLR to be disabled.

Instead of dumping memory content, when our egg is found in memory it will redirect execution flow to our embeeded shellcode.

`gcc egg-shellcode-embedded.c -o egg-shellcode-embedded -z execstack -no-pie -fno-stack-protector`

`./egg-shellcode-embedded`

## Real Life Egg Hunter - Vulnerable Server

(!) Requires ASLR to be disabled.

### Compile Vulnerable Server

`gcc egg-vulnerable-server.c -o egg-vulnerable-server -z execstack -no-pie -fno-stack-protector -pthread`

`./egg-vulnerable-server`

The server will run and wait for commands from connected client.

### Exploit Vulnerable Server

`chmod +x exploit-vulnerable-server.py && ./exploit-vulnerable-server.py`

This python script exploit vulnerable server in two phases.

First phase writes our second and bigger shellcode in process memory.

Second phase exploit buffer overflow present in `ExploitMe()` function to write and execute our egg hunter shellcode configured to search our second shellcode payload.

We choose `egg!` as our egg pattern which preceed our shellcode. 

You can replace the `shellcode` variable with any compatible shellcodes. Don't forget to prepend your shellcode with the correct egg pattern value.

Current shellcode will display content of `/etc/passwd`.

You can generate your own egg hunter shellcode using Metasploit:

`msf-egghunter -f python -e egg! -v egg_hunter -p linux -a x86`
