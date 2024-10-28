# HTB_GoodGames
In this repository you will find an autopwn tool in case you want to resolve the machine GoodGames in HackTheBox.

Autopwn.py will give you root permissions on the docker of GoodGames machine when you run it. If you want to run this exploit you will have to specify 3 parameters:

Host IP: Nunchucks host IP.
Your own IP: Necessary to receive a reverse shell.
Your own Port: Port where you are listening.
Example of use:

python3 autopwn.py <Host_IP> -p <Your_Port> <Your_IP>
python3 autopwn.py 10.10.10.10 10.10.16.8 9999
