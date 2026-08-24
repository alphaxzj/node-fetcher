import yaml
import base64
import json
import urllib.parse


proxies=[]



def add(proxy):

    if proxy:
        proxies.append(proxy)



def vmess(url):

    try:

        data=url[8:]

        raw=base64.b64decode(
            data+"==="
        ).decode()

        j=json.loads(raw)


        return {

            "name":j.get("ps","vmess"),

            "type":"vmess",

            "server":j["add"],

            "port":int(j["port"]),

            "uuid":j["id"],

            "alterId":int(
                j.get("aid",0)
            ),

            "cipher":"auto",

            "udp":True

        }


    except:

        return None




def vless(url):

    try:

        u=urllib.parse.urlparse(url)

        q=urllib.parse.parse_qs(u.query)


        return {

            "name":q.get(
                "remarks",
                ["vless"]
            )[0],

            "type":"vless",

            "server":u.hostname,

            "port":u.port,

            "uuid":u.username,

            "network":
            q.get(
                "type",
                ["tcp"]
            )[0],

            "tls":
            q.get(
                "security",
                ["none"]
            )[0]=="tls"

        }


    except:

        return None




def trojan(url):

    try:

        u=urllib.parse.urlparse(url)


        return {

            "name":"trojan",

            "type":"trojan",

            "server":u.hostname,

            "port":u.port,

            "password":u.username,

            "udp":True

        }

    except:

        return None





def ss(url):

    return {

        "name":"ss",

        "type":"ss",

        "server":url

    }





def parse(line):


    if line.startswith("vmess://"):
        return vmess(line)


    if line.startswith("vless://"):
        return vless(line)


    if line.startswith("trojan://"):
        return trojan(line)


    if line.startswith("ss://"):
        return ss(line)


    return None





with open(
    "nodes.txt",
    encoding="utf8"
) as f:


    for line in f:

        p=parse(
            line.strip()
        )

        add(p)




config={

"mixed-port":7890,

"allow-lan":True,

"mode":"rule",

"log-level":"info",


"proxies":proxies,


"proxy-groups":[

{

"name":"自动选择",

"type":"url-test",

"url":
"http://www.gstatic.com/generate_204",

"interval":300,

"proxies":[

x["name"] for x in proxies

]

}

],


"rules":[

"MATCH,自动选择"

]

}



with open(
    "config.yaml",
    "w",
    encoding="utf8"
) as f:


    yaml.dump(

        config,

        f,

        allow_unicode=True,

        sort_keys=False

    )



print(
    "生成节点:",
    len(proxies)
)