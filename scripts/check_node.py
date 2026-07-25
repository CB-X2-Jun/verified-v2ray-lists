import asyncio
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from parser import (
    parse,
    read_nodes,
)

from country_map import COUNTRY_MAP

BASE = Path(__file__).resolve().parent.parent

NODE_FILE = BASE / "node.txt"

PUBLIC_FILE = BASE / "public" / "proxies.json"

HISTORY_FILE = BASE / "data" / "history.json"

XRAY = shutil.which("xray") or "xray"

SOCKS_PORT = 28080

START_TIMEOUT = 8

TEST_TIMEOUT = 12

GOOGLE = [
    "https://google.com",
]

HTTPS_BACKUP = [

    "https://ipin.io",

    "https://ifconfig.me/all",

    "https://api.ipify.org",

]

HTTP_TEST = [

    "http://ifconfig.me/ip",

    "http://api.ipify.org",

    "http://api.i.pn/json",

]

def load_history():

    if not HISTORY_FILE.exists():
        return {}

    with open(
        HISTORY_FILE,
        encoding="utf-8",
    ) as f:

        obj = json.load(f)

    history = {}

    for i in obj:

        history[i["id"]] = i

    return history

def save_history(history):

    HISTORY_FILE.parent.mkdir(
        exist_ok=True,
    )

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            list(history.values()),
            f,
            ensure_ascii=False,
            indent=2,
        )

def save_public(nodes):

    PUBLIC_FILE.parent.mkdir(
        exist_ok=True,
    )

    with open(
        PUBLIC_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            nodes,
            f,
            ensure_ascii=False,
            indent=2,
        )

def node_id(node):

    import hashlib

    d = node.data

    if node.protocol in (
        "vless",
        "vmess",
    ):
        unique = d.get(
            "id",
            "",
        )

    elif node.protocol in (
        "trojan",
        "hy2",
        "hysteria2",
    ):
        unique = d.get(
            "password",
            "",
        )

    elif node.protocol == "ss":
        unique = "{}:{}".format(
            d.get("method", ""),
            d.get("password", ""),
        )

    else:
        unique = ""


    raw = "|".join(
        (
            node.protocol,
            node.address.lower(),
            str(node.port),
            unique,
        )
    )


    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16]


def export_node(node, result):

    return {

        "id":
            node_id(node),

        "protocol":
            node.protocol,

        "address":
            node.address,

        "port":
            node.port,

        "country":
            node.country,

        "countryName":
            COUNTRY_MAP.get(
                node.country,
                "未知",
            ),

        "uri":
            node.uri,

        "alias":
            node.data.get(
                "alias",
                "",
            ),

        "warning":
            result.get(
                "warning",
                node.warning,
            ),

        "latency":
            result.get(
                "latency",
                -1,
            ),

        "success":
            result.get(
                "success",
                False,
            ),

        "lastCheck":
            int(
                time.time()
            ),

    }

def local_socks():

    return {

        "listen": "127.0.0.1",

        "port": SOCKS_PORT,

        "protocol": "socks",

        "settings": {

            "udp": True,

        },

    }

def build_outbound(node):

    p = node.protocol
    d = node.data


    # =========================
    # protocol settings
    # =========================

    if p == "vless":

        protocol = "vless"

        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": d.get("id",""),
                            "encryption": d.get(
                                "encryption",
                                "none",
                            ),
                            "flow": d.get(
                                "flow",
                                "",
                            ),
                        }
                    ],
                }
            ]
        }


    elif p == "vmess":

        protocol = "vmess"

        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": d.get(
                                "id",
                                "",
                            ),
                            "alterId": int(
                                d.get(
                                    "alterId",
                                    0,
                                )
                            ),
                            "security": d.get(
                                "securityType",
                                "auto",
                            ),
                        }
                    ],
                }
            ]
        }


    elif p == "trojan":

        protocol = "trojan"

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "password": d.get(
                        "password",
                        "",
                    ),
                }
            ]
        }


    elif p == "ss":

        protocol = "shadowsocks"

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "method": d.get(
                        "method",
                        "",
                    ),
                    "password": d.get(
                        "password",
                        "",
                    ),
                }
            ]
        }


    elif p in (
        "hy2",
        "hysteria2",
    ):

        protocol = "hysteria2"

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "password": d.get(
                        "password",
                        "",
                    ),
                }
            ]
        }


    else:

        raise RuntimeError(
            f"Unsupported protocol {p}"
        )



    # =========================
    # stream settings
    # =========================

    network = d.get(
        "network",
        "tcp",
    ).lower()


    security = d.get(
        "security",
        "",
    ).lower()


    stream = {
        "network": network,
        "security": security,
    }



    # =========================
    # TLS
    # =========================

    if security == "tls":

        stream["tlsSettings"] = {

            "serverName": d.get(
                "sni",
                "",
            ),

            "allowInsecure":
                str(
                    d.get(
                        "allowInsecure",
                        "0",
                    )
                ).lower()
                in (
                    "1",
                    "true",
                    "yes",
                ),

        }



    # =========================
    # REALITY
    # =========================

    elif security == "reality":

        stream["realitySettings"] = {

            "serverName": d.get(
                "sni",
                "",
            ),

            "fingerprint": d.get(
                "fp",
                "",
            ),

            "publicKey": d.get(
                "pbk",
                "",
            ),

            "shortId": d.get(
                "sid",
                "",
            ),

            "spiderX": d.get(
                "spx",
                "",
            ),

        }



    # =========================
    # transport
    # =========================

    if network == "ws":

        stream["wsSettings"] = {

            "path": d.get(
                "path",
                "/",
            ),

            "headers": {
                "Host": d.get(
                    "host",
                    "",
                )
            },

        }



    elif network == "grpc":

        stream["grpcSettings"] = {

            "serviceName": d.get(
                "serviceName",
                "",
            ),

            "authority": d.get(
                "authority",
                "",
            ),

        }



    elif network == "xhttp":

        stream["xhttpSettings"] = {

            "host": d.get(
                "host",
                "",
            ),

            "path": d.get(
                "path",
                "/",
            ),

            "mode": d.get(
                "mode",
                "",
            ),

        }



    elif network == "httpupgrade":

        stream["httpupgradeSettings"] = {

            "host": d.get(
                "host",
                "",
            ),

            "path": d.get(
                "path",
                "/",
            ),

        }



    elif network == "h2":

        stream["httpSettings"] = {

            "host": [
                d.get(
                    "host",
                    "",
                )
            ],

            "path": d.get(
                "path",
                "/",
            ),

        }



    elif network == "kcp":

        stream["kcpSettings"] = {

            "header": {
                "type": "none"
            }

        }



    elif network == "quic":

        stream["quicSettings"] = {

            "security": "none",

            "key": "",

            "header": {
                "type": "none"
            }

        }



    # tcp 不需要额外设置

    return {

        "protocol": protocol,

        "settings": settings,

        "streamSettings": stream,

    }

def build_config(node):

    return {

        "log": {

            "loglevel": "warning",

        },

        "inbounds": [

            local_socks()

        ],

        "outbounds": [

            build_outbound(node),

        ],

    }


def wait_port(port, timeout):

    start = time.time()

    while time.time() - start < timeout:

        try:

            with socket.create_connection(
                (
                    "127.0.0.1",
                    port,
                ),
                timeout=1,
            ):

                return True

        except:

            time.sleep(0.2)


    return False



def start_xray(node):

    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
        encoding="utf-8",
    )


    json.dump(
        build_config(node),
        tmp,
        ensure_ascii=False,
    )


    tmp.close()


    process = subprocess.Popen(

        [
            XRAY,
            "run",
            "-config",
            tmp.name,
        ],

        stdout=subprocess.DEVNULL,

        stderr=subprocess.DEVNULL,

    )


    if not wait_port(
        SOCKS_PORT,
        START_TIMEOUT,
    ):

        process.kill()

        os.unlink(
            tmp.name
        )

        return None


    return (
        process,
        tmp.name,
    )



def stop_xray(obj):

    if not obj:
        return


    process, config = obj


    try:

        process.kill()

    except:

        pass


    try:

        os.unlink(config)

    except:

        pass

def curl_test(url):

    try:

        result = subprocess.run(

            [
                "curl",

                "--silent",

                "--max-time",
                str(TEST_TIMEOUT),

                "--proxy",
                f"socks5h://127.0.0.1:{SOCKS_PORT}",

                url,

            ],

            stdout=subprocess.PIPE,

            stderr=subprocess.DEVNULL,

        )


        return result.returncode == 0


    except:

        return False

def check_node(node):

    result = {

        "id":
            node_id(node),

        "protocol":
            node.protocol,

        "address":
            node.address,

        "port":
            node.port,

        "country":
            node.country,

        "uri":
            node.uri,

        "warning":
            list(node.warning),

        "success":
            False,

        "latency":
            -1,

    }



    xray = None


    try:

        xray = start_xray(node)


        if not xray:

            return result



        # ------------------
        # google
        # ------------------

        ok = False


        start = time.time()


        for url in GOOGLE:

            if curl_test(url):

                ok = True

                break



        latency = int(
            (time.time()-start)*1000
        )



        if ok:

            result["success"] = True

            result["latency"] = latency


        else:

            backup = False


            for url in HTTPS_BACKUP:

                if curl_test(url):

                    backup = True

                    break



            if backup:

                result["success"] = True

                result["latency"] = latency

                result["warning"].append(
                    "noGooglePassing"
                )



        # ------------------
        # HTTP
        # ------------------

        if result["success"]:

            http_ok = False


            for url in HTTP_TEST:

                if curl_test(url):

                    http_ok = True

                    break



            if not http_ok:

                result["warning"].append(
                    "notAvailableForNonSSLSites"
                )



    finally:

        stop_xray(xray)



    return result

def history_warning(warning):

    return [
        i
        for i in warning
        if i in (
            "allowInsecure",
            "noLongerSupportedNetwork",
        )
    ]

def main():

    history = load_history()

    public = []


    for uri, country in read_nodes(
        NODE_FILE
    ):

        try:

            node = parse(
                uri,
                country,
            )


            result = check_node(node)


            if result["success"]:

                public.append(
                    export_node(
                        node,
                        result,
                    )
                )

                hid = result["id"]

                history[hid] = {
                    "id": hid,
                
                    "protocol": node.protocol,
                
                    "address": node.address,
                
                    "port": node.port,
                
                    "country": country,
                
                    "uri": node.uri,
                
                    "warning": history_warning(
                        result["warning"]
                    ),
                
                    "lastCheck":
                        int(time.time()),
                }


        except Exception as e:

            print(
                "skip:",
                e,
            )


    save_public(
        public
    )

    save_history(
        history
    )


if __name__ == "__main__":

    main()

