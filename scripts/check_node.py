import asyncio
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import traceback
from pathlib import Path

from parser import parse, read_nodes
from country_map import COUNTRY_MAP

BASE = Path(__file__).resolve().parent.parent

NODE_FILE = BASE / "node.txt"
PUBLIC_FILE = BASE / "public" / "proxies.json"
HISTORY_FILE = BASE / "data" / "history.json"

XRAY = shutil.which("xray") or "xray"

SOCKS_PORT = 28080

START_TIMEOUT = 10
TEST_TIMEOUT = 15

# Google 单独检测
GOOGLE = [
    "https://www.google.com",
]

# Google失败后的备用检测
HTTPS_BACKUP = [
    "https://ipin.io",
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
]

# 非SSL网站检测
HTTP_TEST = [
    "http://ifconfig.me/ip",
    "http://api.ipify.org",
    "http://api.i.pn/json",
]


def load_history():
    if not HISTORY_FILE.exists():
        return {}

    with open(HISTORY_FILE, encoding="utf-8") as f:
        data = json.load(f)

    return {
        i["id"]: i
        for i in data
    }


def save_history(history):
    HISTORY_FILE.parent.mkdir(
        exist_ok=True
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
        exist_ok=True
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
        unique = d.get("id", "")

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
        [
            node.protocol,
            node.address.lower(),
            str(node.port),
            unique,
        ]
    )

    return hashlib.sha256(
        raw.encode()
    ).hexdigest()[:16]


def export_node(node, result, history_item):
    return {
        "id": node_id(node),
        "protocol": node.protocol,
        "address": node.address,
        "port": node.port,
        "country": node.country,
        "countryName": COUNTRY_MAP.get(
            node.country,
            "未知",
        ),
        "uri": node.uri,
        "alias": node.data.get(
            "alias",
            "",
        ),
        "warning": list(set(
            result.get(
                "warning",
                []
            )
        )),
        "latency": result.get(
            "latency",
            -1,
        ),
        "successBool": result.get(
            "success",
            False,
        ),
        "success": history_item["success"],
        "total": history_item["total"],
        "lastCheck": int(time.time()),
    }
def build_outbound(node):

    p = node.protocol
    d = node.data

    if p == "vless":

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
                                "none"
                            ),
                            "flow": d.get(
                                "flow",
                                ""
                            ),
                        }
                    ]
                }
            ]
        }

        protocol = "vless"


    elif p == "vmess":

        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": d.get(
                                "id",
                                ""
                            ),
                            "alterId": int(
                                d.get(
                                    "alterId",
                                    0
                                )
                            ),
                            "security": d.get(
                                "securityType",
                                "auto"
                            )
                        }
                    ]
                }
            ]
        }

        protocol = "vmess"


    elif p == "trojan":

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "password": d.get(
                        "password",
                        ""
                    )
                }
            ]
        }

        protocol = "trojan"


    elif p == "ss":

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "method": d.get(
                        "method",
                        ""
                    ),
                    "password": d.get(
                        "password",
                        ""
                    )
                }
            ]
        }

        protocol = "shadowsocks"


    elif p in (
        "hy2",
        "hysteria2"
    ):

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "password": d.get(
                        "password",
                        ""
                    ),
                    "obfs": d.get(
                        "obfs",
                        ""
                    ),
                    "obfs-password": d.get(
                        "obfs-password",
                        ""
                    )
                }
            ]
        }

        protocol = "hysteria2"


    else:

        raise RuntimeError(
            f"Unsupported protocol: {p}"
        )


    return {
        "protocol": protocol,
        "settings": settings,
        "streamSettings":
            build_stream_settings(d)
    }

def build_stream_settings(d):

    network = d.get(
        "network",
        "tcp"
    ).lower()

    security = d.get(
        "security",
        ""
    ).lower()


    stream = {
        "network": network,
        "security": security
    }


    if security == "tls":

        stream["tlsSettings"] = {

            "serverName": d.get(
                "sni",
                ""
            ),

            "allowInsecure":
                str(
                    d.get(
                        "allowInsecure",
                        "0"
                    )
                ).lower()
                in (
                    "1",
                    "true",
                    "yes"
                )
        }


    elif security == "reality":

        stream["realitySettings"] = {

            "serverName": d.get(
                "sni",
                ""
            ),

            "fingerprint": d.get(
                "fp",
                "chrome"
            ),

            "publicKey": d.get(
                "pbk",
                ""
            ),

            "shortId": d.get(
                "sid",
                ""
            ),

            "spiderX": d.get(
                "spx",
                ""
            )
        }


    stream.update(
        build_transport_settings(
            network,
            d
        )
    )


    return stream

def build_transport_settings(network,d):

    if network == "ws":

        return {

            "wsSettings": {

                "path": d.get(
                    "path",
                    "/"
                ),

                "headers": {

                    "Host":
                        d.get(
                            "host",
                            ""
                        )

                }
            }
        }


    if network == "grpc":

        return {

            "grpcSettings": {

                "serviceName":
                    d.get(
                        "serviceName",
                        ""
                    ),

                "authority":
                    d.get(
                        "authority",
                        ""
                    )
            }
        }


    if network == "xhttp":

        return {

            "xhttpSettings": {

                "host":
                    d.get(
                        "host",
                        ""
                    ),

                "path":
                    d.get(
                        "path",
                        "/"
                    ),

                "mode":
                    d.get(
                        "mode",
                        "auto"
                    )
            }
        }


    if network == "httpupgrade":

        return {

            "httpupgradeSettings": {

                "host":
                    d.get(
                        "host",
                        ""
                    ),

                "path":
                    d.get(
                        "path",
                        "/"
                    )
            }
        }


    if network == "h2":

        return {

            "httpSettings": {

                "host":[
                    d.get(
                        "host",
                        ""
                    )
                ],

                "path":
                    d.get(
                        "path",
                        "/"
                    )
            }
        }


    if network == "tcp":

        return {

        }


    return {}

def local_socks():
    return {
        "listen": "127.0.0.1",
        "port": SOCKS_PORT,
        "protocol": "socks",
        "settings": {
            "udp": True,
        },
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
            build_outbound(node)
        ],
    }

def wait_port(port, timeout):

    start = time.time()

    while time.time() - start < timeout:

        try:

            with socket.create_connection(
                (
                    "127.0.0.1",
                    port
                ),
                timeout=1
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


    config = build_config(node)


    # IPv6支持
    config["routing"] = {
        "domainStrategy": "AsIs"
    }


    json.dump(
        config,
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
        START_TIMEOUT
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

                "--show-error",

                "--max-time",
                str(TEST_TIMEOUT),

                "--proxy",
                f"socks5h://127.0.0.1:{SOCKS_PORT}",

                "-A",
                "Mozilla/5.0",

                url,
            ],

            stdout=subprocess.PIPE,

            stderr=subprocess.DEVNULL,

        )


        return result.returncode == 0


    except Exception:

        return False

def test_google():

    for url in GOOGLE:

        if curl_test(url):

            return True

    return False

def test_backup():

    for url in HTTPS_BACKUP:

        if curl_test(url):

            return True

    return False

def test_http():

    for url in HTTP_TEST:

        if curl_test(url):

            return True

    return False

def check_node(node):

    result = {

        "id": node_id(node),

        "protocol": node.protocol,

        "address": node.address,

        "port": node.port,

        "country": node.country,

        "uri": node.uri,

        "warning": list(node.warning),

        "success": False,

        "latency": -1,

    }


    xray = None


    try:

        xray = start_xray(node)


        if not xray:

            return result


        # =====================
        # Google
        # =====================

        start = time.time()


        if test_google():

            result["success"] = True

            result["latency"] = int(
                (time.time()-start)*1000
            )


        else:

            # =====================
            # Google失败备用
            # =====================

            if test_backup():

                result["success"] = True

                result["latency"] = int(
                    (time.time()-start)*1000
                )


                if (
                    "noGooglePassing"
                    not in result["warning"]
                ):

                    result["warning"].append(
                        "noGooglePassing"
                    )


        # =====================
        # HTTP测试
        # =====================

        if result["success"]:

            if not test_http():

                if (
                    "notAvailableForNonSSLSites"
                    not in result["warning"]
                ):

                    result["warning"].append(
                        "notAvailableForNonSSLSites"
                    )


    except Exception:

        traceback.print_exc()


    finally:

        stop_xray(xray)


    return result

def history_warning(warning):

    keep = {

        "allowInsecure",

        "noLongerSupportedNetwork",

        "noGooglePassing",

        "notAvailableForNonSSLSites",

    }


    return list(
        set(
            i
            for i in warning
            if i in keep
        )
    )

