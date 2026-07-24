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

    return "_".join(

        (

            node.protocol,

            node.address,

            str(node.port),

        )

    )

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

    # -------------------------
    # settings
    # -------------------------

    if p == "vless":

        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": d["id"],
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

        protocol = "vless"

    elif p == "vmess":

        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": d["id"],
                            "security": d.get(
                                "securityType",
                                "auto",
                            ),
                            "alterId": int(
                                d.get(
                                    "alterId",
                                    0,
                                )
                            ),
                        }
                    ],
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
                    "password": d["password"],
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
                    "method": d["method"],
                    "password": d["password"],
                }
            ]
        }

        protocol = "shadowsocks"

    elif p in (
        "hy2",
        "hysteria2",
    ):

        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "password": d["password"],
                }
            ]
        }

        protocol = "hysteria2"

    else:

        raise RuntimeError(
            f"暂不支持协议 {p}"
        )

    # -------------------------
    # streamSettings
    # -------------------------

    network = d.get(
        "network",
        "tcp",
    )

    security = d.get(
        "security",
        "",
    )

    ss = {

        "network": network,

        "security": security,

    }

    # ---------- TLS ----------

    if security == "tls":

        ss["tlsSettings"] = {

            "serverName":
                d.get("sni", ""),

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

    # ---------- REALITY ----------

    elif security == "reality":

        ss["realitySettings"] = {

            "serverName":
                d.get("sni", ""),

            "fingerprint":
                d.get("fp", ""),

            "publicKey":
                d.get("pbk", ""),

            "shortId":
                d.get("sid", ""),

            "spiderX":
                d.get("spx", ""),

        }

    # -------------------------
    # transport
    # -------------------------

    if network == "ws":

        ss["wsSettings"] = {

            "path":

                d.get("path", "/"),

            "headers": {

                "Host":

                    d.get(
                        "host",
                        "",
                    )

            },

        }

    elif network == "grpc":

        ss["grpcSettings"] = {

            "serviceName":

                d.get(
                    "serviceName",
                    "",
                ),

        }

    elif network == "xhttp":

        ss["xhttpSettings"] = {

            "host":

                d.get(
                    "host",
                    "",
                ),

            "path":

                d.get(
                    "path",
                    "/",
                ),

            "mode":

                d.get(
                    "mode",
                    "",
                ),

        }

    elif network == "httpupgrade":

        ss["httpupgradeSettings"] = {

            "host":

                d.get(
                    "host",
                    "",
                ),

            "path":

                d.get(
                    "path",
                    "/",
                ),

        }

    elif network == "h2":

        ss["httpSettings"] = {

            "host": [

                d.get(
                    "host",
                    "",
                )

            ],

            "path":

                d.get(
                    "path",
                    "/",
                ),

        }

    elif network == "kcp":

        ss["kcpSettings"] = {}

    elif network == "quic":

        ss["quicSettings"] = {}

    elif network == "tcp":

        pass

    else:

        print(
            "未知 transport:",
            network,
        )

    return {

        "protocol": protocol,

        "settings": settings,

        "streamSettings": ss,

    }
