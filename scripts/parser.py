import base64
import json
from dataclasses import dataclass, field
from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
)

from warning import detect_warning


SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hy2",
    "hysteria2",
}


@dataclass
class Node:

    protocol: str

    address: str

    port: int

    country: str

    uri: str

    warning: list = field(default_factory=list)

    data: dict = field(default_factory=dict)

def decode_base64(text: str):

    text = text.strip()

    pad = (-len(text)) % 4

    text += "=" * pad

    return base64.urlsafe_b64decode(text).decode()

def read_nodes(path):

    lines = [
        i.rstrip()
        for i in open(path, encoding="utf-8")
        if i.strip()
    ]

    if len(lines) % 2:
        raise RuntimeError(
            "node.txt 每个节点必须两行"
        )

    result = []

    for i in range(0, len(lines), 2):

        result.append(
            (
                lines[i],
                lines[i + 1].upper(),
            )
        )

    return result

PARSERS = {}


def register(name):

    def wrapper(func):

        PARSERS[name] = func

        return func

    return wrapper

def parse(uri, country):

    protocol = uri.split("://", 1)[0].lower()

    if protocol not in PARSERS:

        raise RuntimeError(
            f"暂不支持协议 {protocol}"
        )

    return PARSERS[protocol](
        uri,
        country,
    )

def split_alias(uri: str):
    """
    返回：
        body
        alias(不含#)
    """

    if "#" in uri:
        body, alias = uri.split("#", 1)
        return body, unquote(alias)

    return uri, ""

def get_query(parsed):

    q = {}

    for k, v in parse_qs(parsed.query).items():

        if not v:
            continue

        q[k] = v[0]

    return q

def build_node(
    protocol,
    parsed,
    country,
    uri,
    data,
):

    node = Node(
        protocol=protocol,
        address=parsed.hostname,
        port=parsed.port,
        country=country,
        uri=uri,
    )

    node.data = data

    node.warning = detect_warning(
        protocol,
        data,
    )

    return node

@register("vless")
def parse_vless(uri, country):

    body, alias = split_alias(uri)

    parsed = urlparse(body)

    q = get_query(parsed)

    data = {

        "id": parsed.username,

        "encryption":
            q.get("encryption", "none"),

        "flow":
            q.get("flow", ""),

        "security":
            q.get("security", ""),

        "network":
            q.get(
                "type",
                q.get("network", "tcp"),
            ),

        "host":
            q.get("host", ""),

        "path":
            q.get("path", ""),

        "serviceName":
            q.get("serviceName", ""),

        "authority":
            q.get("authority", ""),

        "mode":
            q.get("mode", ""),

        "sni":
            q.get("sni", ""),

        "fp":
            q.get("fp", ""),

        "pbk":
            q.get("pbk", ""),

        "sid":
            q.get("sid", ""),

        "spx":
            q.get("spx", ""),

        "allowInsecure":
            q.get(
                "allowInsecure",
                q.get("insecure", "0"),
            ),

        "alias":
            alias,
    }

    return build_node(
        "vless",
        parsed,
        country,
        uri,
        data,
    )

@register("trojan")
def parse_trojan(uri, country):

    body, alias = split_alias(uri)

    parsed = urlparse(body)

    q = get_query(parsed)

    data = {

        "password":
            parsed.username,

        "network":
            q.get(
                "type",
                q.get("network", "tcp"),
            ),

        "security":
            q.get("security", "tls"),

        "host":
            q.get("host", ""),

        "path":
            q.get("path", ""),

        "serviceName":
            q.get("serviceName", ""),

        "authority":
            q.get("authority", ""),

        "mode":
            q.get("mode", ""),

        "sni":
            q.get("sni", ""),

        "fp":
            q.get("fp", ""),

        "allowInsecure":
            q.get(
                "allowInsecure",
                q.get("insecure", "0"),
            ),

        "alias":
            alias,
    }

    return build_node(
        "trojan",
        parsed,
        country,
        uri,
        data,
    )

@register("vmess")
def parse_vmess(uri, country):

    body, alias = split_alias(uri)

    encoded = body[len("vmess://"):]

    obj = json.loads(
        decode_base64(encoded)
    )

    if not alias:
        alias = obj.get("ps", "")

    class P:
        pass

    parsed = P()

    parsed.hostname = obj["add"]
    parsed.port = int(obj["port"])

    data = {

        "id":
            obj.get("id", ""),

        "aid":
            obj.get("aid", "0"),

        "security":
            obj.get("tls", ""),

        "network":
            obj.get("net", "tcp"),

        "host":
            obj.get("host", ""),

        "path":
            obj.get("path", ""),

        "serviceName":
            obj.get("serviceName", ""),

        "authority":
            obj.get("authority", ""),

        "mode":
            obj.get("mode", ""),

        "sni":
            obj.get("sni", ""),

        "fp":
            obj.get("fp", ""),

        "allowInsecure":
            obj.get(
                "allowInsecure",
                obj.get("insecure", "0"),
            ),

        "alias":
            alias,
    }

    return build_node(
        "vmess",
        parsed,
        country,
        uri,
        data,
    )

@register("ss")
def parse_ss(uri, country):

    body, alias = split_alias(uri)

    parsed = urlparse(body)

    user = parsed.username

    password = parsed.password

    if user is None:

        raw = body[len("ss://"):]

        if "@" in raw:

            left, right = raw.split("@", 1)

            decoded = decode_base64(left)

            method, password = decoded.split(":", 1)

            parsed = urlparse(
                "ss://" + decoded + "@" + right
            )

            user = method

        else:

            decoded = decode_base64(raw)

            method, rest = decoded.split("@", 1)

            parsed = urlparse(
                "ss://" + method + "@" + rest
            )

            user, password = method.split(":", 1)

    q = get_query(parsed)

    data = {

        "method":
            user,

        "password":
            password,

        "plugin":
            q.get("plugin", ""),

        "network":
            "tcp",

        "allowInsecure":
            q.get(
                "allowInsecure",
                q.get("insecure", "0"),
            ),

        "alias":
            alias,
    }

    return build_node(
        "ss",
        parsed,
        country,
        uri,
        data,
    )

@register("hy2")
@register("hysteria2")
def parse_hy2(uri, country):

    body, alias = split_alias(uri)

    parsed = urlparse(body)

    q = get_query(parsed)

    data = {

        "password":
            parsed.username,

        "sni":
            q.get("sni", ""),

        "obfs":
            q.get("obfs", ""),

        "obfs-password":
            q.get("obfs-password", ""),

        "allowInsecure":
            q.get(
                "allowInsecure",
                q.get("insecure", "0"),
            ),

        "alias":
            alias,
    }

    return build_node(
        "hy2",
        parsed,
        country,
        uri,
        data,
    )

