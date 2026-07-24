from urllib.parse import parse_qs, urlparse

REMOVED_NETWORKS = {
    "quic",
    "h2",
    "kcp",
}

def detect_warning(protocol: str, info: dict):
    """
    返回节点固有 warning（可写入 history）

    allowInsecure
    noLongerSupportedNetwork
    """

    warning = []

    # allowInsecure
    insecure = (
        info.get("allowInsecure")
        or info.get("insecure")
        or info.get("skip-cert-verify")
    )

    if str(insecure).lower() in (
        "1",
        "true",
        "yes",
    ):
        warning.append("allowInsecure")

    # network
    network = (
        info.get("network")
        or info.get("type")
        or ""
    ).lower()

    if network in REMOVED_NETWORKS:
        warning.append("noLongerSupportedNetwork")

    return warning
