from collections import Counter, defaultdict
from ipaddress import IPv4Address, IPv6Address

from app.services.pipeline import qualifying_connections

FIELDS = (
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset",
    "http.request", "dns.flags.response", "dns.flags.rcode",
)
PROTOCOLS = (
    ("http", "HTTP"), ("http2", "HTTP/2"), ("quic", "QUIC"),
    ("tls", "TLS"), ("dns", "DNS"), ("ssh", "SSH"), ("icmp", "ICMP"),
    ("icmpv6", "ICMPv6"), ("arp", "ARP"), ("tcp", "Other TCP"),
    ("udp", "Other UDP"),
)
TRUE = {"1", "True"}
FALSE = {"0", "False"}
MONITORING = ("A.8.16", "Monitoring activities")
NETWORK_SECURITY = ("A.8.20", "Networks security")


def describe(title, detail, frames, addresses, grc, *, rule_ids=(), suggested_filter=None, controls=()):
    return {"title": title, "detail": detail, "frames": list(frames)[:5],
        "addresses": list(dict.fromkeys(addresses)), "grc": grc,
        "rule_ids": list(rule_ids), "suggested_filter": suggested_filter, "controls": list(controls)}


def strongest(groups, threshold):
    pair, evidence = max(groups.items(), key=lambda item: len(item[1]), default=(None, []))
    return (pair, evidence) if len(evidence) >= threshold else (None, [])


def summarize(rows, findings):
    protocols, endpoints = Counter(), Counter()
    resets, name_errors, web_requests = defaultdict(list), defaultdict(list), defaultdict(list)
    attempts = []
    for row in rows:
        (frame, timestamp, stack, source, destination, source6, destination6, port, syn,
         ack, reset, request, dns_response, dns_code) = row.split("\t")
        layers = set(stack.split(":"))
        protocol = next((label for token, label in PROTOCOLS if token in layers), "Other")
        protocols[protocol] += 1
        if not (source and destination):
            if source6 and destination6:
                endpoints.update({str(IPv6Address(source6)), str(IPv6Address(destination6))})
            continue
        pair = (str(IPv4Address(source)), str(IPv4Address(destination)))
        endpoints.update(set(pair))
        frame = int(frame)
        if syn in TRUE and ack in FALSE and port:
            attempts.append({"frame": frame, "time": float(timestamp), "source": pair[0],
                "destination": pair[1], "port": int(port)})
        if reset in TRUE:
            resets[pair].append(frame)
        if request in TRUE:
            web_requests[pair].append(frame)
        if dns_response in TRUE and dns_code == "3":
            name_errors[pair].append(frame)

    observations = []
    for finding in findings:
        if not finding["count"]:
            continue
        flows = finding["flows"]
        controls = ", ".join(control["id"] for control in finding["risk"]["controls"])
        grc = f"Review mapped controls {controls} against the packet evidence." if controls else "Record the evidence and review the relevant monitoring controls."
        addresses = [address for flow in flows[:2] for address in (flow["source"], flow["destination"])]
        observations.append(describe(finding["name"],
            f"Configured rule {finding['id']} matched {finding['count']:,} frames.",
            [flow["frame"] for flow in flows], addresses, grc, rule_ids=[finding["id"]]))

    scans = defaultdict(list)
    for flow in qualifying_connections({"min_connections": 10, "window_seconds": 60}, attempts):
        scans[flow["source"], flow["destination"]].append(flow["frame"])
    pair, evidence = strongest(scans, 10)
    if pair:
        source, destination = pair
        observations.append(describe("TCP port probing pattern",
            "One source attempted to open connections to at least 10 different TCP ports on the same destination within 60 seconds. Check whether it was an authorised scan.",
            evidence, pair, "Check approved scanning records and review network monitoring.",
            suggested_filter=f"ip.src == {source} && ip.dst == {destination} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
            controls=[MONITORING, NETWORK_SECURITY]))

    for title, groups, threshold, qualifier, guidance, filter_expression, control in (
        ("Repeated TCP resets", resets, 8, "TCP reset frames. Check for failed sessions, service interruptions or expected connection handling.",
         "Review monitoring records and any related service incident.", "tcp.flags.reset == 1", MONITORING),
        ("DNS name errors", name_errors, 3, "DNS name-error responses (NXDOMAIN). Check for mistyped names, stale configuration or unusual lookup patterns.",
         "Review DNS monitoring and whether the lookups were expected.", "dns.flags.response == 1 && dns.flags.rcode == 3", MONITORING),
        ("Plaintext HTTP requests", web_requests, 1, "plaintext HTTP request frames. Check whether the service was expected to use TLS and what data was exposed.",
         "Review encryption requirements and the sensitivity of data sent over the connection.", "http.request", NETWORK_SECURITY),
    ):
        pair, evidence = strongest(groups, threshold)
        if pair:
            source, destination = pair
            observations.append(describe(title, f"This endpoint pair had {len(evidence):,} {qualifier}", evidence, pair,
                guidance, suggested_filter=f"ip.src == {source} && ip.dst == {destination} && {filter_expression}",
                controls=[control]))

    return {
        "protocols": [{"name": name, "frames": count} for name, count in protocols.most_common()],
        "endpoints": [{"address": address, "frames": count} for address, count in endpoints.most_common(8)],
        "observations": observations,
    }
