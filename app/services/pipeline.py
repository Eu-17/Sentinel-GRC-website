from collections import defaultdict, deque
from ipaddress import IPv4Address

from app.catalog import RULES
from app.services.grc_engine import assess
from app.services.soc_triage import brief


def qualifying_connections(rule, flows):
    """Count distinct source ports per pair in a rolling window, ignoring retransmits."""
    if "min_connections" not in rule:
        return flows
    pairs = defaultdict(list)
    for flow in flows:
        pairs[flow["source"], flow["destination"]].append(flow)
    accepted = set()
    for group in pairs.values():
        window = deque()
        ports = {}
        for flow in sorted(group, key=lambda item: item["time"]):
            while window and flow["time"] - window[0]["time"] > rule["window_seconds"]:
                old = window.popleft()
                ports[old["port"]] -= 1
                if not ports[old["port"]]:
                    del ports[old["port"]]
            window.append(flow)
            ports[flow["port"]] = ports.get(flow["port"], 0) + 1
            if len(ports) >= rule["min_connections"]:
                # Frames in this window are now confirmed. Only traverse new entries.
                for item in reversed(window):
                    if item["frame"] in accepted:
                        break
                    accepted.add(item["frame"])
    return [flow for flow in flows if flow["frame"] in accepted]


def build_report(name, engine, frames, matches, *, allow_model=True, rules=RULES):
    items = []
    for rule in rules:
        flows = qualifying_connections(rule, matches[rule["id"]])
        risk = assess(rule, flows)
        egress = rule["direction"] == "egress"
        addresses = sorted({IPv4Address(f["destination" if egress else "source"]) for f in flows})
        prefix = "OUTPUT -d" if egress else "INPUT -s"
        items.append({
            "id": rule["id"], "name": rule["name"], "severity": rule["severity"],
            "technique": rule["technique"], "technique_name": rule["technique_name"],
            "tactic": rule["tactic"], "count": len(flows),
            "flows": [{k: v for k, v in flow.items() if k != "port"} for flow in flows[:10]],
            "firewall": [f"iptables -A {prefix} {ip} -j DROP" for ip in addresses[:10]],
            "address_count": len(addresses), "playbook": rule["playbook"],
            "risk": risk, "brief": brief(rule, flows, risk, allow_model=allow_model),
        })
    return {"capture": name, "engine": engine, "frames": frames, "findings": items}
