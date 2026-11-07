import re
import uuid
from datetime import datetime, timezone

import requests
import streamlit as st

st.set_page_config(page_title="ASN Relationship Analyzer", layout="wide")

st.title("ASN Relationship Analyzer")
st.caption("Maximum of 10")

RIPESTAT_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json?resource=AS{asn}"


@st.cache_data(ttl=60 * 60)
def fetch_ripestat_whois(asn: int) -> dict:
    """Fetch WHOIS-style data for an ASN from RIPEstat. Cached for 1 hour."""
    url = RIPESTAT_WHOIS_URL.format(asn=asn)
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.json()


def flatten_ripestat_records(whois_json: dict) -> list[tuple[str, str]]:
    """
    RIPEstat whois format: data.records is a list of records; each record is a list of {key,value}.
    Return flattened [(key,value), ...].
    """
    out: list[tuple[str, str]] = []
    records = (whois_json.get("data") or {}).get("records") or []
    for record in records:
        for kv in record:
            k = kv.get("key")
            v = kv.get("value")
            if isinstance(k, str) and isinstance(v, str):
                out.append((k.strip().lower(), v.strip()))
    return out


def first_value(kvs: list[tuple[str, str]], key: str) -> str | None:
    key = key.strip().lower()
    for k, v in kvs:
        if k == key and v:
            return v
    return None


def all_values(kvs: list[tuple[str, str]], key: str) -> list[str]:
    key = key.strip().lower()
    return [v for k, v in kvs if k == key and v]


def parse_referenced_asns(policy_lines: list[str]) -> set[int]:
    """
    Extract referenced ASNs from policy strings.
    Conservative: just extract any AS<number> in the line.
    """
    refs: set[int] = set()
    for line in policy_lines:
        for m in re.finditer(r"\bAS(\d+)\b", line.upper()):
            try:
                refs.add(int(m.group(1)))
            except ValueError:
                pass
    return refs


def normalize_asn_input(raw: str) -> int | None:
    """
    Accept: '35133' or 'AS35133' or 'asn 35133' etc.
    Extract first digit block.
    """
    if not raw:
        return None
    s = raw.strip().upper()
    m = re.search(r"(\d+)", s)
    if not m:
        return None
    asn_int = int(m.group(1))
    if asn_int < 1 or asn_int > 4294967295:
        return None
    return asn_int


count = st.number_input(
    "How many ASNs would you like to compare?",
    min_value=1,
    max_value=10,
    value=2,
    step=1,
)

asns_raw: list[str] = []
cols = st.columns(2)
for i in range(int(count)):
    with cols[i % 2]:
        asn_text = st.text_input(f"ASN #{i+1}", value="")
        asns_raw.append(asn_text)

if st.button("Analyze"):
    # ---- Validate inputs ----
    cleaned: list[int] = []
    errors: list[str] = []

    for idx, raw in enumerate(asns_raw, start=1):
        if not raw or not raw.strip():
            errors.append(f"ASN #{idx} is empty.")
            continue
        asn_int = normalize_asn_input(raw)
        if asn_int is None:
            errors.append(f"ASN #{idx} is not valid: '{raw}'. Use formats like 35133 or AS35133.")
            continue
        cleaned.append(asn_int)

    dupes = [a for a in set(cleaned) if cleaned.count(a) > 1]
    if dupes:
        errors.append("Duplicate ASN(s) provided: " + ", ".join([f"AS{a}" for a in sorted(dupes)]))

    if errors:
        st.error("Please fix the following:\n" + "\n".join([f"- {e}" for e in errors]))
        st.stop()

    # ---- Start report object ----
    report_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).isoformat()

    report = {
        "reportMeta": {
            "reportId": report_id,
            "generatedAt": now_utc,
            "timezone": "UTC",
            "toolVersion": "0.2.0",
            "disclaimer": (
                "ASN routing relationships and organizational associations can change over time. "
                "Results reflect public sources at lookup time."
            ),
            "requestedAsns": cleaned,
            "attributesModeled": [
                "provider",
                "customer",
                "affiliate",
                "subsidiary",
                "shared_ownership",
                "transit_provider",
                "transit_customer",
                "known_spammer",
                "peer",
                "unknown",
            ],
        },
        "summary": {
            "paragraph": "",
            "highlights": [],
        },
        "sources": [],
        "nodes": [],
        "edges": [],
        "findings": [],
        "renderHints": {
            "graph": {
                "layout": "force",
                "theme": "light",
                "densityGuard": {
                    "enabled": False,
                    "edgeCount": 0,
                    "visibleEdgeCount": 0,
                    "rulesApplied": [],
                },
            }
        },
    }

    # ---- Collect WHOIS data (RIPEstat) for each ASN ----
    asn_to_kvs: dict[int, list[tuple[str, str]]] = {}
    sources_added: set[str] = set()

    with st.spinner("Looking up ASN records (RIPEstat WHOIS)..."):
        for asn in cleaned:
            src_id = f"src-ripe-whois-as{asn}"
            src_uri = RIPESTAT_WHOIS_URL.format(asn=asn)

            try:
                whois_json = fetch_ripestat_whois(asn)
                kvs = flatten_ripestat_records(whois_json)
                asn_to_kvs[asn] = kvs

                if src_id not in sources_added:
                    report["sources"].append(
                        {
                            "id": src_id,
                            "title": f"RIPEstat WHOIS JSON for AS{asn}",
                            "uri": src_uri,
                            "tier": "A",
                            "retrievedAt": now_utc,
                        }
                    )
                    sources_added.add(src_id)

            except Exception as e:
                # Node still exists, but mark data quality issue
                asn_to_kvs[asn] = []
                report["summary"]["highlights"].append(
                    {
                        "type": "data_quality",
                        "message": f"Lookup failed for AS{asn} via RIPEstat: {type(e).__name__}",
                        "relatedIds": [f"asn-{asn}"],
                    }
                )

    # ---- Build nodes with basic enrichment ----
    for asn in cleaned:
        kvs = asn_to_kvs.get(asn, [])
        as_name = first_value(kvs, "as-name")
        descr = first_value(kvs, "descr")
        org_name = first_value(kvs, "org-name")

        display = as_name or org_name or f"AS{asn}"
        if descr and display != descr and len(descr) <= 60:
            display = f"{display} ({descr})"

        report["nodes"].append(
            {
                "id": f"asn-{asn}",
                "asn": asn,
                "displayName": display,
                "enrichment": {
                    "asName": as_name,
                    "orgName": org_name,
                },
                "evidence": [],
                "identityMatches": [],
                "tags": [],
            }
        )

    # ---- Infer edges from declared routing policy references ----
    # For each ASN A, if it "imports from ASB", infer B -> A as transit_provider_to_customer.
    input_set = set(cleaned)
    emitted_edges: set[tuple[int, int]] = set()

    for customer_asn in cleaned:
        kvs = asn_to_kvs.get(customer_asn, [])
        import_lines = all_values(kvs, "import")
        export_lines = all_values(kvs, "export")

        import_refs = parse_referenced_asns(import_lines)
        export_refs = parse_referenced_asns(export_lines)

        # Provider inference: customer imports routes from provider
        for provider_asn in sorted(import_refs.intersection(input_set)):
            if provider_asn == customer_asn:
                continue
            key = (provider_asn, customer_asn)
            if key in emitted_edges:
                continue
            emitted_edges.add(key)

            edge_id = f"edge-{provider_asn}-to-{customer_asn}-routing-policy"

            report["edges"].append(
                {
                    "id": edge_id,
                    "fromNodeId": f"asn-{provider_asn}",
                    "toNodeId": f"asn-{customer_asn}",
                    "relationship": {
                        "type": "transit_provider_to_customer",
                        "directionSemantics": "From provides transit/connectivity to To (inferred from declared import policy).",
                        "attributes": ["transit_provider", "transit_customer"],
                    },
                    "status": "supported",
                    "evidence": [
                        {
                            "id": f"ev-{edge_id}-import",
                            "type": "routing_policy_declared",
                            "tier": "A",
                            "statement": f"AS{customer_asn} declares an import policy referencing AS{provider_asn} (import from AS{provider_asn}).",
                            "sourceRefs": [
                                {"sourceId": f"src-ripe-whois-as{customer_asn}", "locator": "whois:data.records[].import"}
                            ],
                            "attributes": {
                                "customerAsn": customer_asn,
                                "providerAsn": provider_asn,
                                "importLineCount": len(import_lines),
                                "exportReferencesAlsoPresent": provider_asn in export_refs,
                            },
                        }
                    ],
                    "confidence": {
                        "score": 0.85,
                        "label": "High",
                        "breakdown": [
                            {
                                "delta": 0.85,
                                "reason": "Explicit declared routing policy references another input ASN in import lines (Tier A).",
                                "sourceIds": [f"src-ripe-whois-as{customer_asn}"],
                                "weightClass": "strong",
                            }
                        ],
                    },
                    "render": {
                        "style": "solid",
                        "color": "#355CFF",
                        "label": "transit/provider (declared)",
                        "defaultVisible": True,
                    },
                }
            )

    # ---- Summarize ----
    edge_count = len(report["edges"])
    if edge_count == 0:
        report["summary"]["paragraph"] = (
            f"No declared routing-policy relationships were detected among the {len(cleaned)} input ASNs "
            f"using the currently enabled collector (RIPEstat WHOIS)."
        )
    else:
        report["summary"]["paragraph"] = (
            f"Detected {edge_count} relationship edge(s) among {len(cleaned)} input ASN(s) "
            f"based on declared routing policy (RIPEstat WHOIS)."
        )
        report["summary"]["highlights"].append(
            {
                "type": "relationship",
                "message": f"{edge_count} declared policy-based relationship(s) found.",
                "relatedIds": [e["id"] for e in report["edges"]],
            }
        )

    st.subheader("Summary")
    st.write(report["summary"]["paragraph"])

    st.subheader("Edges (detected)")
    if report["edges"]:
        for e in report["edges"]:
            st.write(
                f"- {e['fromNodeId']} → {e['toNodeId']}: {e['relationship']['type']} "
                f"(confidence {e['confidence']['score']})"
            )
    else:
        st.write("No edges detected.")

    st.subheader("Report JSON")
    st.json(report)
