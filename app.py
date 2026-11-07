import re
import uuid
from datetime import datetime, timezone

import pandas as pd
import requests
import streamlit as st
from pyvis.network import Network

st.set_page_config(page_title="ASN Relationship Analyzer", layout="wide")

ACCENT_BLUE = "#355CFF"

# Page-level CSS:
# - Sticky relationship table (stays visible when you scroll)
# - Make it compact + readable
st.markdown(
    """
<style>
.sticky-rel-wrap {
  position: sticky;
  top: 0;
  z-index: 1000;
  background: white;
  padding: 0.5rem 0;
  border-bottom: 1px solid #e5e7eb;
}

.sticky-rel-card {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 10px 12px;
  background: #ffffff;
}

.sticky-rel-title {
  font-weight: 600;
  margin-bottom: 8px;
}

.sticky-rel-table {
  max-height: 220px;
  overflow: auto;
  border-radius: 8px;
}

.sticky-rel-table table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}

.sticky-rel-table th, .sticky-rel-table td {
  padding: 6px 8px;
  border-bottom: 1px solid #f3f4f6;
  text-align: left;
  vertical-align: top;
}

.sticky-rel-table th {
  position: sticky;
  top: 0;
  background: #f9fafb;
  z-index: 1;
}
</style>
""",
    unsafe_allow_html=True,
)

st.title("ASN Relationship Analyzer")
st.caption("Maximum of 10")

# API endpoint used for machine-readable collection
RIPESTAT_WHOIS_API_URL = "https://stat.ripe.net/data/whois/data.json?resource=AS{asn}"

# Human-friendly page used for citations/links in the UI
RIPESTAT_WHOIS_WIDGET_URL = "https://stat.ripe.net/widget/whois#w.resource=AS{asn}&w.show=maximized"


@st.cache_data(ttl=60 * 60)
def fetch_ripestat_whois(asn: int) -> dict:
    """Fetch WHOIS-style data for an ASN from RIPEstat. Cached for 1 hour."""
    url = RIPESTAT_WHOIS_API_URL.format(asn=asn)
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
    """Extract referenced ASNs from policy strings by finding AS<number> tokens."""
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


def source_map(report: dict) -> dict[str, dict]:
    return {s["id"]: s for s in report.get("sources", [])}


def node_id_to_asn(node_id: str) -> str:
    # node_id format is "asn-<number>" in this app
    try:
        return f"AS{int(node_id.split('-', 1)[1])}"
    except Exception:
        return node_id


def render_sticky_relationship_table(rel_df: pd.DataFrame) -> None:
    table_html = rel_df.to_html(index=False, escape=True)
    st.markdown(
        f"""
<div class="sticky-rel-wrap">
  <div class="sticky-rel-card">
    <div class="sticky-rel-title">Relationships shown in the graph</div>
    <div class="sticky-rel-table">
      {table_html}
    </div>
    <div style="font-size:12px;color:#6b7280;margin-top:8px;">
      Tip: The graph is set to <b>click-to-use</b>. Scroll past it safely; click the graph to activate pan/zoom.
      Click outside the graph (or press ESC) to deactivate.
    </div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_interactive_graph(report: dict) -> None:
    """
    Render the graph using PyVis and embed as an HTML string with st.iframe.

    - clickToUse=true prevents accidental scroll-wheel zoom while scrolling the page.
    - CSS injected into the generated HTML changes nav buttons from green to ACCENT_BLUE.
    """
    nodes = report.get("nodes", [])
    edges = report.get("edges", [])

    net = Network(height="560px", width="100%", bgcolor="#ffffff", font_color="#111827", directed=True)
    net.barnes_hut(gravity=-30000, central_gravity=0.3, spring_length=180, spring_strength=0.03, damping=0.09)

    for n in nodes:
        asn = n.get("asn")
        label = n.get("displayName") or f"AS{asn}"
        title = f"AS{asn}\n{label}"
        net.add_node(n["id"], label=f"AS{asn}", title=title, shape="dot")

    for e in edges:
        from_id = e["fromNodeId"]
        to_id = e["toNodeId"]
        rel = (e.get("relationship") or {}).get("type", "unknown")
        conf = (e.get("confidence") or {}).get("score", 0)
        status = e.get("status", "candidate")

        color = ACCENT_BLUE if status == "supported" else "#9CA3AF"
        width = 2 if conf < 0.85 else 4

        net.add_edge(
            from_id,
            to_id,
            label="",
            title=f"{node_id_to_asn(from_id)} → {node_id_to_asn(to_id)}\n{rel}\nconfidence {conf}",
            color=color,
            width=width,
            arrows="to",
        )

    net.set_options(
        f"""
        {{
          "clickToUse": true,
          "nodes": {{
            "font": {{ "size": 28, "face": "Arial", "color": "#111827" }},
            "scaling": {{ "min": 12, "max": 48 }},
            "borderWidth": 2,
            "color": {{
              "border": "{ACCENT_BLUE}",
              "background": "{ACCENT_BLUE}"
            }}
          }},
          "edges": {{
            "smooth": {{ "type": "dynamic" }}
          }},
          "interaction": {{
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": {{ "enabled": true }},
            "zoomSpeed": 0.3,
            "zoomView": true,
            "dragView": true
          }}
        }}
        """
    )

    html = net.generate_html()

    # Inject CSS to recolor the navigation buttons.
    nav_css = f"""
<style>
/* vis.js navigation buttons (override default green) */
div.vis-network div.vis-navigation div.vis-button {{
  background-color: {ACCENT_BLUE} !important;
  border: 1px solid {ACCENT_BLUE} !important;
  border-radius: 8px !important;
  box-shadow: none !important;
}}
div.vis-network div.vis-navigation div.vis-button:hover {{
  filter: brightness(0.92);
}}
div.vis-network div.vis-navigation div.vis-button:active {{
  filter: brightness(0.85);
}}
/* Disabled state */
div.vis-network div.vis-navigation div.vis-button.vis-button-disabled {{
  background-color: #A5B4FC !important;
  border-color: #A5B4FC !important;
  opacity: 0.65 !important;
}}
</style>
"""
    if "</head>" in html:
        html = html.replace("</head>", nav_css + "\n</head>")
    else:
        html = nav_css + "\n" + html

    st.iframe(html, width="stretch", height=620)


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

    report_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).isoformat()

    report = {
        "reportMeta": {
            "reportId": report_id,
            "generatedAt": now_utc,
            "timezone": "UTC",
            "toolVersion": "0.3.0",
            "disclaimer": (
                "ASN routing relationships and organizational associations can change over time. "
                "Results reflect public sources at lookup time."
            ),
            "requestedAsns": cleaned,
        },
        "summary": {"paragraph": "", "highlights": []},
        "sources": [],
        "nodes": [],
        "edges": [],
        "findings": [],
    }

    asn_to_kvs: dict[int, list[tuple[str, str]]] = {}
    sources_added: set[str] = set()

    with st.spinner("Looking up ASN records (RIPEstat WHOIS)..."):
        for asn in cleaned:
            src_id = f"src-ripe-whois-as{asn}"
            src_uri_human = RIPESTAT_WHOIS_WIDGET_URL.format(asn=asn)

            try:
                whois_json = fetch_ripestat_whois(asn)
                kvs = flatten_ripestat_records(whois_json)
                asn_to_kvs[asn] = kvs

                if src_id not in sources_added:
                    report["sources"].append(
                        {
                            "id": src_id,
                            "title": f"RIPEstat WHOIS widget for AS{asn}",
                            "uri": src_uri_human,
                            "tier": "A",
                            "retrievedAt": now_utc,
                        }
                    )
                    sources_added.add(src_id)

            except Exception as e:
                asn_to_kvs[asn] = []
                report["summary"]["highlights"].append(
                    {
                        "type": "data_quality",
                        "message": f"Lookup failed for AS{asn} via RIPEstat: {type(e).__name__}",
                        "relatedIds": [f"asn-{asn}"],
                    }
                )

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
                "enrichment": {"asName": as_name, "orgName": org_name},
            }
        )

    input_set = set(cleaned)
    emitted_edges: set[tuple[int, int]] = set()

    for customer_asn in cleaned:
        kvs = asn_to_kvs.get(customer_asn, [])
        import_lines = all_values(kvs, "import")
        import_refs = parse_referenced_asns(import_lines)

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
                    "relationship": {"type": "transit_provider_to_customer"},
                    "status": "supported",
                    "evidence": [
                        {
                            "id": f"ev-{edge_id}-import",
                            "type": "routing_policy_declared",
                            "tier": "A",
                            "statement": (
                                f"AS{customer_asn} declares an import policy referencing AS{provider_asn} "
                                f"(import from AS{provider_asn})."
                            ),
                            "sourceRefs": [
                                {"sourceId": f"src-ripe-whois-as{customer_asn}", "locator": "whois:data.records[].import"}
                            ],
                        }
                    ],
                    "confidence": {"score": 0.85, "label": "High"},
                }
            )

    edge_count = len(report["edges"])
    if edge_count == 0:
        report["summary"]["paragraph"] = (
            f"No declared routing-policy relationships were detected among the {len(cleaned)} input ASNs "
            f"using RIPEstat WHOIS."
        )
    else:
        report["summary"]["paragraph"] = (
            f"Detected {edge_count} relationship edge(s) among {len(cleaned)} input ASN(s) "
            f"based on declared routing policy (RIPEstat WHOIS)."
        )

    st.subheader("Summary")
    st.write(report["summary"]["paragraph"])
    st.caption(report["reportMeta"]["disclaimer"])

    st.subheader("Nodes")
    node_rows = []
    for n in report["nodes"]:
        enr = n.get("enrichment") or {}
        node_rows.append(
            {
                "ASN": f"AS{n['asn']}",
                "Display name": n.get("displayName"),
                "as-name": enr.get("asName"),
                "org-name": enr.get("orgName"),
            }
        )
    st.dataframe(pd.DataFrame(node_rows), width="stretch", hide_index=True)

    st.subheader("Edges")
    if report["edges"]:
        edge_rows = []
        for e in report["edges"]:
            edge_rows.append(
                {
                    "From": node_id_to_asn(e["fromNodeId"]),
                    "To": node_id_to_asn(e["toNodeId"]),
                    "Type": e["relationship"]["type"],
                    "Confidence": e["confidence"]["score"],
                }
            )
        st.dataframe(pd.DataFrame(edge_rows), width="stretch", hide_index=True)
    else:
        st.write("No edges detected.")

    st.subheader("Interactive graph")

    if report["edges"]:
        rel_df = pd.DataFrame(
            [
                {
                    "From": node_id_to_asn(e["fromNodeId"]),
                    "To": node_id_to_asn(e["toNodeId"]),
                    "Type": e["relationship"]["type"],
                    "Confidence": e["confidence"]["score"],
                }
                for e in report["edges"]
            ]
        )
        render_sticky_relationship_table(rel_df)
    else:
        st.write("No edges to draw.")

    render_interactive_graph(report)

    smap = source_map(report)
    st.subheader("Edge evidence & citations")
    if report["edges"]:
        for e in report["edges"]:
            with st.expander(
                f"{e['id']}  ({e['relationship']['type']}, confidence {e['confidence']['score']})",
                expanded=False,
            ):
                for ev in e.get("evidence", []):
                    st.write(f"- Evidence: {ev.get('statement')}")
                    refs = ev.get("sourceRefs", [])
                    if refs:
                        st.write("  - Citations:")
                        for r in refs:
                            src = smap.get(r["sourceId"])
                            if not src:
                                st.write(f"    - {r['sourceId']}")
                                continue
                            loc = r.get("locator")
                            loc_txt = f" (locator: {loc})" if loc else ""
                            st.markdown(f"    - [{src['tier']}] [{src['title']}]({src['uri']}){loc_txt}")
    else:
        st.write("No edge evidence available (no edges detected).")

    st.subheader("Sources (citations)")
    if report["sources"]:
        for s in report["sources"]:
            st.markdown(f"- [{s['tier']}] [{s['title']}]({s['uri']})")
    else:
        st.write("No sources recorded.")

    with st.expander("Report JSON (debug)", expanded=False):
        st.json(report)
