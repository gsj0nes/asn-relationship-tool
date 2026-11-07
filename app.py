import streamlit as st
import uuid                                    # added manually
from datetime import datetime, timezone        # added manually

st.set_page_config(page_title="ART - The ASN Relationship Tool)", layout="wide")

st.title("ART - The ASN Relationship Tool")
st.caption("Input a mximum of 10 ASNs")

count = st.number_input("How many ASNs would you like to compare?", min_value=1, max_value=10, value=2, step=1)

asns = []
cols = st.columns(2)
for i in range(int(count)):
    with cols[i % 2]:
        asn = st.text_input(f"ASN #{i+1}", value="")
        asns.append(asn.strip())

if st.button("Analyze"):
    cleaned = []
    errors = []
    for idx, raw in enumerate(asns, start=1):
        if not raw:
            errors.append(f"ASN #{idx} is empty.")
            continue
        raw2 = raw.upper().replace("AS", "").strip()
        if not raw2.isdigit():
            errors.append(f"ASN #{idx} is not a valid number: '{raw}'.")
            continue
        cleaned.append(int(raw2))

    if errors:
        st.error("Please fix the following:\n" + "\n".join([f"- {e}" for e in errors]))
    else:
        # --- 1) Build a stub report JSON object ---
        report_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc).isoformat()

        report = {
            "reportMeta": {
                "reportId": report_id,
                "generatedAt": now_utc,
                "timezone": "UTC",
                "toolVersion": "0.1.0",
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
                    "unknown"
                ]
            },
            "summary": {
                "paragraph": (
                    f"Stub report generated for {len(cleaned)} ASN(s): "
                    + ", ".join([f'AS{a}' for a in cleaned])
                    + ". Live data collectors not enabled yet."
                ),
                "highlights": [
                    {
                        "type": "data_quality",
                        "message": "This is a stub report (no external lookups performed yet).",
                        "relatedIds": []
                    }
                ]
            },
            "sources": [],
            "nodes": [
                {
                    "id": f"asn-{a}",
                    "asn": a,
                    "displayName": f"AS{a}",
                    "enrichment": {},
                    "evidence": [],
                    "identityMatches": [],
                    "tags": []
                }
                for a in cleaned
            ],
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
                        "rulesApplied": []
                    }
                }
            }
        }

        st.subheader("Summary")
        st.write(report["summary"]["paragraph"])

        st.subheader("Report JSON (stub)")
        st.json(report)
