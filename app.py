import re
import uuid
from datetime import datetime, timezone

import streamlit as st

st.set_page_config(page_title="|ART| - The ASN Relationship Tool", layout="wide")

st.title("|ART| - The ASN Relationship Tool")
st.caption("Maximum of 10")

count = st.number_input(
    "How many ASNs would you like to compare?",
    min_value=1,
    max_value=10,
    value=2,
    step=1
)

asns = []
cols = st.columns(2)
for i in range(int(count)):
    with cols[i % 2]:
        asn = st.text_input(f"ASN #{i+1}", value="")
        asns.append(asn)

# IMPORTANT: Everything that uses `errors` must be inside this block
if st.button("Analyze"):
    cleaned = []
    errors = []

    for idx, raw in enumerate(asns, start=1):
        if not raw or not raw.strip():
            errors.append(f"ASN #{idx} is empty.")
            continue

        # Accept inputs like: "35133", "AS35133", "as 35133", "ASN35133"
        s = raw.strip().upper()

        # Extract the first digit block anywhere in the string
        m = re.search(r"(\d+)", s)
        if not m:
            errors.append(f"ASN #{idx} is not valid: '{raw}' (no digits found).")
            continue

        asn_int = int(m.group(1))

        # Basic sanity check (32-bit ASN range)
        if asn_int < 1 or asn_int > 4294967295:
            errors.append(f"ASN #{idx} is out of range: '{raw}' -> {asn_int}.")
            continue

        cleaned.append(asn_int)

    # Optional: prevent duplicates
    dupes = [a for a in set(cleaned) if cleaned.count(a) > 1]
    if dupes:
        errors.append(
            "Duplicate ASN(s) provided: " + ", ".join([f"AS{a}" for a in sorted(dupes)])
        )

    if errors:
        st.error("Please fix the following:\n" + "\n".join([f"- {e}" for e in errors]))
    else:
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
                    + ", ".join([f"AS{a}" for a in cleaned])
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
