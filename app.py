import streamlit as st

st.set_page_config(page_title="ART - The ASN Relationship Tool)", layout="wide")

st.title("FART - The ASN Relationship Tool")
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
        st.success("Inputs accepted.")
        st.write("ASNs:", cleaned)

        # Stub output for now
        st.subheader("Summary")
        st.write("This is a stub summary. Next step is to add live data collectors and inference.")

        st.subheader("Graph (stub)")
        st.info("Graph rendering will be added after the report JSON model is implemented.")

