import streamlit as st

st.success("Authentication successful!")
if st.query_params.get("code"):
    st.session_state["oauth_code"] = st.query_params["code"]
    st.script_html("""
        <script>
        window.close();
        window.opener.location.reload();
        </script>
    """)