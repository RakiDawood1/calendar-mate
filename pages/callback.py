import streamlit as st

if 'token' in st.session_state:
    st.success("Successfully authenticated!")
    st.script_html("<script>window.close();</script>")