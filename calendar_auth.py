from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import streamlit as st
import json

class CalendarAuth:
    def __init__(self):
        self.SCOPES = ['https://www.googleapis.com/auth/calendar']
        self.creds = None

        # Create credentials.json content from secrets
        self.client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                "token_uri": st.secrets["google_oauth"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": st.secrets["google_oauth"]["redirect_uris"]
            }
        }

        # Initialize the Flow using the config dictionary
        try:
            flow = InstalledAppFlow.from_client_config(
                self.client_config, self.SCOPES)
            self.creds = flow.run_local_server(port=0)
        except Exception as e:
            st.error(f"Authentication failed: {str(e)}")
            raise

    def get_credentials(self):
        return self.creds