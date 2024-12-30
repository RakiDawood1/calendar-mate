from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import pickle
import streamlit as st


class CalendarAuth:
    def __init__(self):
        self.SCOPES = ['https://www.googleapis.com/auth/calendar']
        self.creds = None

        # Check for existing token in streamlit secrets
        if 'token' in st.session_state:
            self.creds = Credentials.from_authorized_user_info(
                st.session_state.token, self.SCOPES)

        # Refresh or get new credentials
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', self.SCOPES)
                self.creds = flow.run_local_server(port=0)

            # Save credentials in session state
            st.session_state.token = self.creds.to_json()

    def get_credentials(self):
       return self.creds