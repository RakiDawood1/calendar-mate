from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import streamlit as st
from google.auth.transport.requests import Request
import json
import http.cookies as Cookie

class CalendarAuth:
    def __init__(self):
        self.SCOPES = [
            'openid',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        self.creds = None
        self._initialize_session()
        self._load_credentials()

    def _initialize_session(self):
        """Initialize session state variables"""
        if 'credentials_store' not in st.session_state:
            st.session_state.credentials_store = {}
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False

    def _load_credentials(self):
        """Load and validate stored credentials"""
        try:
            if 'user_info' in st.session_state and st.session_state.user_info:
                user_email = st.session_state.user_info.get('email')
                if user_email and f'credentials_{user_email}' in st.session_state:
                    creds_json = st.session_state[f'credentials_{user_email}']
                    self.creds = Credentials.from_authorized_user_info(json.loads(creds_json))
                    
                    # Refresh token if expired
                    if self.creds and self.creds.expired and self.creds.refresh_token:
                        self.creds.refresh(Request())
                        self.save_credentials(self.creds, user_email)
        except Exception as e:
            print(f"Error loading credentials: {e}")
            self.creds = None

    @staticmethod
    def save_credentials(credentials, user_email):
        """Save credentials to session state"""
        if credentials and user_email:
            token = credentials.to_json()
            st.session_state[f'credentials_{user_email}'] = token
            st.session_state.authenticated = True
            return True
        return False

    def check_auth_state(self):
        """Verify authentication state and refresh if needed"""
        if not self.creds:
            return None
            
        try:
            if self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
                if 'user_info' in st.session_state:
                    self.save_credentials(self.creds, st.session_state.user_info['email'])
            return self.creds
        except Exception:
            return None

    def get_credentials(self):
        return self.check_auth_state()

    @staticmethod
    def create_flow():
        client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                "token_uri": st.secrets["google_oauth"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": ["https://calendar-mate.streamlit.app/_stcore/oauth2-redirect"]
            }
        }
        
        return Flow.from_client_config(
            client_config,
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/calendar',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],
            redirect_uri="https://calendar-mate.streamlit.app/_stcore/oauth2-redirect"
        )