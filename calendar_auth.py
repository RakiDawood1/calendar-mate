from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import streamlit as st
from google.auth.transport.requests import Request
import json
import http.cookies as Cookie

def parse_cookie(cookie_string):
        cookie = Cookie.SimpleCookie()
        cookie.load(cookie_string)
        return {key: morsel.value for key, morsel in cookie.items()}

class CalendarAuth:
    def __init__(self):
        """Initialize the Calendar authentication with proper web OAuth flow"""
        self.SCOPES = [
            'openid',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        
        # Initialize credentials
        self.creds = None
        
        # Get credentials from session state if available
        if 'user_info' in st.session_state and st.session_state.user_info:
            user_email = st.session_state.user_info.get('email')
            if user_email and f'credentials_{user_email}' in st.session_state:
                creds_json = st.session_state[f'credentials_{user_email}']
                self.creds = Credentials.from_authorized_user_info(eval(creds_json))
        
    

    def get_credentials(self):
        """Return the current credentials or None if not authenticated"""
        return self.creds
    
    def save_credentials(credentials, user_email):
        token = credentials.to_json()
        st.session_state['auth_token'] = token
        st.session_state[f'credentials_{user_email}'] = token

    def check_auth_state(self):
        try:
            if 'auth_token' in st.session_state:
                credentials = Credentials.from_authorized_user_info(
                    json.loads(st.session_state['auth_token'])
                )
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                    st.session_state['auth_token'] = credentials.to_json()
                return credentials
            return None
        except Exception as e:
            st.error(f"Auth state check failed: {str(e)}")
            return None
    

    @staticmethod
    def create_flow():
        """Create and configure the OAuth flow for web applications"""
        client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                "token_uri": st.secrets["google_oauth"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": [
                    "https://calendar-mate.streamlit.app/_stcore/oauth2-redirect",
                    "http://localhost:8501/_stcore/oauth2-redirect"
                ]
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