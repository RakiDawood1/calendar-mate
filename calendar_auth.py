from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import streamlit as st
from google.auth.transport.requests import Request
import json
import http.cookies as Cookie
from datetime import datetime, timedelta

def parse_cookie(cookie_string):
    cookie = Cookie.SimpleCookie()
    cookie.load(cookie_string)
    return {key: morsel.value for key, morsel in cookie.items()}

class CalendarAuth:
    def __init__(self):
        self.SCOPES = [
            'openid',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        self.creds = None
        self._load_credentials()

    def _load_credentials(self):
        """Load credentials from session state with error handling"""
        try:
            if 'user_info' in st.session_state and st.session_state.user_info:
                user_email = st.session_state.user_info.get('email')
                if user_email and f'credentials_{user_email}' in st.session_state:
                    creds_json = st.session_state[f'credentials_{user_email}']
                    self.creds = Credentials.from_authorized_user_info(eval(creds_json))
        except Exception as e:
            st.error(f"Failed to load credentials: {str(e)}")
            self.clear_auth_state()

    def clear_auth_state(self):
        """Clear all authentication related state"""
        auth_keys = [key for key in st.session_state.keys() 
                    if key.startswith('credentials_') or key in ['user_info', 'authenticated']]
        for key in auth_keys:
            del st.session_state[key]
        self.creds = None

    def get_credentials(self):
        """Get valid credentials, refresh if needed"""
        try:
            if not self.creds:
                return None
                
            if self.creds.expired:
                if self.creds.refresh_token:
                    self.creds.refresh(Request())
                    if 'user_info' in st.session_state:
                        self.save_credentials(self.creds, st.session_state.user_info['email'])
                else:
                    self.clear_auth_state()
                    return None
                    
            return self.creds
        except Exception as e:
            st.error(f"Error refreshing credentials: {str(e)}")
            self.clear_auth_state()
            return None

    @staticmethod
    def save_credentials(credentials, user_email):
        """Save credentials with error handling"""
        try:
            token = credentials.to_json()
            st.session_state[f'credentials_{user_email}'] = token
            return True
        except Exception as e:
            st.error(f"Failed to save credentials: {str(e)}")
            return False

    def check_auth_state(self):
        """Check authentication state and refresh if needed"""
        try:
            if not self.creds:
                return None
                
            if self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
                if 'user_info' in st.session_state:
                    self.save_credentials(self.creds, st.session_state.user_info['email'])
            return self.creds
        except Exception as e:
            st.error(f"Auth state check failed: {str(e)}")
            self.clear_auth_state()
            return None

    @staticmethod
    def create_flow():
        """Create OAuth flow with proper redirect URI handling"""
        base_uri = st.secrets.get("BASE_URI", "https://calendar-mate.streamlit.app")
        redirect_uri = f"{base_uri}/_stcore/oauth2-redirect"
        
        client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                "token_uri": st.secrets["google_oauth"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": [redirect_uri]
            }
        }
        
        try:
            return Flow.from_client_config(
                client_config,
                scopes=[
                    'openid',
                    'https://www.googleapis.com/auth/calendar',
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/userinfo.profile'
                ],
                redirect_uri=redirect_uri
            )
        except Exception as e:
            st.error(f"Failed to create OAuth flow: {str(e)}")
            return None

    def refresh_token_if_expired(self):
        """Refresh token if expired, with error handling"""
        try:
            if self.creds and self.creds.expired:
                if self.creds.refresh_token:
                    self.creds.refresh(Request())
                    if 'user_info' in st.session_state:
                        self.save_credentials(self.creds, st.session_state.user_info['email'])
                    return True
                else:
                    self.clear_auth_state()
            return False
        except Exception as e:
            st.error(f"Token refresh failed: {str(e)}")
            self.clear_auth_state()
            return False