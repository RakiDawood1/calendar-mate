import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import json
import os
import hashlib
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from calendar_manager import CalendarManager

@dataclass
class GoogleOAuthConfig:
    client_id: str
    project_id: str
    auth_uri: str
    token_uri: str
    auth_provider_cert_url: str
    client_secret: str
    redirect_uri: str = "https://calendar-mate.streamlit.app/"
    scopes: list = None

    def __post_init__(self):
        self.scopes = [
            'openid',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]

    @property
    def client_config(self) -> dict:
        return {
            "web": {
                "client_id": self.client_id,
                "project_id": self.project_id,
                "auth_uri": self.auth_uri,
                "token_uri": self.token_uri,
                "auth_provider_x509_cert_url": self.auth_provider_cert_url,
                "client_secret": self.client_secret,
                "redirect_uris": [self.redirect_uri]
            }
        }

class CalendarAuth:
    def __init__(self):
        self.config = GoogleOAuthConfig(
            client_id=st.secrets["google_oauth"]["client_id"],
            project_id=st.secrets["google_oauth"]["project_id"],
            auth_uri=st.secrets["google_oauth"]["auth_uri"],
            token_uri=st.secrets["google_oauth"]["token_uri"],
            auth_provider_cert_url=st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
            client_secret=st.secrets["google_oauth"]["client_secret"]
        )

    def initialize_flow(self) -> tuple[str, str, Flow]:
        flow = Flow.from_client_config(
            self.config.client_config,
            scopes=self.config.scopes,
            redirect_uri=self.config.redirect_uri
        )
        
        csrf_token = hashlib.sha256(os.urandom(32)).hexdigest()
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            state=csrf_token
        )
        
        return auth_url, csrf_token, flow

    @staticmethod
    def get_user_info(credentials: Credentials) -> Optional[Dict[str, Any]]:
        try:
            service = build('oauth2', 'v2', credentials=credentials)
            return service.userinfo().get().execute()
        except Exception as e:
            st.error(f"Failed to fetch user info: {e}")
            return None

    @staticmethod
    def save_credentials(credentials: Credentials, email: str):
        st.session_state[f'credentials_{email}'] = credentials.to_json()

    def check_auth_state(self) -> Optional[Credentials]:
        if not st.session_state.get('user_info'):
            return None

        email = st.session_state['user_info']['email']
        creds_key = f'credentials_{email}'
        
        if creds_key not in st.session_state:
            return None

        credentials = Credentials.from_authorized_user_info(
            json.loads(st.session_state[creds_key])
        )

        if credentials.expired and credentials.refresh_token:
            try:
                credentials.refresh(Request())
                self.save_credentials(credentials, email)
            except Exception:
                return None

        return credentials

class CalendarUI:
    @staticmethod
    def render_sign_in():
        auth = CalendarAuth()
        if st.button("Sign in with Google"):
            auth_url, csrf_token, _ = auth.initialize_flow()
            st.session_state['csrf_token'] = csrf_token
            st.link_button("Continue to Google Sign In", auth_url)

    @staticmethod
    def render_calendar_interface():
        st.write("Enter your meeting or reminder request in natural language:")
        st.write("- 'Schedule a team meeting tomorrow at 2 PM'")
        st.write("- 'Doctor's appointment in 3 days at 2:45 PM'")

        user_input = st.text_input(
            "Enter your request:",
            placeholder="e.g., Schedule a meeting tomorrow at 2pm"
        )

        if st.button("Create Event", use_container_width=True):
            if not user_input:
                st.warning("Please enter an event description.")
                return

            try:
                event_manager = CalendarManager(st.session_state.credentials)
                result = event_manager.create_event(user_input)
                CalendarUI.display_event_details(event_manager.last_event_details, result)
            except Exception as e:
                st.error(f"Failed to create event: {e}")

    @staticmethod
    def display_event_details(details: Dict[str, Any], calendar_link: str):
        if not details:
            st.error("Could not create the event. Please try again.")
            return

        col1, col2 = st.columns(2)
        with col1:
            st.success("✅ Event created successfully!")
            st.write("### Event Details")
            st.write(f"📅 Date: {details['date']}")
            st.write(f"🕒 Time: {details['start_time']}")
            st.write(f"⏱️ Duration: {details['duration_minutes']} minutes")
            st.write(f"📝 Description: {details['description']}")
        
        with col2:
            st.write("### Calendar Link")
            st.write(calendar_link)

def handle_oauth_callback():
    params = st.query_params
    if 'code' not in params or st.session_state.get('authenticated'):
        return

    try:
        auth = CalendarAuth()
        flow = Flow.from_client_config(
            auth.config.client_config,
            scopes=auth.config.scopes,
            redirect_uri=auth.config.redirect_uri
        )

        if params.get('state') != st.session_state.get('csrf_token'):
            raise ValueError("Invalid CSRF token")

        flow.fetch_token(code=params['code'])
        credentials = flow.credentials
        user_info = CalendarAuth.get_user_info(credentials)

        if user_info:
            st.session_state.authenticated = True
            st.session_state.user_info = user_info
            st.session_state.credentials = credentials
            CalendarAuth.save_credentials(credentials, user_info['email'])
            st.query_params.clear()
            st.rerun()

    except Exception as e:
        st.error(f"Authentication failed: {e}")
        clear_session_state()
        st.query_params.clear()
        st.rerun()

def clear_session_state():
    keys_to_clear = ['authenticated', 'user_info', 'csrf_token', 'credentials']
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]

def main():
    st.title("Calendar Assistant")

    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    # Handle OAuth callback
    handle_oauth_callback()

    # Main app flow
    if not st.session_state.authenticated:
        CalendarUI.render_sign_in()
    else:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        with col2:
            if st.button("Sign Out"):
                clear_session_state()
                st.rerun()
        
        CalendarUI.render_calendar_interface()

if __name__ == "__main__":
    main()