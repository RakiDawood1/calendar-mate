import streamlit as st
import json
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import logging
logging.basicConfig(level=logging.INFO)

class CalendarAuth:
    def __init__(self):
        self.SCOPES = ['https://www.googleapis.com/auth/calendar']
        self.logger = logging.getLogger(__name__)
        try:
            self.credentials = json.loads(st.secrets['google_credentials'])
            self.redirect_uri = f"https://{st.secrets['DOMAIN']}/callback"
            self.flow = Flow.from_client_config(
                self.credentials,
                scopes=self.SCOPES,
                redirect_uri=self.redirect_uri
            )
        except Exception as e:
            self.logger.error(f"Init error: {e}")
            raise RuntimeError("Failed to initialize authentication.")

    def authenticate(self):
        try:
            # Debug current state
            st.write("Auth state:", dict(st.query_params))
            
            if 'code' in st.query_params:
                st.write(f"Got code: {st.query_params['code']}")
                code = st.query_params['code']
                self.flow.fetch_token(code=code)
                st.session_state['token'] = self.flow.credentials
                return build('calendar', 'v3', credentials=self.flow.credentials)
            
            elif 'token' in st.session_state:
                st.write("Using existing token")
                credentials = Credentials.from_authorized_user_info(
                    st.session_state['token'],
                    self.SCOPES
                )
                if credentials and not credentials.expired:
                    return build('calendar', 'v3', credentials=credentials)
                st.write("Token expired")
                del st.session_state['token']
            
            st.write("Starting new auth flow")
            authorization_url, _ = self.flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true'
            )
            st.markdown(f'Please [login with Google]({authorization_url})')
            return None

        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            st.error(f"Auth error: {str(e)}")
            return None

    def logout(self):
        if 'token' in st.session_state:
            del st.session_state['token']
            st.success("Successfully logged out")

    def is_authenticated(self):
        return 'token' in st.session_state