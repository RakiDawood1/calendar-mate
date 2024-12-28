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
           self.redirect_uri = f"https://{st.secrets['DOMAIN']}/_stcore/callback"
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
           # Use stored token
           if 'token' in st.session_state:
               credentials = Credentials.from_authorized_user_info(
                   json.loads(st.session_state['token']),
                   self.SCOPES
               )
               return build('calendar', 'v3', credentials=credentials)
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