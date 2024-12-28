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
           if 'code' in st.query_params:
               code = st.query_params['code']
               self.flow.fetch_token(code=code)
               st.session_state['token'] = self.flow.credentials.to_json()
               st.rerun()
               return build('calendar', 'v3', credentials=self.flow.credentials)
           
           elif 'token' in st.session_state:
               credentials = Credentials.from_authorized_user_info(
                   json.loads(st.session_state['token']),
                   self.SCOPES
               )
               if credentials and not credentials.expired:
                   return build('calendar', 'v3', credentials=credentials)
               del st.session_state['token']
           
           authorization_url, _ = self.flow.authorization_url(
               access_type='offline',
               prompt='consent',
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