import streamlit as st
import json
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import logging
logging.basicConfig(level=logging.INFO)

class CalendarAuth:
    """
    Handles Google Calendar authentication using OAuth 2.0
    """
    
    def __init__(self):
        """
        Initialize the authentication handler with necessary scopes
        and configuration
        """
        self.SCOPES = ['https://www.googleapis.com/auth/calendar']
        try:
            self.credentials = json.loads(st.secrets['google_credentials'])
            self.flow = Flow.from_client_config(
                self.credentials,
                scopes=self.SCOPES,
                redirect_uri=f"https://{st.secrets['DOMAIN']}/callback"
            )
        except Exception as e:
            print(f"Auth Error: {e}")
            raise RuntimeError("Failed to initialize authentication.")

    def authenticate(self):
        """
        Handles the OAuth2 flow for Google Calendar authentication
        
        Returns:
            googleapiclient.discovery.Resource: Authenticated Calendar API service
            or None if authentication is not complete
        """
        try:
            # Create OAuth2 flow instance
            flow = Flow.from_client_config(
                self.credentials,
                scopes=self.SCOPES,
                redirect_uri=self.redirect_uri
            )

            # Check if we're in the OAuth callback
            if 'code' in st.experimental_get_query_params():
                code = st.experimental_get_query_params()['code'][0]
                flow.fetch_token(code=code)
                st.session_state['token'] = flow.credentials
                return build('calendar', 'v3', credentials=flow.credentials)
            
            # Check if we have a stored token
            elif 'token' in st.session_state:
                # Verify token is still valid
                credentials = Credentials.from_authorized_user_info(
                    st.session_state['token'],
                    self.SCOPES
                )
                if credentials and not credentials.expired:
                    return build('calendar', 'v3', credentials=credentials)
                else:
                    # Clear invalid token
                    del st.session_state['token']
            
            # Start new authentication flow
            authorization_url, _ = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true'
            )
            st.markdown(
                f'Please [login with Google]({authorization_url}) to authorize access to your calendar.'
            )
            return None

        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            st.error("An error occurred during authentication. Please try again.")
            return None

    def logout(self):
        """
        Clears the stored authentication token
        """
        if 'token' in st.session_state:
            del st.session_state['token']
            st.success("Successfully logged out")

    def is_authenticated(self):
        """
        Checks if the user is currently authenticated
        
        Returns:
            bool: True if authenticated, False otherwise
        """
        return 'token' in st.session_state