import streamlit as st
from calendar_manager import CalendarManager
from datetime import datetime
from dotenv import load_dotenv
import os
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import json

# Load environment variables for local development
load_dotenv()

def clear_auth_tokens():
    """
    Cleans up all authentication-related session state variables.
    This ensures a clean slate when signing out or when authentication errors occur.
    """
    auth_related_keys = ['authenticated', 'user_info', 'auth_flow']
    for key in auth_related_keys:
        if key in st.session_state:
            del st.session_state[key]
    
    # Also clear any stored credentials
    for key in list(st.session_state.keys()):
        if key.startswith('credentials_'):
            del st.session_state[key]

def get_redirect_uri():
    """
    Determines the appropriate redirect URI based on the current environment.
    Returns different URIs for local development versus production deployment.
    """
    base_url = str(st.get_url())
    if "localhost" in base_url:
        return "http://localhost:8501/_stcore/oauth2-redirect"
    return "https://calendar-mate.streamlit.app/_stcore/oauth2-redirect"

def initialize_google_auth():
    """
    Initializes the Google OAuth2 flow with proper scopes and configuration.
    Uses Streamlit secrets for secure credential management and handles both
    local and production environments.
    """
    # Define authentication scopes in the required order
    ordered_scopes = [
        'openid',  # OpenID must be first for proper authentication
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ]
    
    # Get the appropriate redirect URI for the current environment
    redirect_uri = get_redirect_uri()
    
    # Create client configuration using Streamlit secrets
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
    
    # Initialize the OAuth flow with the configuration
    flow = Flow.from_client_config(
        client_config,
        scopes=ordered_scopes,
        redirect_uri=redirect_uri
    )
    return flow

def get_user_info(credentials):
    """
    Fetches user information using the provided credentials.
    This information is used to personalize the user experience and manage user-specific data.
    """
    from googleapiclient.discovery import build
    
    try:
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        return user_info
    except Exception as e:
        st.error(f"Error fetching user info: {e}")
        return None

def save_credentials(credentials, user_email):
    """
    Securely saves user credentials in Streamlit's session state.
    Uses the user's email as a unique identifier for their credentials.
    """
    try:
        st.session_state[f'credentials_{user_email}'] = credentials.to_json()
    except Exception as e:
        st.error(f"Failed to save credentials: {e}")
        raise

def load_credentials(user_email):
    """
    Loads and validates user credentials from session state.
    Returns None if credentials are not found or invalid.
    """
    try:
        if f'credentials_{user_email}' in st.session_state:
            credentials_json = st.session_state[f'credentials_{user_email}']
            return Credentials.from_authorized_user_info(json.loads(credentials_json))
    except Exception as e:
        st.error(f"Error loading credentials: {e}")
    return None

def validate_auth_state():
    """
    Validates the current authentication state and ensures all required
    components are present and valid.
    """
    if not st.session_state.get('authenticated'):
        return False
        
    user_info = st.session_state.get('user_info')
    if not user_info or 'email' not in user_info:
        clear_auth_tokens()
        return False
        
    credentials = load_credentials(user_info['email'])
    if not credentials or not credentials.valid:
        clear_auth_tokens()
        return False
        
    return True

def render_calendar_interface():
    """
    Renders the main calendar interface where users can create events.
    Handles event creation and displays results.
    """
    st.write("Enter your meeting or reminder request in natural language. For example:")
    st.write("- 'Schedule a team meeting tomorrow at 2 PM'")
    st.write("- 'Remind me to pay bills next Friday at 10 AM'")
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
            credentials = load_credentials(st.session_state.user_info['email'])
            if not credentials:
                st.error("Authentication error. Please sign in again.")
                clear_auth_tokens()
                st.rerun()
                return

            with st.spinner("Creating your event..."):
                manager = CalendarManager(credentials)
                result = manager.create_event(user_input)
                
            event_details = manager.last_event_details
            if event_details:
                col1, col2 = st.columns(2)
                with col1:
                    st.success("✅ Event created successfully!")
                    st.write("### Event Details")
                    st.write(f"📅 Date: {event_details['date']}")
                    st.write(f"🕒 Time: {event_details['start_time']}")
                    st.write(f"⏱️ Duration: {event_details['duration_minutes']} minutes")
                    st.write(f"📝 Description: {event_details['description']}")
                
                with col2:
                    st.write("### Calendar Link")
                    st.write(result)
            else:
                st.error("Could not create the event. Please try again.")
                st.info("Make sure your request includes a clear date and time.")
        except Exception as e:
            st.error(f"Error creating event: {str(e)}")
            st.info("Please try again or sign out and sign back in if the problem persists.")

def main():
    """
    Main application function that handles the overall flow and user interface.
    Manages authentication state and renders appropriate interfaces.
    """
    st.title("Calendar Assistant")
    
    # Initialize session state variables
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'auth_flow' not in st.session_state:
        st.session_state.auth_flow = None

    # Validate existing authentication if present
    if st.session_state.authenticated and not validate_auth_state():
        st.warning("Your session has expired. Please sign in again.")
        st.session_state.authenticated = False

    # Handle non-authenticated users
    if not st.session_state.authenticated:
        st.write("Please sign in with Google to continue")
        
        if st.button("Sign in with Google"):
            try:
                flow = initialize_google_auth()
                st.session_state.auth_flow = flow
                
                auth_url, _ = flow.authorization_url(
                    access_type='offline',
                    include_granted_scopes='true'
                )
                
                st.markdown(f'<meta http-equiv="refresh" content="0;url={auth_url}">', unsafe_allow_html=True)
                
            except Exception as e:
                st.error(f"Error initializing authentication: {str(e)}")
                st.info("Please check if all required credentials are properly configured.")
                return
    
    # Handle authenticated users
    else:
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        
        with col2:
            if st.button("Sign Out", type="secondary"):
                clear_auth_tokens()
                st.rerun()
        
        render_calendar_interface()

if __name__ == "__main__":
    main()