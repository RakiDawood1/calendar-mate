import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import json
from datetime import datetime
from calendar_manager import CalendarManager
from event_parser import EventParser
import os
from dotenv import load_dotenv

# Load environment variables for local development
load_dotenv()

def initialize_google_auth():
    """
    Creates a simplified Google OAuth2 flow with enhanced environment checking.
    """
    try:
        # First, explicitly check and print environment configuration
        environment = st.secrets.get("secrets", {}).get("env")
        st.write("Debug Information:")
        st.write(f"Raw environment setting: {environment}")
        
        # Determine if we're in production based on environment setting
        is_production = environment == "prod"
        
        # Set the redirect URI based on environment
        redirect_uri = (
            "https://calendar-mate.streamlit.app/_stcore/oauth2-redirect"
            if is_production
            else "http://localhost:8501/_stcore/oauth2-redirect"
        )
        
        st.write(f"Production mode: {is_production}")
        st.write(f"Selected redirect URI: {redirect_uri}")
        
        # Define the scopes our application needs
        scopes = [
            'openid',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
        
        # Create the client configuration dictionary
        client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": [redirect_uri]  # Use the selected redirect URI
            }
        }
        
        # Create the OAuth flow
        flow = Flow.from_client_config(
            client_config,
            scopes=scopes,
            redirect_uri=redirect_uri
        )
        
        # Generate the authorization URL
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        # Print full configuration for debugging
        st.write("Configuration Summary:")
        st.write("- Environment:", environment)
        st.write("- Redirect URI:", redirect_uri)
        st.write("- Scopes:", ", ".join(scopes))
        st.write("Auth URL Preview (first 100 chars):")
        st.write(auth_url[:100] + "...")
        
        return auth_url, state, flow
        
    except Exception as e:
        st.error("Authentication Initialization Error")
        st.error(f"Error type: {type(e).__name__}")
        st.error(f"Error details: {str(e)}")
        
        # Print current secrets configuration (excluding sensitive data)
        st.error("Secrets Configuration Check:")
        st.error(f"- Secrets keys available: {list(st.secrets.keys())}")
        raise e
    
def get_user_info(credentials):
    """Fetches the user's information using their credentials."""
    try:
        service = build('oauth2', 'v2', credentials=credentials)
        return service.userinfo().get().execute()
    except Exception as e:
        st.error(f"Error fetching user info: {str(e)}")
        return None

def save_credentials(credentials, user_email):
    """Saves the user's credentials in the session state."""
    try:
        st.session_state[f'credentials_{user_email}'] = credentials.to_json()
    except Exception as e:
        st.error(f"Failed to save credentials: {str(e)}")

def clear_auth_tokens():
    """Clears all authentication-related session state variables."""
    auth_related_keys = ['authenticated', 'user_info', 'oauth_state', 'oauth_config']
    for key in auth_related_keys:
        if key in st.session_state:
            del st.session_state[key]
    
    # Clear any stored credentials
    for key in list(st.session_state.keys()):
        if key.startswith('credentials_'):
            del st.session_state[key]

def render_calendar_interface():
    """
    Renders the main calendar interface where users can create events.
    Handles event creation and displays results in a user-friendly format.
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
            # Get credentials from session state
            if not st.session_state.user_info:
                st.error("User information not found. Please sign in again.")
                return
                
            credentials = Credentials.from_authorized_user_info(
                json.loads(st.session_state[f'credentials_{st.session_state.user_info["email"]}'])
            )
            
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

def render_sign_in_button():
    """
    Renders a sign-in button that handles the OAuth flow directly.
    """
    if st.button("Sign in with Google"):
        try:
            # Generate the auth URL and state
            auth_url, state, _ = initialize_google_auth()
            
            # Store state for verification
            st.session_state['oauth_state'] = state
            
            # Create a direct HTML link for authentication
            html_code = f'''
                <meta http-equiv="refresh" content="0; url={auth_url}">
                <p>Redirecting to Google sign-in...</p>
            '''
            
            st.markdown(html_code, unsafe_allow_html=True)
            
        except Exception as e:
            st.error("Failed to initialize authentication")
            st.error(f"Error details: {str(e)}")

def main():
    """
    Main application function with simplified authentication flow.
    """
    st.title("Calendar Assistant")
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    
    # Debug information (you can remove this in production)
    st.write("### Debug Information")
    st.write("Available secret sections:", list(st.secrets.keys()))
    if "secrets" in st.secrets:
        st.write("Environment setting:", st.secrets["secrets"].get("env"))
    
    # Handle OAuth callback parameters
    params = st.query_params
    if 'code' in params and 'state' in params:
        try:
            if st.session_state.get('oauth_state') == params['state']:
                # Get the stored OAuth configuration
                oauth_config = st.session_state.get('oauth_config', {})
                
                # Create a new flow
                flow = Flow.from_client_config(
                    oauth_config['client_config'],
                    scopes=oauth_config['scopes'],
                    redirect_uri=oauth_config['redirect_uri']
                )
                
                # Complete the OAuth flow
                flow.fetch_token(code=params['code'])
                
                # Get user credentials and info
                credentials = flow.credentials
                user_info = get_user_info(credentials)
                
                if user_info:
                    st.session_state.authenticated = True
                    st.session_state.user_info = user_info
                    save_credentials(credentials, user_info['email'])
                    st.query_params.clear()
                    st.experimental_rerun()
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            clear_auth_tokens()
    
    # Show sign-in button for non-authenticated users
    if not st.session_state.authenticated:
        st.write("Please sign in with Google to continue")
        render_sign_in_button()
    
    # Show the main interface for authenticated users
    else:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        with col2:
            if st.button("Sign Out", type="secondary"):
                clear_auth_tokens()
                st.experimental_rerun()
        
        render_calendar_interface()

if __name__ == "__main__":
    main()