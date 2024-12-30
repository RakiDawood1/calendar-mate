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
    scopes = [
        'openid',
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ]
    
    # Create client config from secrets
    client_config = {
        "web": {
            "client_id": st.secrets["google_oauth"]["client_id"],
            "project_id": st.secrets["google_oauth"]["project_id"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": st.secrets["google_oauth"]["client_secret"],
            "redirect_uris": st.secrets["google_oauth"]["redirect_uris"]
        }
    }
    
    # Use redirect URI from secrets
    redirect_uri = (
    "https://calendar-mate.streamlit.app"
    if st.secrets["secrets"]["env"] == "prod"
    else "http://localhost:8501"
)
    
    flow = Flow.from_client_config(
        client_config,
        scopes=scopes,
        redirect_uri=redirect_uri
    )
    
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    return auth_url, state, flow
    
def get_user_info(credentials):
    """Fetches the user's information using their credentials."""
    try:
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        return user_info
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
    """Cleans up all authentication-related session state variables."""
    auth_related_keys = [
        'authenticated', 
        'user_info', 
        'oauth_state', 
        'oauth_config',
        'last_processed_code'
    ]
    for key in auth_related_keys:
        if key in st.session_state:
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
    """Renders the sign-in button and handles the OAuth flow."""
    if st.button("Sign in with Google", key="google_signin"):
        try:
            # Generate the auth URL and state
            auth_url, state, _ = initialize_google_auth()
            
            # Store state in session
            st.session_state['oauth_state'] = state
            
            # Redirect using Streamlit's built-in functionality
            st.link_button("Continue to Google Sign In", auth_url)
            
        except Exception as e:
            st.error("Failed to initialize authentication")
            st.error(f"Error details: {str(e)}")
            return False
    
    return True

def main():
    """Main application function with fixed OAuth callback handling."""
    st.title("Calendar Assistant")
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
        
    # Get query parameters
    params = st.query_params
    
    # Handle OAuth callback
    if 'code' in params:
        if 'last_processed_code' not in st.session_state or st.session_state.last_processed_code != params['code']:
            try:
                st.session_state.last_processed_code = params['code']
                
                # Get stored OAuth configuration
                oauth_config = st.session_state.get('oauth_config', {})
                if not oauth_config:
                    st.error("OAuth configuration not found. Please try signing in again.")
                    return
                    
                # Create new flow
                flow = Flow.from_client_config(
                    oauth_config['client_config'],
                    scopes=oauth_config['scopes'],
                    redirect_uri=oauth_config['redirect_uri']
                )
                
                # Fetch token
                flow.fetch_token(code=params['code'])
                
                # Get user info
                credentials = flow.credentials
                user_info = get_user_info(credentials)
                
                if user_info:
                    st.session_state.authenticated = True
                    st.session_state.user_info = user_info
                    save_credentials(credentials, user_info['email'])
                    
                # Clear params and reload
                st.query_params.clear()
                st.rerun()
                
            except Exception as e:
                st.error(f"Authentication error: {str(e)}")
                clear_auth_tokens()
                st.query_params.clear()
                st.rerun()
                return

        # Auto redirect if still on callback URL
        if '_stcore/oauth2-redirect' in st.runtime.get_url():
            st.markdown(f'<meta http-equiv="refresh" content="0;url=https://calendar-mate.streamlit.app">', unsafe_allow_html=True)
            st.stop()
    if st.query_params.get("code"):
        st.markdown("""
        # Redirecting...
        Please wait while we complete your sign in. If you're not redirected automatically, 
        [click here to return to the app](https://calendar-mate.streamlit.app)
        """)
        
        # Add JavaScript for redirect
        st.components.v1.html(
            """
            <script>
                setTimeout(function() {
                    window.location.href = 'https://calendar-mate.streamlit.app';
                }, 2000);
            </script>
            """,
            height=0
        )
        return
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    
    # Debug information
    st.write("### Debug Information")
    st.write("Available secret sections:", list(st.secrets.keys()))
    if "secrets" in st.secrets:
        st.write("Environment setting:", st.secrets["secrets"].get("env"))
    
    # Get query parameters
    params = st.query_params
    
    # Handle OAuth callback
    if 'code' in params and 'state' in params:
        try:
            # First check if we've already processed this code
            if 'last_processed_code' not in st.session_state or st.session_state.last_processed_code != params['code']:
                st.session_state.last_processed_code = params['code']
                
                if st.session_state.get('oauth_state') == params['state']:
                    # Get stored OAuth configuration
                    oauth_config = st.session_state.get('oauth_config', {})
                    
                    # Create new flow
                    flow = Flow.from_client_config(
                        oauth_config['client_config'],
                        scopes=oauth_config['scopes'],
                        redirect_uri=oauth_config['redirect_uri']
                    )
                    
                    # Fetch the token
                    token = flow.fetch_token(code=params['code'])
                    
                    # Get user credentials and info
                    credentials = flow.credentials
                    user_info = get_user_info(credentials)
                    
                    if user_info:
                        st.session_state.authenticated = True
                        st.session_state.user_info = user_info
                        save_credentials(credentials, user_info['email'])
                        
                        # Clear query parameters and reload the page
                        st.query_params.clear()
                        st.rerun()
                    
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            clear_auth_tokens()
            st.query_params.clear()
            st.rerun()
    
    # Show appropriate interface based on authentication state
    if not st.session_state.authenticated:
        st.write("Please sign in with Google to continue")
        if st.button("Sign in with Google", key="google_signin"):
            try:
                # Generate the auth URL and state
                auth_url, state, _ = initialize_google_auth()
                
                # Store state in session
                st.session_state['oauth_state'] = state
                
                # Redirect using link button
                st.link_button("Continue to Google Sign In", auth_url)
                
            except Exception as e:
                st.error("Failed to initialize authentication")
                st.error(f"Error details: {str(e)}")
    else:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        with col2:
            if st.button("Sign Out", type="secondary"):
                clear_auth_tokens()
                st.query_params.clear()
                st.rerun()
        
        render_calendar_interface()

if __name__ == "__main__":
    main()