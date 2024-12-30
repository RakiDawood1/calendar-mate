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
from google.auth.transport.requests import Request

# Load environment variables for local development
load_dotenv()

def initialize_google_auth():
    scopes = [
        'openid',
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ]
    
    client_config = {
        "web": {
            "client_id": st.secrets["google_oauth"]["client_id"],
            "project_id": st.secrets["google_oauth"]["project_id"],
            "auth_uri": st.secrets["google_oauth"]["auth_uri"],
            "token_uri": st.secrets["google_oauth"]["token_uri"],
            "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
            "client_secret": st.secrets["google_oauth"]["client_secret"],
            "redirect_uris": ["https://calendar-mate.streamlit.app/"]
        }
    }
    
    redirect_uri = "https://calendar-mate.streamlit.app/"
    
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
            
            if credentials.expired and credentials.refresh_token:
                try:
                    credentials.refresh(Request())
                    save_credentials(credentials, st.session_state.user_info["email"])
                except Exception:
                    clear_auth_tokens()
                    st.rerun()

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
    if st.button("Sign in with Google", key="google_signin"):
        try:
            auth_url, state, _ = initialize_google_auth()
            
            # Store OAuth config immediately after initialization
            st.session_state['oauth_config'] = {
                'client_config': {
                    "web": {
                        "client_id": st.secrets["google_oauth"]["client_id"],
                        "project_id": st.secrets["google_oauth"]["project_id"],
                        "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                        "token_uri": st.secrets["google_oauth"]["token_uri"],
                        "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                        "client_secret": st.secrets["google_oauth"]["client_secret"],
                        "redirect_uris": ["https://calendar-mate.streamlit.app/"]
                    }
                },
                'scopes': [
                    'openid',
                    'https://www.googleapis.com/auth/calendar',
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/userinfo.profile'
                ],
                'redirect_uri': "https://calendar-mate.streamlit.app/"
            }
            st.session_state['oauth_state'] = state
            
            st.link_button("Continue to Google Sign In", auth_url)
        except Exception as e:
            st.error(f"Failed to initialize authentication: {str(e)}")
            return False
    return True

def main():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None

    st.title("Calendar Assistant")
    
    params = st.query_params
    
    if 'code' in params and not st.session_state.authenticated:
        try:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": st.secrets["google_oauth"]["client_id"],
                        "project_id": st.secrets["google_oauth"]["project_id"],
                        "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                        "token_uri": st.secrets["google_oauth"]["token_uri"],
                        "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                        "client_secret": st.secrets["google_oauth"]["client_secret"],
                        "redirect_uris": ["https://calendar-mate.streamlit.app/"]
                    }
                },
                scopes=['openid', 'https://www.googleapis.com/auth/calendar', 
                       'https://www.googleapis.com/auth/userinfo.email', 
                       'https://www.googleapis.com/auth/userinfo.profile'],
                redirect_uri="https://calendar-mate.streamlit.app/"
            )
            
            flow.fetch_token(code=params['code'])
            credentials = flow.credentials
            user_info = get_user_info(credentials)
            
            if user_info:
                st.session_state.authenticated = True
                st.session_state.user_info = user_info
                save_credentials(credentials, user_info['email'])
                st.query_params.clear()
                st.rerun()
            
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            clear_auth_tokens()
            st.query_params.clear()
            st.rerun()
    
    if not st.session_state.authenticated:
        if st.button("Sign in with Google"):
            auth_url, state, _ = initialize_google_auth()
            st.link_button("Continue to Google Sign In", auth_url)
    else:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write(f"Welcome, {st.session_state.user_info['name']}!")
        with col2:
            if st.button("Sign Out"):
                clear_auth_tokens()
                st.rerun()
        
        render_calendar_interface()
        
if __name__ == "__main__":
    main()