import streamlit as st
from calendar_manager import CalendarManager
from datetime import datetime
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import json

# Configure the page settings for a better user experience
st.set_page_config(
    page_title="Calendar Assistant",
    page_icon="📅",
    layout="wide"
)

def initialize_google_auth():
    """
    Initialize Google OAuth2 authentication using credentials from Streamlit secrets.
    Returns a Flow object for handling the OAuth2 process.
    """
    try:
        # Create client configuration dictionary from Streamlit secrets
        client_config = {
            "web": {
                "client_id": st.secrets["google_oauth"]["client_id"],
                "project_id": st.secrets["google_oauth"]["project_id"],
                "auth_uri": st.secrets["google_oauth"]["auth_uri"],
                "token_uri": st.secrets["google_oauth"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["google_oauth"]["auth_provider_x509_cert_url"],
                "client_secret": st.secrets["google_oauth"]["client_secret"],
                "redirect_uris": st.secrets["google_oauth"]["redirect_uris"]
            }
        }

        # Initialize the OAuth2 flow with the configuration
        flow = Flow.from_client_config(
            client_config,
            scopes=['https://www.googleapis.com/auth/calendar'],
            redirect_uri=st.secrets["google_oauth"]["redirect_uris"][0]
        )
        return flow
    except Exception as e:
        st.error(f"Failed to initialize Google authentication: {str(e)}")
        st.info("Please check if all required credentials are properly set in Streamlit secrets.")
        raise

def create_sidebar():
    """
    Create and configure the sidebar with useful information and options.
    """
    with st.sidebar:
        st.title("ℹ️ About")
        st.write("""
        This Calendar Assistant helps you schedule events using natural language.
        Simply type your event details, and it will create a calendar entry for you.
        """)
        
        st.subheader("✨ Features")
        st.write("""
        - Natural language processing
        - Automatic time parsing
        - Google Calendar integration
        - Multiple attendee support
        """)
        
        st.subheader("📝 Example Inputs")
        st.write("""
        - "Team meeting tomorrow at 2 PM"
        - "Lunch with John next Friday at 12:30 PM"
        - "Doctor's appointment in 3 days at 2:45 PM"
        """)

def display_event_details(event_details, calendar_link):
    """
    Display the created event details in a well-formatted manner.
    """
    # Create two columns for better layout
    col1, col2 = st.columns(2)
    
    with col1:
        st.success("✅ Event created successfully!")
        st.write("### Event Details")
        st.write(f"📅 **Date:** {event_details['date']}")
        st.write(f"🕒 **Time:** {event_details['start_time']}")
        st.write(f"⏱️ **Duration:** {event_details['duration_minutes']} minutes")
        st.write(f"📝 **Description:** {event_details['description']}")
        
        if event_details.get('attendees'):
            st.write("👥 **Attendees:**")
            for attendee in event_details['attendees']:
                st.write(f"  - {attendee}")
    
    with col2:
        st.write("### Google Calendar Link")
        st.markdown(f"[Open in Google Calendar]({calendar_link})")

def main():
    """
    Main application function that handles the UI and event creation logic.
    """
    # Create the sidebar
    create_sidebar()
    
    # Main content
    st.title("📅 Calendar Assistant")
    st.write("Enter your meeting or reminder request in natural language.")
    
    # User input section
    user_input = st.text_input(
        "Enter your request:",
        placeholder="e.g., Schedule a team meeting tomorrow at 2pm",
        key="event_input"
    )
    
    # Add some spacing
    st.write("")
    
    # Create event button with loading spinner
    if st.button("🎯 Create Event", use_container_width=True):
        if not user_input:
            st.warning("Please enter an event description.")
            return
            
        try:
            with st.spinner("Creating your event..."):
                # Initialize calendar manager and create event
                manager = CalendarManager()
                result = manager.create_event(user_input)
                
                # Get and display event details
                event_details = manager.last_event_details
                if event_details and result:
                    display_event_details(event_details, result)
                else:
                    st.error("Could not create the event. Please try again.")
                    st.info("Make sure your event description includes a clear date and time.")
                    
        except Exception as e:
            st.error("Failed to create event")
            st.error(f"Error details: {str(e)}")
            st.info("""
            If you're seeing an authentication error, please try:
            1. Refreshing the page
            2. Clearing your browser cache
            3. Logging in to Google Calendar again
            """)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error("Application Error")
        st.write(f"An unexpected error occurred: {str(e)}")
        st.info("Please refresh the page or contact support if the issue persists.")