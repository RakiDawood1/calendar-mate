from calendar_auth import CalendarAuth
from event_parser import EventParser
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

class CalendarManager:
    def __init__(self):
        self.auth = CalendarAuth()
        self.parser = EventParser()
        self.service = self.auth.authenticate()
        self.timezone = 'Asia/Kolkata'
        self.last_event_details = None  

    def create_event(self, user_input):
        event_details = self.parser.parse_request(user_input)
        self.last_event_details = event_details  # Store the details
        if not event_details:
            return "Failed to parse event details"

        event = {
            'summary': event_details['description'],
            'start': {
                'dateTime': f"{event_details['date']}T{event_details['start_time']}:00",
                'timeZone': self.timezone,
            },
            'end': {
                'dateTime': self.calculate_end_time(event_details),
                'timeZone': self.timezone,
            },
            'attendees': [{'email': email} for email in event_details['attendees']]
        }

        try:
            created_event = self.service.events().insert(calendarId='primary', body=event).execute()
            return f"Event created: {created_event.get('htmlLink')}"
        except Exception as e:
            return f"Error creating event: {e}"

    def calculate_end_time(self, event_details):
        try:
            start = datetime.fromisoformat(f"{event_details['date']}T{event_details['start_time']}:00")
            duration = event_details.get('duration_minutes', 30)  # Default 30 mins
            end = start + timedelta(minutes=duration)
            return end.isoformat()
        except Exception as e:
            print(f"Error calculating end time: {e}")
            # Return default end time (30 mins from start)
            return (start + timedelta(minutes=30)).isoformat()