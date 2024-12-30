import google.generativeai as genai
import json
from datetime import datetime, timedelta
import streamlit as st

class EventParser:
    def __init__(self):
        try:
            api_key = st.secrets.get("GOOGLE_AI_KEY")
            if not api_key:
                raise ValueError("Missing GOOGLE_AI_KEY in secrets")
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
        except Exception as e:
            st.error(f"Error initializing Gemini AI: {str(e)}")
            self.model = None

    def parse_request(self, user_input: str):
        # Validate input
        if not user_input or not user_input.strip():
            st.warning("Please provide an event description.")
            return None

        # Get current date and time in the user's timezone
        current_date = datetime.now().astimezone()
        
        # Enhanced prompt with more examples and clear instructions
        prompt = f"""
        Parse this calendar event request: "{user_input}"
        Current date and time: {current_date.strftime('%Y-%m-%d %H:%M')}

        Please parse the input and extract:
        1. Dates - Convert relative dates to absolute dates (YYYY-MM-DD)
           - "tomorrow" → "{(current_date + timedelta(days=1)).strftime('%Y-%m-%d')}"
           - "next week" → "{(current_date + timedelta(days=7)).strftime('%Y-%m-%d')}"
           - "in 3 days" → "{(current_date + timedelta(days=3)).strftime('%Y-%m-%d')}"

        2. Times - Convert to 24-hour format (HH:MM)
           - "2:45 PM" → "14:45"
           - "9:30 AM" → "09:30"
           - "3 PM" → "15:00"

        3. Duration - Extract or use default 30 minutes
           - "for 1 hour" → 60 minutes
           - "45 min meeting" → 45 minutes
           - No duration specified → 30 minutes

        4. Attendees - Extract email addresses
           - "with john@example.com" → ["john@example.com"]
           - Multiple attendees should be in an array

        Return a JSON object with this exact structure:
        {{
            "date": "YYYY-MM-DD",
            "start_time": "HH:MM",
            "duration_minutes": integer,
            "description": "Clear event description",
            "attendees": ["email1@example.com", "email2@example.com"]
        }}

        Example inputs and outputs:
        1. Input: "Doctor's follow-up in 3 days at 2:45 PM"
           Output: {{
               "date": "{(current_date + timedelta(days=3)).strftime('%Y-%m-%d')}",
               "start_time": "14:45",
               "duration_minutes": 30,
               "description": "Doctor's follow-up",
               "attendees": []
           }}

        2. Input: "Team meeting tomorrow at 10am with alice@company.com and bob@company.com for 1 hour"
           Output: {{
               "date": "{(current_date + timedelta(days=1)).strftime('%Y-%m-%d')}",
               "start_time": "10:00",
               "duration_minutes": 60,
               "description": "Team meeting",
               "attendees": ["alice@company.com", "bob@company.com"]
           }}
        """

        try:
            # Generate response from Gemini AI
            response = self.model.generate_content(prompt)
            
            # Log the raw response for debugging
            print("Raw response:", response.text)
            
            # Clean up the response text
            json_str = response.text.strip()
            
            # Handle markdown code block formatting if present
            if json_str.startswith("```json"):
                json_str = json_str.replace("```json", "").replace("```", "")
            elif json_str.startswith("```"):
                json_str = json_str.replace("```", "")
            
            # Extract JSON object
            json_str = json_str[json_str.find("{"):json_str.rfind("}")+1].strip()
            
            # Parse JSON and validate required fields
            parsed_data = json.loads(json_str)
            required_fields = ['date', 'start_time', 'duration_minutes', 'description', 'attendees']
            
            if not all(field in parsed_data for field in required_fields):
                missing_fields = [field for field in required_fields if field not in parsed_data]
                st.warning(f"Missing required fields: {', '.join(missing_fields)}")
                return None
                
            return parsed_data

        except json.JSONDecodeError as e:
            st.error(f"Failed to parse AI response as JSON: {str(e)}")
            print(f"JSON parsing error: {str(e)}")
            print(f"Problematic JSON string: {json_str}")
            return None
            
        except Exception as e:
            st.error(f"Error processing event details: {str(e)}")
            print(f"General error: {str(e)}")
            return None

    def _validate_date_format(self, date_str: str) -> bool:
        """Helper method to validate date format (YYYY-MM-DD)"""
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False

# Test usage (only runs when script is executed directly)
if __name__ == "__main__":
    parser = EventParser()
    test_inputs = [
        "Schedule a meeting with john@example.com tomorrow at 2pm for 30 minutes",
        "Doctor's appointment next Monday at 3:45 PM",
        "Team sync in 2 days at 10:30 AM for 45 minutes with team@company.com"
    ]
    
    for test_input in test_inputs:
        print(f"\nTesting input: {test_input}")
        result = parser.parse_request(test_input)
        print(f"Result: {json.dumps(result, indent=2)}")