import google.generativeai as genai
import json
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import re


load_dotenv()

class EventParser:
   def __init__(self):
       genai.configure(api_key=os.getenv('GOOGLE_AI_KEY'))
       self.model = genai.GenerativeModel('gemini-pro')
   
   def parse_request(self, user_input: str):
    current_date = datetime.now().astimezone()
    
    prompt = f"""
    Parse this appointment/reminder: "{user_input}"
    Current date and time: {current_date.strftime('%Y-%m-%d %H:%M')}
    
    Please understand and convert:
    - Relative dates like "in 3 days" into actual dates
    - Time expressions like "2:45 PM" into 24-hour format
    - Extract the main task or appointment description
    
    Return a JSON that includes:
    {{
        "date": "YYYY-MM-DD",
        "start_time": "HH:MM",
        "duration_minutes": 30,
        "description": "The actual task or appointment description",
        "attendees": []
    }}
    
    For example:
    Input: "Doctor's follow-up in 3 days at 2:45 PM"
    Should return:
    {{
        "date": "{(current_date + timedelta(days=3)).strftime('%Y-%m-%d')}",
        "start_time": "14:45",
        "duration_minutes": 30,
        "description": "Doctor's follow-up",
        "attendees": []
    }}
    """
    
    try:
        response = self.model.generate_content(prompt)
        print("Raw response:", response.text)
        json_str = response.text.strip()
        if json_str.startswith("```"):
            json_str = json_str[json_str.find("{"):json_str.rfind("}")+1]
        return json.loads(json_str.strip())
    except Exception as e:
        print(f"Error parsing response: {e}")
        return None

# Test usage
if __name__ == "__main__":
   parser = EventParser()
   result = parser.parse_request("Schedule a meeting with john@example.com tomorrow at 2pm for 30 minutes")
   print(result)