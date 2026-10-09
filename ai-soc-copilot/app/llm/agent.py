import ollama

def analyze_alert(alert_data: dict) -> str:
    """
    Takes an alert dictionary and returns an AI-generated triage report using local Ollama.
    """
    rule_name = alert_data.get("rule_name", "Unknown Rule")
    severity = alert_data.get("severity", "Unknown")
    summary = alert_data.get("summary", "No summary provided")
    raw_log = alert_data.get("raw_log", "No raw log available")

    system_prompt = """
    You are an expert Tier 1 SOC (Security Operations Center) Analyst. 
    Your job is to triage security alerts quickly and accurately.
    Analyze the provided alert and format your response exactly like this:
    
    **Summary:** A 1-2 sentence explanation of what happened in plain English.
    **Impact:** What could happen if this is a true positive?
    **False Positive Likelihood:** (High/Medium/Low) and why.
    **Recommended Actions:** 3 bullet points on how the analyst should investigate or remediate.
    """

    user_prompt = f"""
    Please triage the following security alert:
    
    Rule Triggered: {rule_name}
    Severity Level: {severity}
    System Summary: {summary}
    Raw Log Data: {raw_log}
    """

    try:
        response = ollama.chat(model='llama3', messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_prompt},
        ])
        return response['message']['content']
    except Exception as e:
        return f"Error communicating with local AI: {str(e)}"