from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import psycopg2
import uvicorn
import os
from dotenv import load_dotenv
import ollama

from security_context import SECURITY_CONTEXT
from soc_tools import (
    run_security_tool,
    run_copilot_tool,
    analyze_investigation
)


# =========================================================
# ENVIRONMENT / OLLAMA
# =========================================================

load_dotenv()

client = ollama.Client(
    host="http://localhost:11434"
)

OLLAMA_MODEL = "llama3.2:3b"

print("Ollama client loaded successfully.")
print(f"Ollama model: {OLLAMA_MODEL}")


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(title="AI SOC Copilot")


# =========================================================
# DATABASE CONFIGURATION
# =========================================================
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "ai_soc_copilot"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD"),
    "port": os.getenv("DB_PORT", "5432"),
    "connect_timeout": 5
}


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    try:

        return psycopg2.connect(**DB_CONFIG)

    except psycopg2.Error as e:

        raise HTTPException(
            status_code=500,
            detail=f"Database connection failed: {str(e)}"
        )


# =========================================================
# OLLAMA AI FUNCTION
# =========================================================

def ask_ollama(prompt: str):

    try:

        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        return response["message"]["content"]

    except Exception as e:

        print(f"Ollama error: {e}")

        raise HTTPException(
            status_code=500,
            detail=f"Ollama error: {str(e)}"
        )


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    conn = None
    cursor = None

    try:

        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                severity VARCHAR(20),
                message TEXT,
                source VARCHAR(100),
                username VARCHAR(100),
                status VARCHAR(20) DEFAULT 'NEW'
            )
        """)

        cursor.execute("""
            ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'NEW'
        """)

        cursor.execute("""
            UPDATE alerts
            SET status = 'NEW'
            WHERE status IS NULL
        """)

        conn.commit()

        print("Database connected successfully.")
        print("Alerts table is ready.")

    except psycopg2.Error as e:

        print("WARNING: Database connection failed.")
        print(f"Database error: {e}")

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# STARTUP
# =========================================================

@app.on_event("startup")
def startup_event():

    print("Starting AI SOC Copilot...")

    initialize_database()

    print("AI SOC Copilot startup completed.")


# =========================================================
# STATIC FILES / DASHBOARD
# =========================================================

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


@app.get("/dashboard")
def dashboard():

    return FileResponse("static/index.html")


@app.get("/")
def home():

    return {
        "message": "AI SOC Copilot is running!"
    }


# =========================================================
# MODELS
# =========================================================

class Alert(BaseModel):

    severity: str
    message: str
    source: str
    username: str


class AlertStatus(BaseModel):

    status: str


class CopilotQuestion(BaseModel):

    question: str


# =========================================================
# CREATE ALERT
# =========================================================

@app.post("/alerts")
def create_alert(alert: Alert):

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO alerts
            (severity, message, source, username, status)
            VALUES (%s, %s, %s, %s, 'NEW')
            RETURNING id, severity, message, source, username, status
            """,
            (
                alert.severity.upper(),
                alert.message,
                alert.source,
                alert.username
            )
        )

        new_alert = cursor.fetchone()

        conn.commit()

        return {
            "message": "Security alert saved successfully",
            "alert": {
                "id": new_alert[0],
                "severity": new_alert[1],
                "message": new_alert[2],
                "source": new_alert[3],
                "username": new_alert[4],
                "status": new_alert[5]
            }
        }

    except psycopg2.Error as e:

        conn.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Database error: {str(e)}"
        )

    finally:

        cursor.close()
        conn.close()


# =========================================================
# GET ALL ALERTS
# =========================================================

@app.get("/alerts")
def get_alerts():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                severity,
                message,
                source,
                username,
                status
            FROM alerts
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

        alerts = []

        for row in rows:

            alerts.append({
                "id": row[0],
                "severity": row[1],
                "message": row[2],
                "source": row[3],
                "username": row[4],
                "status": row[5] or "NEW"
            })

        return {
            "alerts": alerts
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# UPDATE ALERT STATUS
# =========================================================

@app.put("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    data: AlertStatus
):

    allowed_statuses = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED"
    ]

    status = data.status.upper()

    if status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid status. Use NEW, INVESTIGATING, or RESOLVED."
        )

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            UPDATE alerts
            SET status = %s
            WHERE id = %s
            RETURNING id, severity, message, source, username, status
            """,
            (status, alert_id)
        )

        updated_alert = cursor.fetchone()

        if not updated_alert:

            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        conn.commit()

        return {
            "message": "Alert status updated successfully",
            "alert": {
                "id": updated_alert[0],
                "severity": updated_alert[1],
                "message": updated_alert[2],
                "source": updated_alert[3],
                "username": updated_alert[4],
                "status": updated_alert[5]
            }
        }

    except HTTPException:

        conn.rollback()
        raise

    except psycopg2.Error as e:

        conn.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Database error: {str(e)}"
        )

    finally:

        cursor.close()
        conn.close()


# =========================================================
# DETECT SUSPICIOUS ACTIVITY
# =========================================================

@app.get("/detect")
def detect_suspicious_activity():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                username,
                COUNT(*),
                MAX(source)
            FROM alerts
            WHERE LOWER(message) LIKE '%failed login%'
            GROUP BY username
            HAVING COUNT(*) >= 3
        """)

        results = cursor.fetchall()

        findings = []

        for username, count, source_ip in results:

            findings.append({
                "threat": "Possible brute-force login attack",
                "severity": "HIGH",
                "username": username,
                "failed_attempts": count,
                "source_ip": source_ip,
                "recommended_action":
                    "Investigate the source IP and review authentication logs."
            })

        return {
            "suspicious_activity": len(findings) > 0,
            "findings": findings
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# SECURITY ANALYSIS
# =========================================================

@app.get("/analyze")
def analyze_security_activity():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                username,
                COUNT(*),
                MAX(source)
            FROM alerts
            WHERE LOWER(message) LIKE '%failed login%'
            GROUP BY username
            HAVING COUNT(*) >= 3
        """)

        suspicious_users = cursor.fetchall()

        findings = []

        for username, count, source_ip in suspicious_users:

            if count >= 10:
                risk_level = "CRITICAL"

            elif count >= 5:
                risk_level = "HIGH"

            else:
                risk_level = "MEDIUM"

            findings.append({
                "threat": "Possible brute-force login attack",
                "risk_level": risk_level,
                "username": username,
                "failed_attempts": count,
                "source_ip": source_ip,
                "explanation":
                    f"The account '{username}' experienced "
                    f"{count} failed login attempts. "
                    "Repeated authentication failures may indicate "
                    "a brute-force attack.",
                "recommended_action":
                    "Investigate the source IP, review authentication "
                    "logs, and check whether the account was accessed."
            })

        return {
            "analysis_status":
                "Suspicious activity detected"
                if findings
                else "No suspicious activity detected",
            "findings": findings
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# SEVERITY ANALYSIS
# =========================================================

@app.get("/severity-analysis")
def severity_analysis():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM alerts
            GROUP BY severity
            ORDER BY COUNT(*) DESC
        """)

        results = cursor.fetchall()

        analysis = []

        for severity, count in results:

            severity_upper = severity.upper()

            if severity_upper == "HIGH":

                risk = "High priority"
                action = "Investigate these alerts immediately."

            elif severity_upper == "MEDIUM":

                risk = "Moderate priority"
                action = "Review these alerts."

            else:

                risk = "Low priority"
                action = "Continue monitoring."

            analysis.append({
                "severity": severity_upper,
                "alert_count": count,
                "risk": risk,
                "recommended_action": action
            })

        return {
            "severity_analysis": analysis
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# PRIORITY ANALYSIS
# =========================================================

@app.get("/priority")
def priority_analysis():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                severity,
                message,
                source,
                username
            FROM alerts
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

        results = []

        for alert_id, severity, message, source, username in rows:

            severity_upper = severity.upper()

            if severity_upper == "HIGH":

                priority = "IMMEDIATE"
                action = "Investigate immediately."

            elif severity_upper == "MEDIUM":

                priority = "HIGH"
                action = "Investigate soon."

            else:

                priority = "LOW"
                action = "Monitor the activity."

            results.append({
                "alert_id": alert_id,
                "severity": severity_upper,
                "priority": priority,
                "message": message,
                "source_ip": source,
                "username": username,
                "recommended_action": action
            })

        return {
            "priority_analysis": results
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# SECURITY TIMELINE
# =========================================================

@app.get("/timeline/{username}")
def security_timeline(username: str):

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                severity,
                message,
                source,
                username
            FROM alerts
            WHERE LOWER(username) = LOWER(%s)
            ORDER BY id ASC
        """, (username,))

        rows = cursor.fetchall()

        timeline = []

        for number, row in enumerate(rows, start=1):

            timeline.append({
                "step": number,
                "alert_id": row[0],
                "severity": row[1].upper(),
                "event": row[2],
                "source_ip": row[3],
                "username": row[4]
            })

        return {
            "username": username,
            "total_events": len(timeline),
            "timeline": timeline
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# IP ANALYSIS
# =========================================================

@app.get("/ip-analysis")
def ip_analysis():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                source,
                COUNT(*)
            FROM alerts
            WHERE LOWER(message) LIKE '%failed login%'
            GROUP BY source
            ORDER BY COUNT(*) DESC
        """)

        rows = cursor.fetchall()

        analysis = []

        for source_ip, count in rows:

            if count >= 10:

                risk = "CRITICAL"

            elif count >= 5:

                risk = "HIGH"

            elif count >= 3:

                risk = "MEDIUM"

            else:

                risk = "LOW"

            analysis.append({
                "source_ip": source_ip,
                "failed_login_attempts": count,
                "risk_level": risk
            })

        return {
            "status": "IP analysis completed",
            "ip_analysis": analysis
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# SECURITY TOOL ENDPOINT
# =========================================================

@app.post("/security-tool")
def security_tool(
    tool: str,
    value: str | None = None
):

    allowed_tools = [
        "user",
        "ip",
        "suspicious_activity"
    ]

    if tool not in allowed_tools:

        raise HTTPException(
            status_code=400,
            detail=(
                "Unknown tool. Use: "
                "user, ip, or suspicious_activity."
            )
        )

    result = run_security_tool(
        tool,
        value
    )

    return {
        "tool": tool,
        "value": value,
        "result": result
    }


# =========================================================
# AI ANALYSIS ENDPOINT
# =========================================================

@app.post("/ai-analysis")
def ai_analysis(data: CopilotQuestion):

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                severity,
                message,
                source,
                username,
                status
            FROM alerts
            ORDER BY id DESC
        """)

        alerts = cursor.fetchall()

    finally:

        cursor.close()
        conn.close()

    if not alerts:

        return {
            "analysis": {
                "threat_detected": False,
                "risk_level": "LOW",
                "explanation":
                    "There are currently no security alerts.",
                "recommended_actions": [
                    "Continue monitoring security events."
                ]
            }
        }

    security_events = []

    for alert in alerts:

        security_events.append({
            "id": alert[0],
            "severity": alert[1],
            "message": alert[2],
            "source_ip": alert[3],
            "username": alert[4],
            "status": alert[5]
        })

    prompt = f"""
{SECURITY_CONTEXT}

You are an AI Security Operations Center analyst.

Analyze the following security alerts.

User question:
{data.question}

Security alerts:
{security_events}

Use only the provided evidence.

Explain:

1. Threat detected
2. Risk level
3. Important evidence
4. Explanation
5. Recommended actions

Do not invent facts.
"""

    analysis = ask_ollama(prompt)

    return {
        "analysis": analysis
    }


# =========================================================
# AI SOC COPILOT
# =========================================================

@app.post("/copilot")
def soc_copilot(data: CopilotQuestion):

    question = data.question.strip()

    if not question:

        raise HTTPException(
            status_code=400,
            detail="Question cannot be empty."
        )

    # =====================================================
    # STEP 1 — SELECT SECURITY TOOL
    # =====================================================

    tool_result = run_copilot_tool(question)

    # =====================================================
    # STEP 2 — SECURITY TOOL FOUND
    # =====================================================

    if tool_result["tool_used"] is not None:

        evidence = tool_result["result"]

        # Local security reasoning
        reasoning = analyze_investigation(evidence)

        # =================================================
        # AI ANALYST RESPONSE
        # =================================================

        ai_prompt = f"""
You are an AI Security Operations Center (SOC) analyst.

Analyze the security investigation below.

User question:
{question}

Security evidence:
{evidence}

Local security analysis:
{reasoning}

Give a concise professional SOC analyst response.

Include:

1. Risk level
2. Whether suspicious activity was detected
3. Important evidence
4. What the activity could indicate
5. Recommended next actions

IMPORTANT RULES:

- Use ONLY the security evidence provided.
- Treat the evidence as the source of truth.
- Do not invent IP addresses, usernames, events, timestamps, login successes, or other facts.
- A failed login attempt proves only that a login attempt failed.
- A RESOLVED alert does NOT prove that an attacker successfully logged in.
- An INVESTIGATING alert does NOT prove that an attack was successful.
- Do not claim an account was compromised unless the evidence explicitly shows compromise.
- Do not claim unauthorized access unless the evidence explicitly supports it.
- Clearly separate FACTS from POSSIBLE INTERPRETATIONS.
- When suggesting a possible attack, use language such as "may indicate", "could indicate", or "is consistent with".
- If the evidence is insufficient to determine something, explicitly say that it cannot be determined from the available evidence.
- Base the risk level primarily on the provided security evidence and local security analysis.
- Keep the response concise and professional, like a SOC analyst investigating an alert.
"""

        try:

            ai_answer = ask_ollama(ai_prompt)

        except Exception as e:

            print(f"Ollama error: {e}")

            ai_answer = (
                "AI analysis could not be completed. "
                "The local security analysis is available below."
            )

        # =================================================
        # RETURN COMPLETE RESULT
        # =================================================

        return {
            "answer": ai_answer,
            "question": question,
            "tool_used": tool_result["tool_used"],
            "value": tool_result.get("value"),
            "risk_level": reasoning["risk_level"],
            "threat_detected": reasoning["threat_detected"],
            "explanation": reasoning["explanation"],
            "recommended_actions": reasoning["recommended_actions"],
            "evidence": evidence
        }

    # =====================================================
    # NO SECURITY TOOL
    # =====================================================

    return {
        "answer": (
            "I could not identify a specific security "
            "investigation from the question. "
            "Try asking something like "
            "'Investigate admin' or "
            "'Investigate IP 192.168.1.40'."
        ),
        "question": question,
        "tool_used": None,
        "value": None,
        "risk_level": "UNKNOWN",
        "threat_detected": False,
        "evidence": None
    }


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )