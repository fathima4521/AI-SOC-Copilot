import psycopg2


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DB_CONFIG = {
    "host": "localhost",
    "database": "ai_soc_copilot",
    "user": "postgres",
    "password": "Fath@1234",
    "port": "5432"
}


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    return psycopg2.connect(**DB_CONFIG)


# =========================================================
# INVESTIGATE USER
# =========================================================

def investigate_user(username):

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
            WHERE LOWER(username) = LOWER(%s)
            ORDER BY id ASC
        """, (username,))

        rows = cursor.fetchall()

        events = []

        for row in rows:

            events.append({
                "alert_id": row[0],
                "severity": row[1],
                "message": row[2],
                "source_ip": row[3],
                "username": row[4],
                "status": row[5]
            })

        return {
            "username": username,
            "total_events": len(events),
            "events": events
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# INVESTIGATE IP
# =========================================================

def investigate_ip(source_ip):

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
            WHERE source = %s
            ORDER BY id ASC
        """, (source_ip,))

        rows = cursor.fetchall()

        events = []

        for row in rows:

            events.append({
                "alert_id": row[0],
                "severity": row[1],
                "message": row[2],
                "source_ip": row[3],
                "username": row[4],
                "status": row[5]
            })

        return {
            "source_ip": source_ip,
            "total_events": len(events),
            "events": events
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# INVESTIGATE SUSPICIOUS ACTIVITY
# =========================================================

def investigate_suspicious_activity():

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT
                username,
                source,
                COUNT(*)
            FROM alerts
            WHERE LOWER(message) LIKE '%failed login%'
            GROUP BY username, source
            HAVING COUNT(*) >= 3
            ORDER BY COUNT(*) DESC
        """)

        rows = cursor.fetchall()

        findings = []

        for username, source_ip, count in rows:

            findings.append({
                "username": username,
                "source_ip": source_ip,
                "failed_login_attempts": count,
                "threat": "Possible brute-force attack",
                "severity": "HIGH"
            })

        return {
            "suspicious_activity_detected": len(findings) > 0,
            "findings": findings
        }

    finally:

        cursor.close()
        conn.close()


# =========================================================
# SECURITY TOOL RUNNER
# =========================================================

def run_security_tool(tool, value=None):

    if tool == "user":

        return investigate_user(value)

    elif tool == "ip":

        return investigate_ip(value)

    elif tool == "suspicious_activity":

        return investigate_suspicious_activity()

    else:

        return {
            "error": "Unknown security tool"
        }


# =========================================================
# CHOOSE SECURITY TOOL
# =========================================================

def choose_security_tool(question):

    question_lower = question.lower().strip()

    words = question_lower.split()


    # =====================================================
    # USER INVESTIGATION
    # =====================================================

    if "investigate" in question_lower:

        # Example:
        # "Investigate user admin"

        if "user" in words:

            index = words.index("user")

            if index + 1 < len(words):

                username = words[index + 1]

                return "user", username


        # Example:
        # "Investigate admin"

        if len(words) >= 2:

            username = words[-1]

            # Only reject generic words.
            # "admin" is now correctly accepted.

            if username not in [
                "user",
                "account",
                "the",
                "activity",
                "security"
            ]:

                return "user", username


    # =====================================================
    # IP INVESTIGATION
    # =====================================================

    if (
        "ip" in question_lower
        or "address" in question_lower
    ):

        for word in words:

            cleaned_word = word.strip(
                ".,!?;:"
            )

            if cleaned_word.count(".") == 3:

                parts = cleaned_word.split(".")

                if all(
                    part.isdigit()
                    for part in parts
                ):

                    return "ip", cleaned_word


    # =====================================================
    # SUSPICIOUS ACTIVITY
    # =====================================================

    if (
        "suspicious activity" in question_lower
        or "suspicious" in question_lower
        or "brute force" in question_lower
        or "brute-force" in question_lower
    ):

        return "suspicious_activity", None


    # =====================================================
    # NO TOOL
    # =====================================================

    return None, None


# =========================================================
# RUN COPILOT TOOL
# =========================================================

def run_copilot_tool(question):

    tool, value = choose_security_tool(question)

    if tool is None:

        return {
            "tool_used": None,
            "value": None,
            "result": None
        }

    result = run_security_tool(
        tool,
        value
    )

    return {
        "tool_used": tool,
        "value": value,
        "result": result
    }


# =========================================================
# SECURITY REASONING
# =========================================================

def analyze_investigation(result):

    if not result:

        return {
            "risk_level": "LOW",
            "threat_detected": False,
            "explanation":
                "No security evidence was found.",
            "recommended_actions": [
                "Continue monitoring security events."
            ]
        }


    events = result.get(
        "events",
        []
    )


    # =====================================================
    # NO EVENTS
    # =====================================================

    if not events:

        return {
            "risk_level": "LOW",
            "threat_detected": False,
            "explanation":
                "No security events were found.",
            "recommended_actions": [
                "Continue monitoring the account."
            ]
        }


    # =====================================================
    # BASIC COUNTS
    # =====================================================

    total_events = len(events)

    high_events = sum(
        1
        for event in events
        if event["severity"].upper() == "HIGH"
    )

    investigating_events = sum(
        1
        for event in events
        if event["status"].upper() == "INVESTIGATING"
    )

    resolved_events = sum(
        1
        for event in events
        if event["status"].upper() == "RESOLVED"
    )

    failed_login_events = sum(
        1
        for event in events
        if "failed login" in event["message"].lower()
    )

    source_ips = set(
        event["source_ip"]
        for event in events
        if event["source_ip"]
    )


    # =====================================================
    # RISK CALCULATION
    # =====================================================

    if (
        high_events >= 5
        or failed_login_events >= 5
        or len(source_ips) >= 3
    ):

        risk_level = "HIGH"

    elif (
        high_events >= 3
        or failed_login_events >= 3
        or investigating_events >= 2
    ):

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    threat_detected = (
        high_events > 0
        or failed_login_events > 0
    )


    # =====================================================
    # USER / IP NAME
    # =====================================================

    username = result.get(
        "username"
    )

    source_ip = result.get(
        "source_ip"
    )


    if username:

        target = f"account '{username}'"

    elif source_ip:

        target = f"IP address '{source_ip}'"

    else:

        target = "the investigated entity"


    # =====================================================
    # EXPLANATION
    # =====================================================

    explanation = (
        f"The {target} has {total_events} security events. "
        f"{high_events} are HIGH severity, "
        f"{investigating_events} are currently under investigation, "
        f"and {resolved_events} are resolved. "
        f"There are {failed_login_events} failed-login events "
        f"from {len(source_ips)} source IP address(es)."
    )


    # =====================================================
    # RECOMMENDED ACTIONS
    # =====================================================

    recommended_actions = []


    if failed_login_events > 0:

        recommended_actions.append(
            "Review authentication logs for the affected account."
        )


    if len(source_ips) >= 2:

        recommended_actions.append(
            "Investigate the source IP addresses involved."
        )


    if investigating_events > 0:

        recommended_actions.append(
            "Continue investigating unresolved security alerts."
        )


    if high_events > 0:

        recommended_actions.append(
            "Prioritize the HIGH severity alerts."
        )


    if not recommended_actions:

        recommended_actions.append(
            "Continue monitoring the security activity."
        )


    return {
        "risk_level": risk_level,
        "threat_detected": threat_detected,
        "explanation": explanation,
        "recommended_actions": recommended_actions
    }