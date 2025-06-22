def triage_alert(alert):
    """
    ทำการจัดลำดับความสำคัญของ alert โดยพิจารณาจาก severity, category หรือ field อื่น ๆ
    """
    try:
        severity = alert.get("severity", "").lower()
        category = alert.get("type", "").lower()
        tags = alert.get("tags", [])

        if not severity:
            return "❔ Unknown severity"

        if "critical" in severity or severity in ["high", "sev-high"]:
            return "🚨 High Severity"
        elif "medium" in severity or severity in ["moderate", "sev-med"]:
            return "⚠️ Medium Severity"
        elif "low" in severity or severity in ["info", "sev-low"]:
            return "ℹ️ Low Severity"
        else:
            return f"❔ Unclassified - severity: {severity}"

    except Exception as e:
        return f"❌ Error during triage: {str(e)}"
