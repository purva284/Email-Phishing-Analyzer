
from datetime import datetime
import re


def analyze_email():
    print("\n===== Phishing Email Analyzer =====")

    sender = input("Enter sender email address: ").strip()
    email_text = input("Paste the email text to analyze: ").strip()

    if not sender or not email_text:
        print("\nError: Sender email and email text cannot be empty.")
        return

    risk_score = 0
    warnings = []

    # Check the sender email address
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
        risk_score += 20
        warnings.append("Sender email address may be invalid")
    elif sender.lower().endswith(
        ("@gmail.com", "@yahoo.com", "@outlook.com")
    ):
        warnings.append(
            "Sender uses a public email provider. "
            "This is not proof of phishing; verify the sender."
        )

    # Suspicious phrases and their risk points
    suspicious_phrases = {
        "urgent": 10,
        "verify your account": 15,
        "password": 10,
        "account suspended": 15,
        "click here": 10,
        "claim your prize": 15,
        "one-time password": 15,
        "otp": 10,
        "bank details": 15,
        "immediate payment": 15,
        "limited time": 10,
        "confirm your identity": 10
    }

    email_lower = email_text.lower()

    # Check each suspicious phrase only once
    for phrase, points in suspicious_phrases.items():
        if phrase == "otp":
            found = re.search(r"\botp\b", email_lower)
        else:
            found = phrase in email_lower

        if found:
            risk_score += points
            warnings.append(
                f"Suspicious phrase found: {phrase} (+{points})"
            )

    # Detect HTTP and HTTPS links
    links = re.findall(
        r"https?://[^\s<>\"']+",
        email_text,
        flags=re.IGNORECASE
    )

    if links:
        risk_score += 20
        warnings.append(
            f"Email contains {len(links)} web link(s). "
            "Check each link before opening it."
        )

    # Check excessive exclamation marks
    if email_text.count("!") >= 2:
        risk_score += 5
        warnings.append("Email uses multiple exclamation marks (+5)")

    # Keep the score between 0 and 100
    risk_score = min(risk_score, 100)

    # Determine the risk level
    if risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Safety recommendations
    if risk_level == "HIGH":
        advice = (
            "Do not click links or share passwords, OTPs, "
            "or banking details. Verify the message independently."
        )
    elif risk_level == "MEDIUM":
        advice = (
            "Check the sender carefully. Verify links and requests "
            "through an official website or trusted contact."
        )
    else:
        advice = (
            "No major warning signs were detected by these rules. "
            "This does not guarantee that the email is safe."
        )

    # Display results
    print("\n===== Analysis Results =====")
    print("Sender:", sender)
    print("Risk Score:", risk_score, "/ 100")
    print("Risk Level:", risk_level)

    print("\nWarning Signs:")
    if warnings:
        for warning in warnings:
            print("-", warning)
    else:
        print("No warning signs detected by these rules.")

    print("\nSafety Recommendations:")
    print(advice)

    # Generate a detailed report
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_content = f"""
PHISHING EMAIL ANALYSIS REPORT
Date and Time: {current_time}

Sender: {sender}

Email Text:
{email_text}

Risk Score: {risk_score}/100
Risk Level: {risk_level}

Warning Signs:
"""

    if warnings:
        for warning in warnings:
            report_content += "- " + warning + "\n"
    else:
        report_content += "No warning signs detected by these rules.\n"

    report_content += "\nSafety Recommendations:\n" + advice + "\n"
    report_content += (
        "\nLIMITATIONS:\n"
        "This is a rule-based analyzer, not an AI detection system.\n"
        "The score is an indication, not proof of phishing.\n"
        "Legitimate emails can contain suspicious phrases or links.\n"
        "A low score does not guarantee that an email is safe.\n"
    )

    # Save the report without deleting earlier reports
    with open(
        "phishing_report.txt", "a", encoding="utf-8"
    ) as report_file:
        report_file.write(report_content + "\n" + "-" * 50 + "\n")

    print("\nDetailed report saved to phishing_report.txt")


analyze_email()
