from flask import Flask, jsonify, render_template

from modules.parser import LogParser
from modules.detector import ThreatDetector
from modules.database import Database

app = Flask(__name__)

parser = LogParser()
detector = ThreatDetector()
db = Database()

db.create_tables()


def process_logs():

    with open("/var/log/auth.log") as file:

        for line in file.readlines():

            parsed = parser.parse_line(line)

            if not parsed:
                continue

            event = detector.detect(parsed)

            if event:
                db.insert_event(event)


@app.route("/")
def dashboard():

    process_logs()

    events = db.get_events()

    total = len(events)

    high = sum(1 for e in events if e[6] == "HIGH")

    auth = sum(1 for e in events if e[4] == "Authentication")

    privilege = sum(1 for e in events if e[4] == "Privilege Escalation")

    return render_template(
        "dashboard.html",
        events=events,
        total=total,
        high=high,
        auth=auth,
        privilege=privilege
    )


@app.route("/api/events")
def api():

    process_logs()

    events = db.get_events()

    data = []

    for row in events:

        data.append({

            "id": row[0],
            "timestamp": row[1],
            "hostname": row[2],
            "service": row[3],
            "category": row[4],
            "event": row[5],
            "severity": row[6],
            "user": row[7],
            "ip": row[8]

        })

    return jsonify(data)


if __name__ == "__main__":
    app.run(debug=True)
