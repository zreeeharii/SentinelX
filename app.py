from flask import Flask, jsonify, render_template, request, Response

from modules.parser import LogParser
from modules.detector import ThreatDetector
from modules.database import Database


app = Flask(__name__)


parser = LogParser()
detector = ThreatDetector()
db = Database()


db.create_tables()



def process_logs():

    with open("/var/log/auth.log", "r") as file:

        lines = file.readlines()


    for line in lines:

        parsed = parser.parse_line(line)


        if not parsed:
            continue


        event = detector.detect(parsed)


        if event:

            db.insert_event(event)




@app.route("/")
def dashboard():


    process_logs()


    search = request.args.get("search", "")


    if search:

        events = db.search_events(search)

    else:

        events = db.get_events()



    total = len(events)


    high = 0
    auth = 0
    privilege = 0


    for event in events:

        if event[6] == "HIGH":

            high += 1


        if event[4] == "Authentication":

            auth += 1


        if event[4] == "Privilege Escalation":

            privilege += 1

    severity_data = {

        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0

    }


    category_data = {}


    for event in events:

        severity = event[6]
        category = event[4]


        if severity in severity_data:

            severity_data[severity] += 1


        if category:

            if category not in category_data:

                category_data[category] = 0


            category_data[category] += 1

    return render_template(

        "dashboard.html",

        events=events,

        total=total,

        high=high,

        auth=auth,

        privilege=privilege,

        severity_data=severity_data,

        category_data=category_data

    )




@app.route("/api/events")
def api_events():


    events = db.get_events()


    data = []


    for event in events:


        data.append({

            "id": event[0],
            "timestamp": event[1],
            "hostname": event[2],
            "service": event[3],
            "category": event[4],
            "event": event[5],
            "severity": event[6],
            "user": event[7],
            "ip": event[8]

        })


    return jsonify(data)

@app.route("/export")
def export_csv():

    import csv
    import io


    events = db.get_events()


    output = io.StringIO()


    writer = csv.writer(output)


    writer.writerow([

        "ID",
        "Timestamp",
        "Hostname",
        "Service",
        "Category",
        "Event",
        "Severity",
        "User",
        "IP"

    ])


    for event in events:

        writer.writerow([

            event[0],
            event[1],
            event[2],
            event[3],
            event[4],
            event[5],
            event[6],
            event[7],
            event[8]

        ])


    return Response(

        output.getvalue(),

        mimetype="text/csv",

        headers={

            "Content-Disposition":
            "attachment; filename=sentinelx_events.csv"

        }

    )


if __name__ == "__main__":

    app.run(debug=True)