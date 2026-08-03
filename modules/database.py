import sqlite3


class Database:

    def __init__(self):

        self.conn = sqlite3.connect(
            "database/events.db",
            check_same_thread=False
        )

        self.cursor = self.conn.cursor()

    def create_tables(self):

        self.cursor.execute("""

        CREATE TABLE IF NOT EXISTS events(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,
            hostname TEXT,
            service TEXT,
            category TEXT,
            event TEXT,
            severity TEXT,
            user TEXT,
            ip TEXT,
            message TEXT UNIQUE

        )

        """)

        self.conn.commit()

    def insert_event(self, event):

        try:

            self.cursor.execute("""

            INSERT INTO events
            (
                timestamp,
                hostname,
                service,
                category,
                event,
                severity,
                user,
                ip,
                message
            )

            VALUES(?,?,?,?,?,?,?,?,?)

            """, (

                event["timestamp"],
                event["hostname"],
                event["service"],
                event["category"],
                event["event"],
                event["severity"],
                event["user"],
                event["ip"],
                event["message"]

            ))

            self.conn.commit()

        except sqlite3.IntegrityError:
            pass

    def get_events(self):

        self.cursor.execute("""

        SELECT *
        FROM events
        ORDER BY id DESC

        """)

        return self.cursor.fetchall()
