import re


class LogParser:

    def __init__(self):

        self.pattern = re.compile(

            r"^(?P<month>\w+)\s+"
            r"(?P<day>\d+)\s+"
            r"(?P<time>\d+:\d+:\d+)\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>\w+)(?:\[\d+\])?:\s+"
            r"(?P<message>.*)$"

        )

    def parse_line(self, line):

        match = self.pattern.match(line)

        if match:

            return match.groupdict()

        return None
