from datetime import datetime


class Timer:
    def __init__(self):
        self.init_time = datetime.today()

    def update_timer(self):
        self.init_time = datetime.today()

    @staticmethod
    def get_time():
        time = datetime.today()
        sec = datetime.timestamp(time)
        return int(sec), time.microsecond

    def get_time_delta(self):
        return (datetime.today() - self.init_time).total_seconds()
