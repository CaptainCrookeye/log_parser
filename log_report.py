import io
import datetime
import numpy as np
import matplotlib.pyplot as plt
from discord import File, SyncWebhook

# used to generate monthly report

LOG_REPORT_FILE = "/path/to/log_stats.txt"     # set in parser.py
WEBHOOK_URL = "<YOUR WEBHOOK>"


def load_data() -> list[str]:
    data: list[str] = []
    with open(LOG_REPORT_FILE, "r", encoding="utf-8") as f:
        data = f.readlines()
    return data


def get_prev_month() -> str:
    m = datetime.date.today().month
    months = [
        "JANUARY",
        "FEBRUARY",
        "MARCH",
        "APRIL",
        "MAY",
        "JUNE",
        "JULY",
        "AUGUST",
        "SEPTEMBER",
        "OCTOBER",
        "NOVEMBER",
        "DECEMBER",
    ]
    return months[m - 2]


def clear_data_file():
    with open(LOG_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("")


def filter_attack_types(data: list[str]) -> dict[str, int]:
    filtered: dict[str, int] = {}

    for line in data:
        attack_types = line.split("|")[1]
        attack_types_split = attack_types.split(";")

        for i in range(len(attack_types_split) - 1):
            if attack_types_split[i] not in filtered:
                filtered[attack_types_split[i]] = 0
            filtered[attack_types_split[i]] += 1

    return filtered


def graph_attack_types(data: dict[str, int]):
    labels: list[str] = []
    values: list[int] = []

    for key in data:
        labels.append(f"{str(data[key])}: {key}")
        values.append(data[key])
    y = np.array(values)

    fig, ax = plt.subplots()
    ax.pie(values, labels=labels)
    ax.set_title("Detected alert types")
    return fig


def filter_dates(data: list[str]) -> list[int]:
    filtered: list[int] = []

    for line in data:
        date = line.split("|")[0][0:2]
        filtered.append(int(date))

    return filtered


def graph_dates(data: list[int]):
    x = np.array(data)
    fig, ax = plt.subplots()
    ax.hist(x, bins=np.arange(1, 33) - 0.5, edgecolor="white")
    ax.set_title("Alerts per day")
    ax.set_xticks(range(1, 32), labels=range(1, 32), rotation=90)
    ax.set_xlabel("Day of month")
    ax.set_ylabel("Count")
    return fig


def filter_hours(data: list[str]) -> list[int]:
    filtered: list[str] = []

    for line in data:
        hour = line.split("|")[0][12:14]
        filtered.append(int(hour))

    return filtered


def graph_hours(data: list[int]):
    x = np.array(data)
    fig, ax = plt.subplots()
    ax.hist(x, bins=np.arange(0, 25) - 0.5, edgecolor="white")
    ax.set_xticks(range(0, 24), labels=range(0, 24), rotation=90)
    ax.set_title("Alerts per hour of day")
    ax.set_xlabel("Hour of day")
    ax.set_ylabel("Count")
    return fig


def is_leap_year() -> int:
    y = datetime.date.today().year
    if y % 4 == 0 and (y % 100 != 0 or y % 400 == 0):
        return 1
    return 0


def alerts_average(data: list[int]) -> int:
    last_month: int = datetime.date.today().month - 1
    if last_month == 0:
        last_month = 12

    days_in_month: int = 31
    thirty_day_months: set[int] = {4, 6, 9, 11}
    if last_month == 2:
        days_in_month = 28 + is_leap_year()
    elif last_month in thirty_day_months:
        days_in_month = 30

    return len(data) // days_in_month


def fig_to_file(fig, filename: str) -> File:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    buf.seek(0)
    plt.close(fig)
    return File(buf, filename=filename)


def main():
    webhook = SyncWebhook.from_url(WEBHOOK_URL)
    webhook_message = f"# REPORT FOR MONTH {get_prev_month()}\n"
    data = load_data()

    if len(data) == 0:
        webhook_message += "Nothing to report"
        webhook.send(content=webhook_message)
        return

    data_attack_types = filter_attack_types(data)
    data_dates = filter_dates(data)
    data_hours = filter_hours(data)

    webhook_message += f"Average number of alerts per day: {alerts_average(data_dates)}"
    webhook.send(content=webhook_message,
                 files=[
                     fig_to_file(graph_dates(data_dates), f"{datetime.date.today()}_dates.png"),
                     fig_to_file(graph_hours(data_hours), f"{datetime.date.today()}_hours.png"),
                     fig_to_file(graph_attack_types(data_attack_types), f"{datetime.date.today()}_attack_types.png"),
                 ])

    clear_data_file()


if __name__ == "__main__":
    main()
