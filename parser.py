import re
import sys
import time
import logging
import threading
from datetime import datetime
from discord import SyncWebhook

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


# file for storing information for generating reports
LOG_REPORT_FILE = "log_stats.txt"

# discord webhook url
WEBHOOK_URL = "<YOUR WEBHOOK>"

# line parsing patterns - change to fit given log format
LOG_REGEX_PATTERN = r'^([^\s]+)\s([^\s]+)\s([^\s]+)\s\[(....................).......\s"([^"]+)"\s(...)\s([^\s]+)\s"([^"]+)"\s"([^"]+)"\s([^\s]+)\s(.+)'
LOG_DATETIME_PATTERN = "%d/%b/%Y:%H:%M:%S"

# time in seconds in which login attempts are counted for bruteforce alert
LOGIN_TIME_WINDOW = 5

# how many login attempts in LOGIN_TIME_WINDOW from the same IP trigger bruteforce alert
LOGIN_MAX_ATTEMPTS = 10

# time in seconds in which logs are counted for spam alert
SPAM_TIME_WINDOW = 10

# max number of logs that can be received in SPAM_TIME_WINDOW before spam alert is triggered
SPAM_MAX_LOGS = 500

# time in seconds after which info in dictionaries will be cleared to prevent memory bloating
MEM_CLEAR_TIME = 86400

# time in seconds for which an alert from the same IP has to wait before sending webhook again
SEND_ALERT_COOLDOWN = 60


# class to hold values which need to be remembered but are cleared periodically
class MemValues:
    def __init__(self):
        self.login_attempts: dict[str, tuple[str, int]] = {}            # format - {ip: (last_attempt_timestamp, attempts_count)}
        self.alerts_sent: dict[str, set[tuple[datetime, str]]] = {}     # format - {ip: [(alert_datetime, attack_type)]}

    def clear_mem(self):
        self.login_attempts.clear()
        self.alerts_sent.clear()


# class to hold values that need to be shared between main() and bg_checks()
class BGChecksValues:
    def __init__(self):
        self.log_count: int = 0
        self.last_mem_clear: datetime = datetime.now()
        self.last_spam_alert: datetime = datetime.fromisoformat("2025-09-15T13:20:00")


# checks for too many login attempts from the same IP in short amount of time
def login_bruteforce_check(ip: str, mem: MemValues, attempt_timestamp: str, alerts: list[str]):
    if ip not in mem.login_attempts:
        mem.login_attempts[ip] = (attempt_timestamp, 1)
        return

    prev_timestamp, attempts = mem.login_attempts[ip]
    prev_time = datetime.strptime(prev_timestamp, LOG_DATETIME_PATTERN)
    cur_time = datetime.strptime(attempt_timestamp, LOG_DATETIME_PATTERN)
    delta = cur_time - prev_time

    if delta.total_seconds() <= LOGIN_TIME_WINDOW:
        attempts += 1
        if attempts >= LOGIN_MAX_ATTEMPTS:
            alerts.append("suspected bruteforce")
            attempts = 1
    else:
        attempts = 1

    mem.login_attempts[ip] = (attempt_timestamp, attempts)


# checks the path for SQL keywords and weird symbols indicating attempt of injection
def injection_check(path: str, alerts: list[str]):
    blacklist = [";", "|", "$", ":", "<", "and ", "or ", "drop "]
    path_lower = path.lower()
    for keyword in blacklist:
        if keyword in path_lower:
            alerts.append("suspected injection")
            return


# checks the path for common directory scan targets
def path_check(path: str, alerts: list[str]):
    blacklist = ["/admin", "/asset", "/api", "/dashboard", "/.env", "../", "..\\", "%00", "%2e%2e"]
    path_lower = path.lower()
    for keyword in blacklist:
        if keyword in path_lower:
            alerts.append("suspected path scan")
            return


# checks if the user agent is empty or a known tool
def user_agent_check(user_agent: str, alerts: list[str]):
    # optionally detect blank user agent, though this gets triggered a lot
    # if user_agent == "" or user_agent == "-":
    #     alerts.append("- suspicious user agent\n")
    #     return

    blacklist = ["nmap", "sqlmap", "nikto", "gobuster", "dirbuster", "hydra", "masscan", "zgrab"]
    user_agent_lower = user_agent.lower()
    for keyword in blacklist:
        if keyword in user_agent_lower:
            alerts.append("suspicious user agent")
            return


# sends discord webhook - run in a separate thread
def send_alert(alerts: str, log_line: str | None):
    message = f"# SERVER ALERT\n{alerts}"
    if log_line is not None:
        message += f"\nfull log:\n`{log_line}`"
    webhook = SyncWebhook.from_url(WEBHOOK_URL)
    webhook.send(content=message)


# processes one line from stdin
def process_line(line: str, mem: MemValues):
    line_split = re.search(pattern=LOG_REGEX_PATTERN, string=line)
    if line_split is None:
        return

    # assign line groups to values - change to fit regex pattern
    client_ip = line_split.group(1)
    timestamp = line_split.group(4)
    request = line_split.group(5).split()
    if len(request) != 3:
        request = ["", "", ""]
    req_method = request[0]
    req_path = request[1]
    status = line_split.group(6)
    client_browser = line_split.group(9)

    # currently unused log data but available for future reference
    # client_identify = split.group(2)
    # client_authenticated = split.group(3)
    # bytes_sent = split.group(7)
    # http_referer = split.group(8)
    # time_to_process = line_split.group(10)
    # time_backend = split.group(11)
    # req_http_ver = request[2]

    # list to store critical alerts
    alerts: list[str] = []

    # perform all checks
    injection_check(path=req_path, alerts=alerts)
    path_check(path=req_path, alerts=alerts)
    if req_method == "POST" and req_path == "/login":
        login_bruteforce_check(ip=client_ip, mem=mem, attempt_timestamp=timestamp, alerts=alerts)
    user_agent_check(user_agent=client_browser, alerts=alerts)
    # alert for 5XX status code
    if status[0] == "5":
        alerts.append("internal server error")

    # send alert webhook in a non-blocking way if the IP is not on cooldown
    if len(alerts) > 0:
        alerts_msg: str = ""
        alerts_single_line: str = ""
        for reason in alerts:
            alerts_msg += f"- {reason}\n"
            alerts_single_line += f"{reason};"

        if client_ip in mem.alerts_sent:
            for prev_entry in mem.alerts_sent[client_ip]:
                prev_date, prev_type = prev_entry
                if prev_type == alerts_single_line:
                    delta = datetime.now() - prev_date
                    if delta.total_seconds() <= SEND_ALERT_COOLDOWN:
                        return

                    mem.alerts_sent[client_ip].remove(prev_entry)
                    break

        else:
            mem.alerts_sent[client_ip] = set()

        mem.alerts_sent[client_ip].add((datetime.now(), alerts_single_line))
        logging.info("LOG FLAGGED: %s%s", line, alerts_msg)
        # threading.Thread(target=send_alert, kwargs={"alerts": alerts_msg, "log_line": line}).start()
        with open(LOG_REPORT_FILE, "a", encoding="utf-8") as f:
            f.write(f"{timestamp}|{alerts_single_line}\n")


# checks designed to run periodically in a separate background thread
def bg_checks(values: BGChecksValues, mem: MemValues):
    while True:
        current_time = datetime.now()
        
        # clear dictionaries after a set amount of time to prevent old entries taking up memory
        mem_clear_delta = current_time - values.last_mem_clear
        if mem_clear_delta.total_seconds() >= MEM_CLEAR_TIME:
            mem.clear_mem()
            values.last_mem_clear = current_time

        # check how many logs were received since last check
        if values.log_count > SPAM_MAX_LOGS:
            alert_delta = current_time - values.last_spam_alert
            if alert_delta.total_seconds() >= SEND_ALERT_COOLDOWN:
                values.last_spam_alert = current_time
                logging.info("ABNORMAL NUMBER OF LOGS DETECTED: %s in the last %s seconds\n",
                             values.log_count, SPAM_TIME_WINDOW)
                threading.Thread(target=send_alert,
                                 kwargs={"alerts": f"- abnormal number of logs detected: {values.log_count} in the last {SPAM_TIME_WINDOW} seconds\n",
                                         "log_line": None}).start()

        values.log_count = 0

        time.sleep(SPAM_TIME_WINDOW)


def main():
    # dictionaries for storing info about recently processed logs
    mem_values = MemValues()

    # start periodic background checks
    bg_checks_values = BGChecksValues()
    threading.Thread(target=bg_checks, kwargs={"values": bg_checks_values, "mem": mem_values},
                     daemon=True).start()

    # ASCII art made with https://patorjk.com/software/taag/
    print(r"""================================================
    _   __     __       _ __
   / | / /__  / /______(_) /   ____  ____ ______
  /  |/ / _ \/ __/ ___/ / /   / __ \/ __ `/ ___/
 / /|  /  __/ /_/ /  / / /___/ /_/ / /_/ (__  )
/_/ |_/\___/\__/_/  /_/_____/\____/\__, /____/
                                  /____/
================================================""")
    print("Made by Captain Crookeye")
    print("================================================")
    print("Press Ctrl+C to exit")
    print("================================================")

    try:
        for line in sys.stdin:
            if not line:
                continue
            bg_checks_values.log_count += 1
            process_line(line=line, mem=mem_values)

    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
