import sys
import time
import subprocess
from datetime import datetime

# use to determine regular amount of received logs

TIME_WINDOW = 10    # monitoring period in seconds
LOG_FILE = "path/to/file.log"

def main():
    # ASCII art made with https://patorjk.com/software/taag/
    print(r"""=============================================================
    _   __     __       _ __  ___            _ __
   / | / /__  / /______(_)  |/  /___  ____  (_) /_____  _____
  /  |/ / _ \/ __/ ___/ / /|_/ / __ \/ __ \/ / __/ __ \/ ___/
 / /|  /  __/ /_/ /  / / /  / / /_/ / / / / / /_/ /_/ / /
/_/ |_/\___/\__/_/  /_/_/  /_/\____/_/ /_/_/\__/\____/_/

=============================================================""")
    print("Made by Captain Crookeye")
    print("=============================================================")
    print("Press Ctrl+C to exit")
    print("=============================================================")

    try:
        count = subprocess.check_output(["wc", "-l", LOG_FILE], text=True)
    except subprocess.CalledProcessError:
        print("Error: wc command failed")
        sys.exit(1)

    start_time = datetime.now()
    last = int(count.split()[0])
    highest_diff = 0

    while True:
        try:
            try:
                count = subprocess.check_output(["wc", "-l", LOG_FILE], text=True)
            except subprocess.CalledProcessError:
                print("Error: wc command failed")
                sys.exit(1)
            current = int(count.split()[0])

            diff = current - last
            if diff > highest_diff:
                highest_diff = diff
                with open("monitor_result.txt", "w") as f:
                    f.write(f"{str(diff)}\n")
            last = current

            time.sleep(TIME_WINDOW)

        except KeyboardInterrupt:
            print(f"\nStarted at: {start_time}")
            print(f"Finished at: {datetime.now()}")
            print(f"Highest number of logs written in {TIME_WINDOW} seconds: {highest_diff}")
            sys.exit(0)


if __name__ == "__main__":
    main()
