# log_parser
A simple live log parser written in Python

## functions
- monitoring of a live log file - e.g. one actively being written into by another process
- automatic sending of warnings via Discord webhooks
- monthly stats report

## basic setup and usage
1. Download required libraries: `pip install -r req.txt`
2. Set variables:
  - `LOG_FILE` in `start_parser.sh`
  - `WEBHOOK_URL` in `parser.py`
  - `LOG_REPORT_FILE`, `WEBHOOK_URL` in `log_report.py`
  - optionally `LOG_FILE` in `througput_monitor.py` and other variables
3. Set REGEX pattern in `parser.py` based on the format used by logger
  - variables: `LOG_REGEX_PATTERN`, `LOG_DATETIME_PATTERN`
  - group splits: top of `process_line()` function
4. Run with: `./start_parser.sh`
5. Optionally: set a job planner(e.g. CRON) to regularly run `log_report.py` to generate a report
