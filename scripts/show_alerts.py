"""Print every alert stored in logs/events.db. Add -v to see the last one in full."""
import json
import sqlite3
import sys


def main() -> None:
    db = sqlite3.connect("logs/events.db")
    rows = db.execute(
        "SELECT payload FROM events WHERE event_type='alert' ORDER BY timestamp"
    ).fetchall()
    db.close()
    if not rows:
        print("No alerts.")
        return
    for (payload,) in rows:
        a = json.loads(payload)
        print(f'{a["timestamp"]}  {a["status"]:9} {a["severity"]:8} '
              f'score={a["risk_score"]:<3} {a["message"]}')
    if "-v" in sys.argv:
        print(json.dumps(json.loads(rows[-1][0]), indent=2))


if __name__ == "__main__":
    main()