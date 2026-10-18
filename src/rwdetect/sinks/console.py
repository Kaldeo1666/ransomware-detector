import json


class ConsoleSink:
    def emit(self, record: dict) -> None:
        kind = record.get("event_type")
        if kind == "file_event":
            line = f'{record["timestamp"]}  {record["action"].upper():9} {record["path"]}'
            if record.get("dest_path"):
                line += f' -> {record["dest_path"]}'
            if record.get("entropy") is not None:
                line += f'   H={record["entropy"]:.2f}'
            if record.get("entropy_delta") is not None:
                line += f' ({record["entropy_delta"]:+.2f})'
        elif kind == "alert":
            line = (f'\n*** ALERT [{record["severity"].upper()}] score={record["risk_score"]} '
                    f'({record["status"]}) {record["message"]}\n')
        else:
            line = json.dumps(record)
        print(line, flush=True)

    def close(self) -> None:
        pass