import json


class ConsoleSink:
    def emit(self, record: dict) -> None:
        if record.get("event_type") == "file_event":
            line = f'{record["timestamp"]}  {record["action"].upper():9} {record["path"]}'
            if record.get("dest_path"):
                line += f' -> {record["dest_path"]}'
        else:
            line = json.dumps(record)
        print(line, flush=True)

    def close(self) -> None:
        pass