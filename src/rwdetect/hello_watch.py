import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class PrintHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"CREATED  {event.src_path}")

    def on_modified(self, event):
        print(f"MODIFIED {event.src_path}")

    def on_deleted(self, event):
        print(f"DELETED  {event.src_path}")

    def on_moved(self, event):
        print(f"MOVED    {event.src_path} -> {event.dest_path}")


if __name__ == "__main__":
    watch_dir = Path("sandbox").resolve()

    observer = Observer()
    observer.schedule(PrintHandler(), str(watch_dir), recursive=True)
    observer.start()
    print(f"Watching {watch_dir}  (Ctrl+C to stop)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()