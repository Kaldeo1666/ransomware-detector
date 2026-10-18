import os

# Formats that are ALREADY compressed, so high entropy is normal for them.
HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".gz", ".7z", ".rar", ".bz2", ".xz", ".jpg", ".jpeg", ".png", ".gif",
    ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".pdf", ".docx", ".xlsx", ".pptx",
}


def classify(event, settings: dict) -> str | None:
    """Return 'jump', 'new_high' or None for one enriched event."""
    cfg = settings["entropy"]
    if event.is_directory or event.entropy is None:
        return None
    if event.size is not None and event.size < settings["min_file_size"]:
        return None
    if event.entropy < cfg["high"]:
        return None
    if event.entropy_delta is not None:
        return "jump" if event.entropy_delta >= cfg["jump_delta"] else None
    if event.action in ("created", "moved"):
        target = event.dest_path or event.path
        if os.path.splitext(target)[1].lower() not in HIGH_ENTROPY_EXTENSIONS:
            return "new_high"
    return None