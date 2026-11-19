import json

from modules.paths import get_user_data_dir


def _settings_path():
    return get_user_data_dir() / "remote_targets.json"


def load_remote_settings():

    settings_path = _settings_path()
    if not settings_path.exists():
        return {
            "targets": [],
            "domain": "",
            "remember_targets": True,
            "remember_domain": True,
        }

    with settings_path.open("r", encoding="utf-8") as file:
        settings = json.load(file)

    targets = settings.get("targets", [])
    domain = settings.get("domain", "")
    remember_targets = settings.get("remember_targets", True)
    remember_domain = settings.get("remember_domain", True)

    if (
        not isinstance(targets, list)
        or any(not isinstance(target, str) for target in targets)
        or not isinstance(domain, str)
        or not isinstance(remember_targets, bool)
        or not isinstance(remember_domain, bool)
    ):
        raise ValueError("Saved remote settings have an invalid format.")

    return {
        "targets": targets,
        "domain": domain,
        "remember_targets": remember_targets,
        "remember_domain": remember_domain,
    }


def save_remote_settings(
    targets,
    domain,
    remember_targets,
    remember_domain,
):

    settings_path = _settings_path()
    saved_settings = {
        "targets": list(targets) if remember_targets else [],
        "domain": domain if remember_domain else "",
        "remember_targets": remember_targets,
        "remember_domain": remember_domain,
    }

    if not remember_targets and not remember_domain:
        settings_path.unlink(missing_ok=True)
        return

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = settings_path.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps(saved_settings, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(settings_path)


def forget_remote_settings():

    _settings_path().unlink(missing_ok=True)
