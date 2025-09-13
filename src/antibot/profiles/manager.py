"""Manage persistent browser identity profiles."""

import random
from pathlib import Path

from antibot.profiles.profile import BrowserProfile

PROFILES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "profiles"

# GPU options for randomization
GPUS = [
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
]

SCREENS = [(1920, 1080), (2560, 1440), (1366, 768), (1536, 864), (1440, 900)]
TIMEZONES = [
    ("America/New_York", -300), ("America/Chicago", -360),
    ("America/Denver", -420), ("America/Los_Angeles", -480),
    ("Europe/London", 0), ("Europe/Berlin", -60),
]


class ProfileManager:
    """Create, load, list, and delete browser profiles."""

    def __init__(self, profiles_dir: Path | None = None):
        self.profiles_dir = profiles_dir or PROFILES_DIR
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

    def create(self, name: str, browser: str = "chrome") -> BrowserProfile:
        """Generate a new consistent browser identity."""
        gpu = random.choice(GPUS)
        screen = random.choice(SCREENS)
        tz = random.choice(TIMEZONES)

        profile = BrowserProfile(
            name=name,
            browser=browser,
            screen_width=screen[0],
            screen_height=screen[1],
            timezone=tz[0],
            timezone_offset=tz[1],
            canvas_seed=random.randint(1, 2**31),
            webgl_vendor=gpu[0],
            webgl_renderer=gpu[1],
            hardware_concurrency=random.choice([4, 8, 12, 16]),
            device_memory=random.choice([4, 8, 16]),
        )

        profile.save(self.profiles_dir)
        return profile

    def load(self, name: str) -> BrowserProfile | None:
        """Load a profile by name."""
        path = self.profiles_dir / f"{name}.json"
        if not path.exists():
            return None
        return BrowserProfile.load(path)

    def list(self) -> list[BrowserProfile]:
        """List all saved profiles."""
        profiles = []
        for path in sorted(self.profiles_dir.glob("*.json")):
            try:
                profiles.append(BrowserProfile.load(path))
            except Exception:
                continue
        return profiles

    def delete(self, name: str) -> bool:
        """Delete a profile."""
        path = self.profiles_dir / f"{name}.json"
        if path.exists():
            path.unlink()
            return True
        return False
