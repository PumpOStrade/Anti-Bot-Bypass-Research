"""Statistical models of real human behavior for anti-detection.

Timing distributions based on HCI research:
- Mouse velocity follows bell curve with acceleration/deceleration
- Click intervals follow log-normal distribution
- Scroll patterns include read-dwell-scroll cycles
- Typing speed varies by key distance on QWERTY layout
"""

import math
import random
from dataclasses import dataclass


@dataclass
class ScrollEvent:
    delta_y: int
    delay_before: float  # seconds
    speed: float  # pixels per second


@dataclass
class MousePoint:
    x: int
    y: int
    delay: float  # seconds to next point


class HumanTimingModel:
    """Statistical model of human interaction timing."""

    def first_interaction_delay(self) -> float:
        """Delay before first mouse move after page load (1-4s, skewed right)."""
        return random.lognormvariate(0.7, 0.4)  # median ~2s

    def mouse_velocity_curve(self, distance: float, steps: int = 30) -> list[float]:
        """Generate realistic velocity multipliers for a mouse movement.

        Real humans: slow start, fast middle, slow end (bell curve).
        Returns list of velocity multipliers (0.0-1.0) for each step.
        """
        curve = []
        for i in range(steps):
            t = i / max(steps - 1, 1)
            # Sine-based velocity profile: slow-fast-slow
            velocity = math.sin(t * math.pi)
            # Add slight randomness
            velocity *= random.uniform(0.8, 1.2)
            curve.append(max(0.05, velocity))
        return curve

    def mouse_move_delay(self, velocity: float) -> float:
        """Delay between mouse move events based on velocity.

        Faster movement = shorter delays between events.
        """
        base_delay = 0.008  # ~125 Hz mouse polling
        jitter = random.uniform(-0.003, 0.003)
        return max(0.002, base_delay / max(velocity, 0.1) + jitter)

    def click_interval(self) -> float:
        """Time between clicks — log-normal distribution, median ~800ms."""
        return random.lognormvariate(-0.22, 0.5)  # median ~800ms

    def double_click_interval(self) -> float:
        """Time between clicks in a double-click — 50-150ms."""
        return random.uniform(0.05, 0.15)

    def scroll_pattern(self, page_height: int = 3000, viewport_height: int = 1080) -> list[ScrollEvent]:
        """Generate a realistic scroll pattern: scroll-stop-read-scroll.

        Humans scroll in bursts, pause to read, then scroll again.
        """
        events = []
        current_y = 0
        max_scroll = page_height - viewport_height

        while current_y < max_scroll:
            # Scroll burst: 2-5 scroll events in quick succession
            burst_size = random.randint(2, 5)
            for _ in range(burst_size):
                delta = random.randint(80, 300)
                events.append(ScrollEvent(
                    delta_y=delta,
                    delay_before=random.uniform(0.05, 0.2),  # Quick within burst
                    speed=random.uniform(200, 600),
                ))
                current_y += delta
                if current_y >= max_scroll:
                    break

            # Reading pause between bursts (0.5-4 seconds)
            if current_y < max_scroll:
                events.append(ScrollEvent(
                    delta_y=0,
                    delay_before=random.lognormvariate(0.5, 0.6),  # median ~1.6s
                    speed=0,
                ))

        return events

    def typing_speed(self, text: str) -> list[float]:
        """Per-key delays based on QWERTY key distance.

        Adjacent keys are typed faster; distant keys have longer gaps.
        Average: 150-300ms per keystroke.
        """
        # QWERTY row positions (row, col)
        key_pos = {}
        rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
        for r, row in enumerate(rows):
            for c, char in enumerate(row):
                key_pos[char] = (r, c)

        delays = []
        prev_pos = None
        for char in text.lower():
            pos = key_pos.get(char, (1, 5))  # Default to middle

            if prev_pos:
                # Distance between keys
                dist = math.sqrt((pos[0] - prev_pos[0]) ** 2 + (pos[1] - prev_pos[1]) ** 2)
                # Closer keys = faster typing
                base_delay = 0.08 + dist * 0.03
            else:
                base_delay = 0.15

            # Add human-like jitter
            delay = base_delay * random.uniform(0.7, 1.4)
            delays.append(max(0.04, delay))
            prev_pos = pos

        return delays

    def page_read_time(self, content_length: int) -> float:
        """Estimated time a human would spend on a page.

        Based on average reading speed of ~250 words/min,
        assuming ~5 chars per word.
        """
        words = content_length / 5
        reading_time = words / 250 * 60  # seconds
        # Humans don't read everything — 20-60% of content
        return reading_time * random.uniform(0.2, 0.6) + random.uniform(1, 3)

    def overshoot_probability(self) -> bool:
        """Whether to overshoot a target and correct — happens ~15% of the time."""
        return random.random() < 0.15

    def overshoot_distance(self) -> int:
        """How far past the target to overshoot (10-50 pixels)."""
        return random.randint(10, 50)

    def micro_pause(self) -> float:
        """Brief hesitation during mouse movement — 50-200ms, happens occasionally."""
        return random.uniform(0.05, 0.2)
