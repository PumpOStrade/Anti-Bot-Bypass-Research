"""Browser profile data structure — a consistent browser identity."""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BrowserProfile:
    name: str
    browser: str = "chrome"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    )
    screen_width: int = 1920
    screen_height: int = 1080
    color_depth: int = 24
    timezone: str = "America/New_York"
    timezone_offset: int = -300
    locale: str = "en-US"
    languages: list[str] = field(default_factory=lambda: ["en-US", "en"])
    hardware_concurrency: int = 16
    device_memory: int = 8
    max_touch_points: int = 0
    platform: str = "Win32"
    canvas_seed: int = 0  # Seed for deterministic canvas noise
    webgl_vendor: str = "Google Inc. (NVIDIA)"
    webgl_renderer: str = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
    plugins: list[str] = field(default_factory=lambda: [
        "PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer",
        "Microsoft Edge PDF Viewer", "WebKit built-in PDF",
    ])
    cookies: dict[str, str] = field(default_factory=dict)

    def to_stealth_script(self) -> str:
        """Generate JavaScript injection that applies this exact profile."""
        plugins_js = ",".join(
            f'{{ name: "{p}", filename: "internal-pdf-viewer", description: "", length: 1 }}'
            for p in self.plugins
        )

        return f"""
// Browser Profile: {self.name}
Object.defineProperty(navigator, 'webdriver', {{ get: () => false }});
Object.defineProperty(navigator, 'userAgent', {{ get: () => "{self.user_agent}" }});
Object.defineProperty(navigator, 'platform', {{ get: () => "{self.platform}" }});
Object.defineProperty(navigator, 'languages', {{ get: () => {json.dumps(self.languages)} }});
Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {self.hardware_concurrency} }});
Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {self.device_memory} }});
Object.defineProperty(navigator, 'maxTouchPoints', {{ get: () => {self.max_touch_points} }});

Object.defineProperty(navigator, 'plugins', {{
    get: () => {{
        const plugins = [{plugins_js}];
        plugins.refresh = function(){{}};
        plugins.namedItem = function(n) {{ return this.find(p => p.name === n) || null; }};
        plugins.item = function(i) {{ return this[i] || null; }};
        return plugins;
    }}
}});

if (!window.chrome) {{
    window.chrome = {{
        runtime: {{ onMessage: {{ addListener: function(){{}}, removeListener: function(){{}}}}, sendMessage: function(){{}}, connect: function() {{ return {{ onMessage: {{ addListener: function(){{}}}}}};}} }},
        loadTimes: function() {{ return {{}}; }},
        csi: function() {{ return {{}}; }},
    }};
}}

// Deterministic canvas noise using seed {self.canvas_seed}
const _ctd = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {{
    const ctx = this.getContext('2d');
    if (ctx && this.width > 0) {{
        try {{
            const id = ctx.getImageData(0, 0, Math.min(this.width, 16), Math.min(this.height, 16));
            let seed = {self.canvas_seed};
            for (let i = 0; i < id.data.length; i += 4) {{
                seed = (seed * 1103515245 + 12345) & 0x7fffffff;
                if ((seed % 100) > 97) id.data[i] ^= 1;
            }}
            ctx.putImageData(id, 0, 0);
        }} catch(e) {{}}
    }}
    return _ctd.apply(this, arguments);
}};

// WebGL spoofing
const _gp = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(p) {{
    if (p === 37445) return '{self.webgl_vendor}';
    if (p === 37446) return '{self.webgl_renderer}';
    return _gp.apply(this, arguments);
}};
try {{
    const _gp2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(p) {{
        if (p === 37445) return '{self.webgl_vendor}';
        if (p === 37446) return '{self.webgl_renderer}';
        return _gp2.apply(this, arguments);
    }};
}} catch(e) {{}}

Date.prototype.getTimezoneOffset = function() {{ return {self.timezone_offset}; }};

delete window.__nightmare;
delete window._phantom;
delete window.callPhantom;
delete window.domAutomation;
delete window.domAutomationController;
try {{ delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array; }} catch(e) {{}}
try {{ delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise; }} catch(e) {{}}

Object.defineProperty(Notification, 'permission', {{ get: () => 'default' }});
"""

    def save(self, directory: str | Path):
        """Save profile to JSON file."""
        path = Path(directory) / f"{self.name}.json"
        data = {
            "name": self.name, "browser": self.browser,
            "user_agent": self.user_agent, "screen_width": self.screen_width,
            "screen_height": self.screen_height, "color_depth": self.color_depth,
            "timezone": self.timezone, "timezone_offset": self.timezone_offset,
            "locale": self.locale, "languages": self.languages,
            "hardware_concurrency": self.hardware_concurrency,
            "device_memory": self.device_memory, "max_touch_points": self.max_touch_points,
            "platform": self.platform, "canvas_seed": self.canvas_seed,
            "webgl_vendor": self.webgl_vendor, "webgl_renderer": self.webgl_renderer,
            "plugins": self.plugins, "cookies": self.cookies,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, filepath: str | Path) -> "BrowserProfile":
        """Load profile from JSON file."""
        data = json.loads(Path(filepath).read_text(encoding="utf-8"))
        return cls(**data)
