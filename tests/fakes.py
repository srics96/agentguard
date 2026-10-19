"""A fake Playwright-style page for exercising the guard without Chromium.

It records fills/clicks/navigations and can hold a scripted network request so
the network guard can be tested too.
"""
from __future__ import annotations


class FakeRoute:
    def __init__(self):
        self.continued = False
        self.aborted = False

    def continue_(self):
        self.continued = True

    def abort(self):
        self.aborted = True


class FakeRequest:
    def __init__(self, method, url, body=""):
        self.method = method
        self.url = url
        self._body = body

    def post_data(self):
        return self._body


class FakePage:
    def __init__(self, url="http://localhost/", body=""):
        self._url = url
        self.body = body
        self.fills: list[tuple[str, str]] = []
        self.clicks: list[str] = []
        self.navigations: list[str] = []
        self.closed = False
        self._net_handler = None

    # --- Playwright surface used by the guard ---
    @property
    def url(self):
        return self._url

    def goto(self, url):
        self._url = url
        self.navigations.append(url)

    def inner_text(self, selector):
        return self.body

    def fill(self, selector, value):
        self.fills.append((selector, value))

    def click(self, selector):
        self.clicks.append(selector)

    def press(self, selector, key):
        self.clicks.append(f"{selector}:{key}")

    def set_input_files(self, selector, path):
        self.fills.append((selector, f"<file:{path}>"))

    def screenshot(self, path=None):
        return b"PNG"

    def close(self):
        self.closed = True

    def route(self, pattern, handler):
        self._net_handler = handler

    # --- test helper: simulate the page making a request ---
    def emit_request(self, method, url, body=""):
        route = FakeRoute()
        self._net_handler(route, FakeRequest(method, url, body))
        return route
