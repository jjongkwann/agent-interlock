from __future__ import annotations

import http.client
import unittest
from urllib.parse import urlsplit

from agent_interlock import LoopbackCallbackReceiver, OAuthConsentError, run_consent


def _browser_redirect_to(callback_query: str):
    """A fake 'browser' opener: ignores the auth URL and hits the loopback callback."""

    def opener(authorization_uri: str) -> None:
        # A real browser would visit authorization_uri, then the AS would 302 it here.
        target = _pending["redirect"]
        parts = urlsplit(target)
        connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=3)
        try:
            connection.request("GET", f"{parts.path}?{callback_query}")
            connection.getresponse().read()
        finally:
            connection.close()

    return opener


_pending: dict[str, str] = {}


class LoopbackConsentTests(unittest.TestCase):
    def test_run_consent_returns_the_one_time_callback_uri(self):
        with LoopbackCallbackReceiver() as receiver:
            _pending["redirect"] = receiver.redirect_uri
            callback = run_consent(
                "https://idp.example/authorize?client_id=c&state=xyz",
                receiver,
                opener=_browser_redirect_to("code=auth-code-123&state=xyz"),
                timeout=3,
            )
        self.assertEqual(callback, f"{receiver.redirect_uri}?code=auth-code-123&state=xyz")
        parts = urlsplit(callback)
        self.assertEqual(parts.path, "/callback")
        self.assertIn("code=auth-code-123", parts.query)
        self.assertIn("state=xyz", parts.query)

    def test_second_callback_is_refused(self):
        with LoopbackCallbackReceiver() as receiver:
            parts = urlsplit(receiver.redirect_uri)

            def hit(query: str) -> int:
                connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=3)
                try:
                    connection.request("GET", f"{parts.path}?{query}")
                    return connection.getresponse().status
                finally:
                    connection.close()

            self.assertEqual(hit("code=a&state=s"), 200)
            self.assertEqual(hit("code=b&state=s"), 409)  # single-use
            self.assertEqual(receiver.wait_for_callback(timeout=1), f"{receiver.redirect_uri}?code=a&state=s")

    def test_timeout_raises(self):
        with LoopbackCallbackReceiver() as receiver, self.assertRaises(OAuthConsentError):
            receiver.wait_for_callback(timeout=0.2)

    def test_non_loopback_host_is_refused(self):
        with self.assertRaises(ValueError):
            LoopbackCallbackReceiver(host="0.0.0.0")


if __name__ == "__main__":
    unittest.main()
