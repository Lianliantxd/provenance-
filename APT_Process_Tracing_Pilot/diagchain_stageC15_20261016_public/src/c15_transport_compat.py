"""Observed CLI reconnect text compatibility; canonical reply checks stay native."""
from __future__ import annotations
import re
from jsonl_final_message_parser import JsonlParser, ParseFailure
from safe_paths import strict_json, SafetyError

VERSION = 'C15_TRANSPORT_COMPAT_V1'
REASONS = (
    'workspace routing discovery timed out',
    'stream disconnected before completion: IO error: peer closed connection without sending TLS close_notify: '
    'https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof',
)
EXTRA_RECONNECT = re.compile(r'Reconnecting\.\.\. ([1-5])/5 \((' + '|'.join(re.escape(s) for s in REASONS) + r')\)')
EXTRA_FALLBACKS = frozenset('Falling back from WebSockets to HTTPS transport. ' + s for s in REASONS)

class CompatParser(JsonlParser):
    def _event(self, line: str) -> None:
        try:
            event = strict_json(line)
        except (ValueError, SafetyError):
            return super()._event(line)
        message = event.get('message')
        match = EXTRA_RECONNECT.fullmatch(message) if isinstance(message, str) and event.get('type') == 'error' else None
        item = event.get('item', {})
        fallback = (event.get('type') == 'item.completed' and isinstance(item, dict)
                    and item.get('type') == 'error' and isinstance(item.get('message'),str)
                    and item.get('message') in EXTRA_FALLBACKS)
        if not match and not fallback:
            return super()._event(line)
        if self.completions:
            raise ParseFailure('EVENT_AFTER_TURN_COMPLETION')
        self.events.append(event)
        if self.starts != 1:
            raise ParseFailure('UNRECOGNIZED_OR_PRE_TURN_ERROR')
        if match:
            index = int(match.group(1))
            if len(self.reconnects) >= 5 or self.reconnects and index <= self.reconnects[-1]['attempt_number']:
                raise ParseFailure('TRANSPORT_RETRY_STATE_UNKNOWN')
            self.reconnects.append({'attempt_number': index, 'message': message, 'event_index': len(self.events)-1})
        else:
            if self.https_fallback or not self.reconnects:
                raise ParseFailure('TRANSPORT_RETRY_STATE_UNKNOWN')
            self.https_fallback = True
