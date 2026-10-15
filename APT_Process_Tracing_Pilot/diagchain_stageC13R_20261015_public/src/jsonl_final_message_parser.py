"""Codex 0.160 JSONL framing + canonical output-last-message selection.

Physical UTF-8 chunks are reassembled only within their JSONL record. Distinct
message IDs are never concatenated. Unknown fragment schemas stop as ambiguous.
"""
from __future__ import annotations
import codecs
import json
import re
from safe_paths import SafetyError, sha, strict_json

STARTUP_WARNINGS = {
    'Under-development features enabled: skip_host_skill_discovery. Under-development features are incomplete and may behave unpredictably. To suppress this warning, set `suppress_unstable_features_warning = true` in /Users/tianxd/.codex/config.toml.',
    'Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.',
}
TRANSPORT = re.compile(r'Reconnecting\.\.\. ([1-5])/5 \((request timed out|stream disconnected before completion: tls handshake eof|Connection failed: error sending request)\)')


class ParseFailure(SafetyError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class JsonlParser:
    def __init__(self) -> None:
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.finished = False
        self.buffer, self.bytes_seen = '', 0
        self.events, self.messages, self.message_ids = [], [], set()
        self.threads, self.starts, self.completions = 0, 0, 0
        self.reconnects, self.startup, self.usage = [], [], {}
        self.https_fallback = False

    def feed(self, chunk: bytes) -> None:
        if self.finished:
            raise ParseFailure("PARSER_ALREADY_FINISHED")
        if not isinstance(chunk, bytes):
            raise ParseFailure('JSONL_NOT_BYTES')
        self.bytes_seen += len(chunk)
        if self.bytes_seen > 8388608:
            raise ParseFailure('JSONL_BYTE_LIMIT')
        try:
            self.buffer += self.decoder.decode(chunk)
        except UnicodeDecodeError as exc:
            raise ParseFailure('FINAL_TEXT_AMBIGUOUS_INVALID_UTF8') from exc
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            if line.strip():
                self._event(line)

    def _event(self, line: str) -> None:
        try:
            e = strict_json(line)
        except (ValueError, SafetyError) as exc:
            raise ParseFailure('INVALID_OR_TRUNCATED_JSONL') from exc
        if self.completions:
            raise ParseFailure('EVENT_AFTER_TURN_COMPLETION')
        typ = e.get('type')
        known = {'thread.started', 'turn.started', 'turn.completed', 'turn.failed',
                 'item.started', 'item.updated', 'item.completed', 'error'}
        if typ not in known:
            raise ParseFailure('UNKNOWN_JSONL_EVENT')
        self.events.append(e)
        if typ == 'thread.started':
            self.threads += 1
            if self.threads != 1 or self.starts:
                raise ParseFailure('THREAD_OR_TURN_AMBIGUOUS')
        elif typ == 'turn.started':
            self.starts += 1
            if self.starts != 1 or self.threads != 1:
                raise ParseFailure('THREAD_OR_TURN_AMBIGUOUS')
        elif typ == 'turn.completed':
            if self.starts != 1:
                raise ParseFailure('COMPLETION_WITHOUT_START')
            self.completions += 1
            self.usage = e.get('usage', {})
        elif typ == 'turn.failed':
            raise ParseFailure('TURN_FAILED_REMOTE_COMPLETION_UNKNOWN')
        elif typ == 'error':
            message = e.get('message')
            match = TRANSPORT.fullmatch(message) if isinstance(message, str) else None
            if not match or self.starts != 1:
                raise ParseFailure('UNRECOGNIZED_OR_PRE_TURN_ERROR')
            index = int(match.group(1))
            if len(self.reconnects) >= 5 or self.reconnects and index <= self.reconnects[-1]['attempt_number']:
                raise ParseFailure('TRANSPORT_RETRY_STATE_UNKNOWN')
            self.reconnects.append({'attempt_number': index, 'message': message,
                                    'event_index': len(self.events) - 1})
        else:
            item = e.get('item')
            if not isinstance(item, dict):
                raise ParseFailure('MISSING_ITEM')
            kind = item.get('type')
            if kind == 'error' and typ == 'item.completed' and self.starts == 0 and item.get('message') in STARTUP_WARNINGS:
                if item['message'] in self.startup:
                    raise ParseFailure('DUPLICATE_STARTUP_ERROR')
                self.startup.append(item['message'])
                return
            if kind == 'error' and typ == 'item.completed' and self.starts == 1 and item.get('message') == 'Falling back from WebSockets to HTTPS transport. stream disconnected before completion: tls handshake eof':
                if self.https_fallback or not self.reconnects:
                    raise ParseFailure('TRANSPORT_RETRY_STATE_UNKNOWN')
                self.https_fallback = True
                return
            if kind not in {'agent_message', 'reasoning'}:
                raise ParseFailure('TOOL_OR_UNSUPPORTED_ITEM')
            if self.starts != 1:
                raise ParseFailure('TEXT_OUTSIDE_TURN')
            if kind == 'agent_message':
                identity = item.get('id')
                if not isinstance(identity, str) or not identity:
                    raise ParseFailure('FINAL_TEXT_AMBIGUOUS_MISSING_ID')
                if typ == 'item.completed':
                    if identity in self.message_ids:
                        raise ParseFailure('DUPLICATE_FINAL_EVENT')
                    if not isinstance(item.get('text'), str):
                        raise ParseFailure('FINAL_TEXT_AMBIGUOUS_UNVERIFIED_FRAGMENT_SCHEMA')
                    self.message_ids.add(identity)
                    self.messages.append({'id': identity, 'text': item['text']})

    def finish(self, raw_final: bytes, cli_exit_code: int | None) -> dict:
        if self.finished:
            raise ParseFailure("PARSER_ALREADY_FINISHED")
        self.finished = True
        try:
            self.buffer += self.decoder.decode(b'', final=True)
        except UnicodeDecodeError as exc:
            raise ParseFailure('FINAL_TEXT_AMBIGUOUS_INVALID_UTF8') from exc
        if self.buffer.strip():
            self._event(self.buffer)
        self.buffer = ''
        if type(cli_exit_code) is not int or cli_exit_code != 0:
            raise ParseFailure('CLI_EXIT_ABNORMAL_OR_UNVERIFIED')
        if self.starts != 1 or self.completions != 1:
            raise ParseFailure('REMOTE_COMPLETION_UNKNOWN')
        if not self.messages or not raw_final or len(raw_final) > 1048576:
            raise ParseFailure('EMPTY_OR_OVERSIZED_FINAL_REPLY')
        try:
            text = raw_final.decode('utf-8', errors='strict')
        except UnicodeDecodeError as exc:
            raise ParseFailure('FINAL_TEXT_AMBIGUOUS_INVALID_UTF8') from exc
        if self.messages[-1]['text'].encode('utf-8') != raw_final:
            raise ParseFailure('FINAL_TEXT_AMBIGUOUS_OUTPUT_FILE_MISMATCH')
        try:
            strict_json(text)
            author_json_status = 'OBJECT'
        except SafetyError as exc:
            author_json_status = str(exc)
        except ValueError:
            author_json_status = 'INVALID_OR_TRUNCATED_AUTHOR_JSON'
        return {'status': 'CANONICAL_FINAL_VERIFIED', 'selection': 'EXACT_LAST_COMPLETED_MESSAGE_MATCHES_CANONICAL_FILE',
                'cli_exit_code': cli_exit_code, 'tool_verdict': 'NO_TOOL_CALL_OBSERVED',
                'reply_sha256': sha(raw_final), 'reply_bytes': len(raw_final),
                'selected_message_id': self.messages[-1]['id'], 'completed_message_count': len(self.messages),
                'earlier_message_hashes': [sha(x['text']) for x in self.messages[:-1]],
                'messages_concatenated': False, 'raw_reply_modified': False,
                'author_json_status': author_json_status, 'usage': self.usage,
                'transport_events': self.reconnects, 'known_startup_warnings': self.startup,
                'https_fallback_observed': self.https_fallback,
                'internal_model_generation_count': 'NOT_IDENTIFIABLE', 'model_snapshot': 'UNVERIFIED'}


def parse_final(events: bytes, raw_final: bytes, cli_exit_code: int | None) -> dict:
    parser = JsonlParser()
    parser.feed(events)
    return parser.finish(raw_final, cli_exit_code)

