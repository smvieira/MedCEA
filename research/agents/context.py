"""research/agents/context.py (AH.4, R22, R30): the model's request, append-only and canonical.
A tool result is shown as <tool_result ... untrusted="true">escaped, at most 1000 characters
</tool_result>: & < > are escaped, so the content cannot close the wrapper."""
import hashlib
import json

SHOWN_MAX = 1000


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode("utf-8")).hexdigest()


def wrap_result(tool, call, result_text):
    """-> (wrapped text, full sha256, shown text, truncated?)"""
    full = sha(result_text)
    esc = result_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    shown = esc[:SHOWN_MAX]
    return ('<tool_result tool="%s" call="%d" sha256="%s" untrusted="true">%s</tool_result>'
            % (tool, call, full, shown), full, shown, len(esc) > SHOWN_MAX)


class Context:
    def __init__(self, standing, skill, tools):
        self.system = standing + "\n\n" + skill
        self.tools = tools                      # [{name, description}], fixed for the session
        self.messages = []                      # only ever appended to

    def add(self, role, content, **extra):
        self.messages.append(dict(extra, role=role, content=content))

    def request(self):
        return {"system": self.system, "tools": self.tools, "messages": self.messages}

    def request_bytes(self):
        return canonical(self.request())

    def est_tokens(self):
        return (len(self.request_bytes()) + 3) // 4
