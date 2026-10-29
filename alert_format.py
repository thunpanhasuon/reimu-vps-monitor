"""Compact Telegram HTML cards. All server-supplied text is escaped."""
from datetime import datetime, timedelta, timezone
from html import escape
import re

CAMBODIA = timezone(timedelta(hours=7))
METRIC = re.compile(r'^(CPU|RAM|Disk|Incoming traffic|Outgoing traffic):\s*([\d.]+)\s*(%|Mbps|Kbps)$')
LABELS = {'CPU': 'CPU', 'RAM': 'Memory', 'Disk': 'Disk',
          'Incoming traffic': 'Network in', 'Outgoing traffic': 'Network out'}
BOLD_LABELS = {'Threshold', 'Duration', 'Recovery', 'Schedule', 'Stage', 'Reason',
               'Host', 'Process', 'Binding', 'Access', 'Next step', 'Expiry', 'Status',
               'Available', 'Reminders', 'Reboots', 'Listeners'}


def friendly_title(first):
    resource = re.fullmatch(r'(⚠️ HIGH|⚠️ STILL HIGH|✅ RECOVERED) — (.+)', first)
    if resource:
        event, name = resource.groups()
        name = {'CPU': 'CPU usage', 'RAM': 'Memory usage', 'Disk': 'Disk usage'}.get(name, name)
        if 'RECOVERED' in event:
            return '✅ ' + name + ' recovered'
        return '⚠️ ' + name + (' remains high' if 'STILL HIGH' in event else ' is high')
    return first


def format_alert(config, text, now=None):
    # Bound untrusted text before escaping, so truncation never breaks HTML tags.
    text = str(text)
    if len(text) > 3000:
        text = text[:2900].rsplit('\n', 1)[0] + '\n… Details shortened; see the VPS logs.'
    lines = text.splitlines() or ['Server notification']
    first = lines.pop(0)
    title = friendly_title(first)
    if len(title) > 160:
        split = title.rfind(' ', 0, 150)
        split = split if split > 0 else 150
        lines.insert(0, title[split:].strip())
        title = title[:split] + '…'
    blocks = ['<b>' + escape(title) + '</b>',
              '<code>' + escape(str(config['name'])[:96]) + '</code>', '']
    metrics = []
    def flush_metrics():
        if metrics:
            blocks.append('<pre>' + escape('\n'.join(metrics)) + '</pre>')
            blocks.append('')
            metrics.clear()
    for line in lines:
        match = METRIC.fullmatch(line)
        if match:
            label, number, unit = match.groups()
            value = number + ('%' if unit == '%' else ' ' + unit)
            metrics.append('%-12s %s' % (LABELS[label], value))
            continue
        flush_metrics()
        package = re.fullmatch(r'([a-zA-Z0-9.+:_-]+): (.+) → (.+)', line)
        if package:
            name, old, new = package.groups()
            blocks += ['<b>• ' + escape(name) + '</b>',
                       '<code>' + escape(old + ' → ' + new) + '</code>']
            continue
        label, colon, value = line.partition(':')
        if colon and label in BOLD_LABELS:
            blocks.append('<b>' + escape(label) + ':</b>' + escape(value))
        elif line.startswith(('sudo ', 'python3 ', '/usr/bin/python3 ')):
            blocks.append('<code>' + escape(line) + '</code>')
        else:
            blocks.append(escape(line))
    flush_metrics()
    while blocks and not blocks[-1]:
        blocks.pop()
    stamp = (now or datetime.now(CAMBODIA)).astimezone(CAMBODIA)
    blocks += ['', '<i>' + stamp.strftime('%d %b · %H:%M') + ' Cambodia</i>']
    compact = []
    for block in blocks:
        if block or not compact or compact[-1]:
            compact.append(block)
    return '\n'.join(compact)
