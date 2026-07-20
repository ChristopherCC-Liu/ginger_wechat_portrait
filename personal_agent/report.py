"""Self-contained aggregate dashboard for language-emotion cycle output."""

from __future__ import annotations

import html
from typing import Any, Dict, List, Sequence


def _number(value: Any, digits: int = 2) -> str:
    if value is None:
        return "--"
    return f"{float(value):.{digits}f}"


def _polyline(
    rows: Sequence[Dict[str, Any]], metric: str, width: int, height: int
) -> str:
    if not rows:
        return ""
    left, right, top, bottom = 42, 16, 16, 28
    plot_width = width - left - right
    plot_height = height - top - bottom
    points: List[str] = []
    for index, row in enumerate(rows):
        x = left + (index / max(1, len(rows) - 1)) * plot_width
        value = float(row["metrics"][metric])
        normalized = (value + 1.0) / 2.0 if metric == "valence" else value
        y = top + (1.0 - max(0.0, min(1.0, normalized))) * plot_height
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def _timeline_svg(daily: Sequence[Dict[str, Any]]) -> str:
    rows = list(daily[-90:])
    if not rows:
        return '<div class="empty">暂无可用日数据</div>'
    width, height = 960, 244
    valence = _polyline(rows, "valence", width, height)
    tension = _polyline(rows, "tension", width, height)
    first_date = html.escape(rows[0]["date"])
    last_date = html.escape(rows[-1]["date"])
    anomaly_dots = []
    left, right, top, bottom = 42, 16, 16, 28
    plot_width = width - left - right
    plot_height = height - top - bottom
    for index, row in enumerate(rows):
        if not row.get("anomaly_flags"):
            continue
        x = left + (index / max(1, len(rows) - 1)) * plot_width
        normalized = (float(row["metrics"]["valence"]) + 1.0) / 2.0
        y = top + (1.0 - max(0.0, min(1.0, normalized))) * plot_height
        anomaly_dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" />')
    return f"""
<svg class="timeline" viewBox="0 0 {width} {height}" role="img" aria-label="近 90 个观测日的语言效价与紧张度趋势">
  <line class="grid" x1="42" y1="16" x2="944" y2="16" />
  <line class="grid" x1="42" y1="116" x2="944" y2="116" />
  <line class="grid" x1="42" y1="216" x2="944" y2="216" />
  <text class="axis" x="8" y="20">高</text>
  <text class="axis" x="8" y="120">中</text>
  <text class="axis" x="8" y="220">低</text>
  <polyline class="line-valence" points="{valence}" />
  <polyline class="line-tension" points="{tension}" />
  <g class="anomaly">{"".join(anomaly_dots)}</g>
  <text class="axis" x="42" y="240">{first_date}</text>
  <text class="axis axis-end" x="944" y="240">{last_date}</text>
</svg>
"""


def _weekday_rows(cycle: Sequence[Dict[str, Any]]) -> str:
    rows = []
    for item in cycle:
        valence = float(item["metrics"]["valence"])
        tension = float(item["metrics"]["tension"])
        valence_width = max(2.0, min(100.0, (valence + 1.0) * 50.0))
        tension_width = max(2.0, min(100.0, tension * 100.0))
        rows.append(
            f"""
<div class="weekday-row">
  <div class="weekday-name">{html.escape(item["weekday"])}</div>
  <div class="bar-stack">
    <div class="bar-track"><span class="bar valence" style="width:{valence_width:.1f}%"></span></div>
    <div class="bar-track"><span class="bar tension" style="width:{tension_width:.1f}%"></span></div>
  </div>
  <div class="weekday-value">{_number(valence)} / {_number(tension)}</div>
  <div class="weekday-days">{int(item["valid_day_count"])} 天</div>
</div>
"""
        )
    return "".join(rows) or '<div class="empty">有效日不足，暂不形成星期周期</div>'


def _hour_cells(cycle: Sequence[Dict[str, Any]]) -> str:
    by_hour = {int(item["hour"]): item for item in cycle}
    max_share = max((float(item["message_share"]) for item in cycle), default=0.0)
    cells = []
    for hour in range(24):
        item = by_hour.get(hour)
        count = int(item["message_count"]) if item else 0
        share = float(item["message_share"]) if item else 0.0
        intensity = share / max_share if max_share else 0.0
        alpha = 0.08 + intensity * 0.72
        foreground = "#ffffff" if intensity >= 0.62 else "#17342f"
        cells.append(
            f'<div class="hour-cell" style="background:rgba(12,129,118,{alpha:.3f});color:{foreground}" '
            f'title="{hour:02d}:00 · {count} 条 · {share:.1%}">'
            f"<span>{hour:02d}</span><strong>{share:.1%}</strong></div>"
        )
    return "".join(cells)


def _latest_rows(daily: Sequence[Dict[str, Any]]) -> str:
    rows = []
    for item in reversed(daily[-14:]):
        flags = item.get("anomaly_flags", [])
        anomaly = (
            "、".join(f"{flag['metric']} {flag['direction']}" for flag in flags) or "无"
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['date'])}</td>"
            f"<td>{int(item['message_count'])}</td>"
            f"<td>{_number(item['metrics']['valence'])}</td>"
            f"<td>{_number(item['metrics']['tension'])}</td>"
            f"<td>{_number(item['metrics']['warmth'])}</td>"
            f'<td><span class="confidence {html.escape(item["confidence_label"])}">'
            f"{html.escape(item['confidence_label'])} · {_number(item['confidence'])}</span></td>"
            f"<td>{html.escape(anomaly)}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_dashboard(
    emotion_cycle: Dict[str, Any],
    manifest: Dict[str, Any],
    policy: Dict[str, Any],
) -> str:
    summary = emotion_cycle["summary"]
    daily = emotion_cycle["daily"]
    latest = daily[-1] if daily else None
    latest_metrics = latest["metrics"] if latest else {}
    anomaly_count = sum(len(row.get("anomaly_flags", [])) for row in daily)
    send_state = "关闭" if not policy.get("transport_send_allowed") else "开启"
    created = html.escape(manifest["created_at"])
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'none'; base-uri 'none'; form-action 'none'">
<title>Ginger Personal Agent · 语言情绪周期</title>
<style>
:root{{--bg:#f3f6f4;--surface:#fff;--ink:#17211d;--muted:#62716a;--line:#dce4e0;--teal:#0c8176;--coral:#d95f45;--amber:#d39a16;--blue:#3272b8}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;letter-spacing:0}}
header{{background:#15251f;color:#fff;border-bottom:4px solid var(--teal)}} .header-inner{{max-width:1240px;margin:auto;padding:22px 28px;display:flex;justify-content:space-between;gap:24px;align-items:center}}
h1{{font-size:22px;margin:0 0 4px;font-weight:720}} .subtitle{{font-size:13px;color:#bfd0c8}} .mode{{border:1px solid #537269;padding:7px 10px;border-radius:5px;font-size:12px;white-space:nowrap}}
main{{max-width:1240px;margin:0 auto;padding:24px 28px 44px}} .kpis{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}}
.kpi,.panel{{background:var(--surface);border:1px solid var(--line);border-radius:6px}} .kpi{{padding:16px 18px;min-height:104px}} .kpi-label{{color:var(--muted);font-size:12px}} .kpi strong{{display:block;font-size:28px;margin-top:12px;font-variant-numeric:tabular-nums}} .kpi small{{display:block;color:var(--muted);font-size:11px;margin-top:4px}}
.layout{{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,.85fr);gap:16px}} .panel{{padding:18px;margin-bottom:16px;overflow:hidden}} .panel h2{{font-size:15px;margin:0 0 5px}} .panel-note{{font-size:12px;color:var(--muted);margin-bottom:14px}}
.legend{{display:flex;gap:18px;align-items:center;font-size:11px;color:var(--muted);margin-bottom:4px}} .legend i{{width:16px;height:3px;display:inline-block;margin-right:5px;vertical-align:middle}} .legend .v{{background:var(--teal)}} .legend .t{{background:var(--coral)}} .legend .a{{background:var(--amber);height:8px;width:8px;border-radius:50%}}
.timeline{{display:block;width:100%;height:auto;min-height:180px}} .grid{{stroke:#dce4e0;stroke-width:1}} .axis{{font-size:10px;fill:#75837d}} .axis-end{{text-anchor:end}} .line-valence,.line-tension{{fill:none;stroke-width:2.4;stroke-linejoin:round;stroke-linecap:round}} .line-valence{{stroke:var(--teal)}} .line-tension{{stroke:var(--coral)}} .anomaly circle{{fill:var(--amber);stroke:#fff;stroke-width:2}}
.weekday-row{{display:grid;grid-template-columns:42px minmax(90px,1fr) 92px 48px;gap:10px;align-items:center;margin:11px 0;font-size:12px}} .bar-stack{{display:grid;gap:4px}} .bar-track{{height:5px;background:#edf1ef;border-radius:2px;overflow:hidden}} .bar{{display:block;height:100%}} .bar.valence{{background:var(--teal)}} .bar.tension{{background:var(--coral)}} .weekday-value{{font-variant-numeric:tabular-nums;color:var(--muted);text-align:right}} .weekday-days{{color:var(--muted);text-align:right}}
.hours{{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:6px}} .hour-cell{{aspect-ratio:1.35;border-radius:4px;padding:7px;display:flex;flex-direction:column;justify-content:space-between;min-width:0}} .hour-cell span{{font-size:10px}} .hour-cell strong{{font-size:12px;font-variant-numeric:tabular-nums}}
.latest{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}} .metric{{border-left:3px solid var(--line);padding:8px 10px}} .metric:nth-child(1){{border-color:var(--teal)}} .metric:nth-child(2){{border-color:var(--coral)}} .metric:nth-child(3){{border-color:var(--blue)}} .metric span{{display:block;color:var(--muted);font-size:11px}} .metric strong{{display:block;font-size:20px;margin-top:4px}}
.table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse;font-size:12px;min-width:760px}} th,td{{padding:9px 8px;border-bottom:1px solid var(--line);text-align:right;font-variant-numeric:tabular-nums}} th:first-child,td:first-child,th:last-child,td:last-child{{text-align:left}} th{{color:var(--muted);font-weight:600;background:#f8faf9}} .confidence{{font-size:11px}} .confidence.high{{color:var(--teal)}} .confidence.medium{{color:#956d0e}} .confidence.low{{color:var(--coral)}}
.method{{font-size:12px;line-height:1.75;color:#3f4d47}} .method strong{{color:var(--ink)}} .empty{{padding:28px 0;color:var(--muted);text-align:center}} footer{{max-width:1240px;margin:0 auto;padding:0 28px 28px;color:var(--muted);font-size:11px}}
@media(max-width:900px){{.kpis{{grid-template-columns:repeat(2,minmax(0,1fr))}}.layout{{grid-template-columns:1fr}}}} @media(max-width:560px){{.header-inner{{padding:18px;align-items:flex-start}}main{{padding:16px 12px 32px}}.kpis{{grid-template-columns:1fr 1fr;gap:8px}}.kpi{{padding:13px;min-height:92px}}.kpi strong{{font-size:22px}}.panel{{padding:14px}}.hours{{grid-template-columns:repeat(6,minmax(0,1fr))}}.weekday-row{{grid-template-columns:38px minmax(70px,1fr) 80px}}.weekday-days{{display:none}}.latest{{grid-template-columns:1fr 1fr 1fr}}}}
</style>
</head>
<body>
<header><div class="header-inner"><div><h1>Ginger Personal Agent</h1><div class="subtitle">语言情绪周期 · 聚合数据 · 本地状态</div></div><div class="mode">外发能力：{send_state}</div></div></header>
<main>
<section class="kpis">
  <div class="kpi"><span class="kpi-label">自写文本消息</span><strong>{int(summary["outbound_text_messages"]):,}</strong><small>仅分析 outbound text</small></div>
  <div class="kpi"><span class="kpi-label">观测日 / 有效日</span><strong>{int(summary["observed_days"])} / {int(summary["valid_trend_days"])}</strong><small>{html.escape(str(summary["first_date"]))} 至 {html.escape(str(summary["last_date"]))}</small></div>
  <div class="kpi"><span class="kpi-label">累计异常标记</span><strong>{anomaly_count}</strong><small>robust z ≥ 2.5，非诊断结论</small></div>
  <div class="kpi"><span class="kpi-label">数据联系人</span><strong>{int(manifest["contact_count"])}</strong><small>只用于聚合，不展示姓名</small></div>
</section>
<div class="layout"><div>
  <section class="panel"><h2>近 90 个观测日</h2><div class="panel-note">效价范围 -1..1；紧张度范围 0..1。黄点表示有异常指标的日期。</div><div class="legend"><span><i class="v"></i>语言效价</span><span><i class="t"></i>紧张度</span><span><i class="a"></i>异常</span></div>{_timeline_svg(daily)}</section>
  <section class="panel"><h2>最近 14 个观测日</h2><div class="panel-note">低置信度记录保留展示，但不进入趋势判断。</div><div class="table-wrap"><table><thead><tr><th>日期</th><th>消息</th><th>效价</th><th>紧张</th><th>温暖</th><th>置信度</th><th>异常</th></tr></thead><tbody>{_latest_rows(daily)}</tbody></table></div></section>
</div><aside>
  <section class="panel"><h2>最近观测日</h2><div class="panel-note">{html.escape(latest["date"]) if latest else "--"} · confidence {_number(latest["confidence"]) if latest else "--"}</div><div class="latest"><div class="metric"><span>效价</span><strong>{_number(latest_metrics.get("valence"))}</strong></div><div class="metric"><span>紧张</span><strong>{_number(latest_metrics.get("tension"))}</strong></div><div class="metric"><span>温暖</span><strong>{_number(latest_metrics.get("warmth"))}</strong></div></div></section>
  <section class="panel"><h2>星期周期</h2><div class="panel-note">语言效价 / 紧张度 · 只含有效日</div>{_weekday_rows(emotion_cycle["weekday_cycle"])}</section>
  <section class="panel"><h2>小时分布</h2><div class="panel-note">每格为该小时占全部自写文本消息的比例</div><div class="hours">{_hour_cells(emotion_cycle["hourly_cycle"])}</div></section>
  <section class="panel method"><h2>解释边界</h2><p><strong>这是语言代理指标，不是人的真实情绪。</strong>反讽、引用、联系人关系和表达习惯都会改变分数。逐日默认至少 5 条、40 字且置信度不低于 0.45 才进入趋势；基线为此前 28 天中至少 7 个有效日。</p><p>情绪结果不得触发发送、承诺或权限提升，只能建议降速、人工复核或补充上下文。</p></section>
</aside></div>
</main>
<footer>生成于 {created} · schema {html.escape(emotion_cycle["schema"])} · 原始聊天正文未嵌入此报告</footer>
</body></html>
"""
