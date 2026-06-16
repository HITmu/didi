"""应急响应系统的命令行接口入口点。

用法：
    # 人员管理
    python -m incident_response.cli person list
    python -m incident_response.cli person add <name> <email> [--phone <phone>] [--role <role>]
    python -m incident_response.cli person delete <person_id>

    # 绑定管理
    python -m incident_response.cli binding list
    python -m incident_response.cli binding add <api_pattern> <person_id> [--priority <n>] [--desc <text>]
    python -m incident_response.cli binding remove <binding_id>

    # 事件管理
    python -m incident_response.cli incidents list [--api <endpoint>] [--severity <sev>]
    python -m incident_response.cli incidents stats

    # 健康追踪
    python -m incident_response.cli health trend <api_endpoint>

    # 知识
    python -m incident_response.cli knowledge search [--api <endpoint>] [--type <incident_type>]
    python -m incident_response.cli knowledge context <api_endpoint> <incident_type>
    python -m incident_response.cli knowledge stats
"""

import sys
import argparse

from .person_binding import (
    list_persons, add_person, delete_person,
    list_bindings, add_binding, remove_binding,
    print_bindings_table
)
from .disposition import DispositionEngine
from .health_tracker import HealthTracker
from .knowledge_internalizer import KnowledgeInternalizer
from .report_generator import SecurityReportGenerator
from .enterprise_knowledge import EnterpriseKnowledgeBase
from .knowledge_graph import KnowledgeGraph
from .traceability import TraceabilityAnalyzer
from .nlg_explainer import NlgExplainer


def build_parser():
    parser = argparse.ArgumentParser(
        description="Incident Response System CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- 人员 ----
    p_person = sub.add_parser("person")
    p_person_sub = p_person.add_subparsers(dest="action", required=True)

    p_person_list = p_person_sub.add_parser("list")
    p_person_list.set_defaults(func=cmd_person_list)

    p_person_add = p_person_sub.add_parser("add")
    p_person_add.add_argument("name")
    p_person_add.add_argument("email")
    p_person_add.add_argument("--phone", default="")
    p_person_add.add_argument("--role", default="developer")
    p_person_add.set_defaults(func=cmd_person_add)

    p_person_del = p_person_sub.add_parser("delete")
    p_person_del.add_argument("person_id")
    p_person_del.set_defaults(func=cmd_person_delete)

    # ---- 绑定 ----
    p_binding = sub.add_parser("binding")
    p_binding_sub = p_binding.add_subparsers(dest="action", required=True)

    p_binding_list = p_binding_sub.add_parser("list")
    p_binding_list.set_defaults(func=cmd_binding_list)

    p_binding_add = p_binding_sub.add_parser("add")
    p_binding_add.add_argument("api_pattern")
    p_binding_add.add_argument("person_id")
    p_binding_add.add_argument("--priority", type=int, default=0)
    p_binding_add.add_argument("--desc", default="")
    p_binding_add.set_defaults(func=cmd_binding_add)

    p_binding_rem = p_binding_sub.add_parser("remove")
    p_binding_rem.add_argument("binding_id")
    p_binding_rem.set_defaults(func=cmd_binding_remove)

    # ---- 事件 ----
    p_inc = sub.add_parser("incidents")
    p_inc_sub = p_inc.add_subparsers(dest="action", required=True)

    p_inc_list = p_inc_sub.add_parser("list")
    p_inc_list.add_argument("--api", default=None)
    p_inc_list.add_argument("--severity", default=None)
    p_inc_list.set_defaults(func=cmd_incidents_list)

    p_inc_stats = p_inc_sub.add_parser("stats")
    p_inc_stats.set_defaults(func=cmd_incidents_stats)

    # ---- 健康 ----
    p_health = sub.add_parser("health")
    p_health_sub = p_health.add_subparsers(dest="action", required=True)

    p_health_trend = p_health_sub.add_parser("trend")
    p_health_trend.add_argument("api_endpoint")
    p_health_trend.set_defaults(func=cmd_health_trend)

    p_health_recalc = p_health_sub.add_parser("recalculate")
    p_health_recalc.set_defaults(func=cmd_health_recalculate)

    # ---- 知识 ----
    p_know = sub.add_parser("knowledge")
    p_know_sub = p_know.add_subparsers(dest="action", required=True)

    p_know_search = p_know_sub.add_parser("search")
    p_know_search.add_argument("--api", default=None)
    p_know_search.add_argument("--type", default=None)
    p_know_search.set_defaults(func=cmd_knowledge_search)

    p_know_ctx = p_know_sub.add_parser("context")
    p_know_ctx.add_argument("api_endpoint")
    p_know_ctx.add_argument("incident_type")
    p_know_ctx.set_defaults(func=cmd_knowledge_context)

    p_know_stats = p_know_sub.add_parser("stats")
    p_know_stats.set_defaults(func=cmd_knowledge_stats)

    # ---- 报告 ----
    p_report = sub.add_parser("report")
    p_report_sub = p_report.add_subparsers(dest="action", required=True)

    p_report_gen = p_report_sub.add_parser("generate")
    p_report_gen.set_defaults(func=cmd_report_generate)

    p_report_save = p_report_sub.add_parser("save")
    p_report_save.add_argument("--output", "-o", default=None, help="Output file path")
    p_report_save.set_defaults(func=cmd_report_save)

    # ---- 图谱 ----
    p_graph = sub.add_parser("graph")
    p_graph_sub = p_graph.add_subparsers(dest="action", required=True)

    p_graph_stats = p_graph_sub.add_parser("stats")
    p_graph_stats.set_defaults(func=cmd_graph_stats)

    p_graph_query = p_graph_sub.add_parser("query")
    p_graph_query.add_argument("entity", help="Entity ID or fragment (e.g. /orders)")
    p_graph_query.add_argument("--hops", type=int, default=2, help="Traversal depth")
    p_graph_query.set_defaults(func=cmd_graph_query)

    p_graph_path = p_graph_sub.add_parser("path")
    p_graph_path.add_argument("src", help="Source entity fragment")
    p_graph_path.add_argument("dst", help="Destination entity fragment")
    p_graph_path.set_defaults(func=cmd_graph_path)

    p_graph_impact = p_graph_sub.add_parser("impact")
    p_graph_impact.add_argument("api_endpoint", help="API endpoint to analyze")
    p_graph_impact.set_defaults(func=cmd_graph_impact)

    # ---- 溯源 ----
    p_trace = sub.add_parser("trace")
    p_trace_sub = p_trace.add_subparsers(dest="action", required=True)

    p_trace_tl = p_trace_sub.add_parser("timeline")
    p_trace_tl.add_argument("--api", default=None, help="Filter by API endpoint")
    p_trace_tl.set_defaults(func=cmd_trace_timeline)

    p_trace_pt = p_trace_sub.add_parser("patterns")
    p_trace_pt.set_defaults(func=cmd_trace_patterns)

    p_trace_path = p_trace_sub.add_parser("path")
    p_trace_path.add_argument("--id", default=None, help="Incident ID to trace")
    p_trace_path.set_defaults(func=cmd_trace_path)

    p_trace_corr = p_trace_sub.add_parser("correlate")
    p_trace_corr.set_defaults(func=cmd_trace_correlate)

    # ---- 解释 ----
    p_explain = sub.add_parser("explain")
    p_explain_sub = p_explain.add_subparsers(dest="action", required=True)

    p_explain_inc = p_explain_sub.add_parser("incident")
    p_explain_inc.add_argument("incident_id", help="Incident ID to explain")
    p_explain_inc.set_defaults(func=cmd_explain_incident)

    p_explain_last = p_explain_sub.add_parser("last")
    p_explain_last.set_defaults(func=cmd_explain_last)

    # ---- 企业知识 ----
    p_ek = sub.add_parser("enterprise-knowledge", aliases=["ek"])
    p_ek_sub = p_ek.add_subparsers(dest="action", required=True)

    p_ek_list = p_ek_sub.add_parser("list")
    p_ek_list.add_argument("--category", default=None, help="Filter by category")
    p_ek_list.add_argument("--tag", default=None, help="Filter by tag")
    p_ek_list.add_argument("--endpoint", default=None, help="Filter by API endpoint")
    p_ek_list.add_argument("--severity", default=None, help="Filter by severity")
    p_ek_list.set_defaults(func=cmd_ek_list)

    p_ek_search = p_ek_sub.add_parser("search")
    p_ek_search.add_argument("query", help="Search text")
    p_ek_search.add_argument("--category", default=None)
    p_ek_search.add_argument("--tag", default=None)
    p_ek_search.set_defaults(func=cmd_ek_search)

    p_ek_get = p_ek_sub.add_parser("get")
    p_ek_get.add_argument("entry_id", help="Entry ID")
    p_ek_get.set_defaults(func=cmd_ek_get)

    p_ek_add = p_ek_sub.add_parser("add")
    p_ek_add.add_argument("title")
    p_ek_add.add_argument("content")
    p_ek_add.add_argument("--category", default="best_practice",
                          choices=["policy", "case", "pattern", "role_insight", "best_practice"])
    p_ek_add.add_argument("--severity", default="MEDIUM",
                          choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    p_ek_add.add_argument("--tags", default="", help="Comma-separated tags")
    p_ek_add.add_argument("--remediation", default="")
    p_ek_add.set_defaults(func=cmd_ek_add)

    p_ek_del = p_ek_sub.add_parser("delete")
    p_ek_del.add_argument("entry_id")
    p_ek_del.set_defaults(func=cmd_ek_delete)

    p_ek_stats = p_ek_sub.add_parser("stats")
    p_ek_stats.set_defaults(func=cmd_ek_stats)

    p_ek_rebuild = p_ek_sub.add_parser("rebuild")
    p_ek_rebuild.set_defaults(func=cmd_ek_rebuild)

    p_ek_seed = p_ek_sub.add_parser("seed")
    p_ek_seed.set_defaults(func=cmd_ek_seed)

    p_ek_ctx = p_ek_sub.add_parser("context")
    p_ek_ctx.add_argument("--type", dest="incident_type", default=None, help="Incident type filter")
    p_ek_ctx.add_argument("--endpoint", default=None, help="API endpoint filter")
    p_ek_ctx.add_argument("--severity", default=None, help="Severity filter")
    p_ek_ctx.set_defaults(func=cmd_ek_context)

    return parser


def cmd_person_list(args):
    persons = list_persons()
    if not persons:
        print("No persons registered.")
        return
    print(f"{'ID':<10} {'Name':<20} {'Email':<30} {'Role':<15} {'Phone'}")
    print("-" * 85)
    for p in persons:
        print(f"{p.id:<10} {p.name:<20} {p.email:<30} {p.role:<15} {p.phone}")


def cmd_person_add(args):
    p = add_person(
        name=args.name,
        email=args.email,
        phone=args.phone or "",
        role=args.role or "developer",
    )
    print(f"Added person: {p.name} <{p.email}> (id: {p.id})")


def cmd_person_delete(args):
    if delete_person(args.person_id):
        print(f"Deleted person {args.person_id}")
    else:
        print(f"Person {args.person_id} not found")


def cmd_binding_list(args):
    print_bindings_table()


def cmd_binding_add(args):
    b = add_binding(
        api_pattern=args.api_pattern,
        person_id=args.person_id,
        priority=args.priority or 0,
        description=args.desc or "",
    )
    if b:
        print(f"Added binding: {b.api_pattern} -> person {b.person_id} (priority: {b.priority})")
    else:
        print(f"Person {args.person_id} not found, binding not created")


def cmd_binding_remove(args):
    if remove_binding(args.binding_id):
        print(f"Removed binding {args.binding_id}")
    else:
        print(f"Binding {args.binding_id} not found")


def cmd_incidents_list(args):
    engine = DispositionEngine()
    incidents = engine.get_incident_history(
        api_endpoint=args.api,
        severity=args.severity,
    )
    if not incidents:
        print("No incidents found.")
        return
    print(f"{'ID':<14} {'API':<30} {'Severity':<10} {'Disposition':<16} {'Status':<10} {'Time'}")
    print("-" * 110)
    for i in incidents:
        t = i.get("detected_at", "?")[11:19]
        print(f"{i['id']:<14} {i['api_endpoint']:<30} {i['severity']:<10} "
              f"{i['disposition']:<16} {i['disposition_status']:<10} {t}")


def cmd_incidents_stats(args):
    DispositionEngine().print_summary()


def cmd_health_trend(args):
    tracker = HealthTracker()
    trend = tracker.get_health_trend(args.api_endpoint)
    if trend["status"] == "unknown":
        print(f"No health records for {args.api_endpoint}")
        return
    print(f"Health Trend for {args.api_endpoint}")
    print(f"  Current score: {trend['current_score']:.4f}")
    print(f"  Average score: {trend['avg_score']:.4f}")
    print(f"  Min score:     {trend['min_score']:.4f}")
    print(f"  Max score:     {trend['max_score']:.4f}")
    print(f"  Trend:         {trend['trend']}")
    print(f"  Current status: {trend['current_status']}")
    print(f"  Records:       {trend['records_count']}")


def cmd_health_recalculate(args):
    tracker = HealthTracker()
    result = tracker.recalculate_all_scores()
    print(f"Health score recalculation:")
    print(f"  Total records: {result.get('total_records', 0)}")
    print(f"  Updated:       {result.get('updated', 0)}")
    for c in result.get("changes", []):
        print(f"    {c['api_endpoint']} ({c['id']}): {c['old_score']:.4f} → {c['new_score']:.4f}")


def cmd_knowledge_search(args):
    ki = KnowledgeInternalizer()
    results = ki.search(api_endpoint=args.api, incident_type=args.type)
    if not results:
        print("No matching knowledge entries found.")
        return
    print(f"{'ID':<10} {'Type':<20} {'Severity':<10} {'Disposition':<16} {'Health':<12} {'Effectiveness'}")
    print("-" * 85)
    for k in results:
        print(f"{k.id:<10} {k.incident_type:<20} {k.severity:<10} "
              f"{k.disposition_taken:<16} {k.health_impact:<12} {k.effectiveness_score:.4f}")


def cmd_knowledge_context(args):
    ctx = KnowledgeInternalizer().build_rag_context(
        api_endpoint=args.api_endpoint,
        incident_type=args.incident_type,
    )
    print(ctx)


def cmd_knowledge_stats(args):
    stats = KnowledgeInternalizer().get_summary()
    if stats["total"] == 0:
        print("No knowledge internalized yet.")
        return
    print(f"Total knowledge entries: {stats['total']}")
    print(f"By incident type: {stats['by_incident_type']}")
    print(f"By disposition: {stats['by_disposition']}")
    print(f"By health impact: {stats['by_health_impact']}")
    print(f"Average effectiveness: {stats['avg_effectiveness']:.4f}")


def cmd_graph_stats(args):
    kg = KnowledgeGraph()
    kg.build()
    kg.print_summary()


def cmd_graph_query(args):
    kg = KnowledgeGraph()
    kg.build()
    related = kg.get_related(args.entity, max_hops=args.hops)
    if "error" in related:
        print(f"Entity '{args.entity}' not found in graph.")
        return
    print(f"Related to '{related.get('center', args.entity)}' ({len(related['nodes'])} nodes, {len(related['edges'])} edges):")
    for n in related['nodes']:
        print(f"  [{n['type']:16s}] {n['label']}")
    print()
    for e in related['edges']:
        print(f"  {e['source']} --{e.get('type', 'link')}--> {e['target']}")


def cmd_graph_path(args):
    kg = KnowledgeGraph()
    kg.build()
    path = kg.find_path(args.src, args.dst)
    if not path:
        print(f"No path found between '{args.src}' and '{args.dst}'")
        return
    print(f"Path ({len(path)} hops):")
    for i, n in enumerate(path):
        print(f"  {i}: [{n['type']:16s}] {n['label']}")


def cmd_graph_impact(args):
    kg = KnowledgeGraph()
    kg.build()
    impact = kg.get_impact_analysis(args.api_endpoint)
    if impact.get("total_incidents", 0) == 0 and impact.get("health_records_count", 0) == 0:
        print(f"No data found for endpoint '{args.api_endpoint}'")
        return
    print(f"Impact Analysis: {args.api_endpoint}")
    for k, v in impact.items():
        print(f"  {k}: {v}")


def cmd_trace_timeline(args):
    ta = TraceabilityAnalyzer()
    ta.print_timeline(api_endpoint=args.api)


def cmd_trace_patterns(args):
    TraceabilityAnalyzer().print_attack_patterns()


def cmd_trace_path(args):
    ta = TraceabilityAnalyzer()
    result = ta.trace_attack_path(incident_id=args.id)
    if result.get("status") == "not_found":
        print(f"Incident '{args.id}' not found.")
        return
    inc = result.get("incident", {})
    print(f"Attack Path Trace: {inc.get('id', '?')}")
    print(f"  API:       {inc.get('api_endpoint', '?')}")
    print(f"  Severity:  {inc.get('severity', '?')}")
    print(f"  Type:      {inc.get('anomaly_type', '?')}")
    print(f"  Confidence: {inc.get('confidence', 0):.0%}")
    print(f"  Disposition: {inc.get('disposition', '?')}")
    print(f"  Detected:  {inc.get('detected_at', '?')[:19]}")
    print(f"  Reason:    {inc.get('reason', '?')}")
    if result.get("health_impact"):
        print(f"  Health Impact: {len(result['health_impact'])} change(s)")
        for h in result["health_impact"]:
            print(f"    {h.get('api_endpoint', '?')}: {h.get('health_delta', 0):+.4f}")
    if result.get("knowledge_generated"):
        print(f"  Knowledge: {len(result['knowledge_generated'])} entry(ies)")
    if result.get("attack_path_summary"):
        print(f"\n  Summary: {result['attack_path_summary']}")


def cmd_trace_correlate(args):
    ta = TraceabilityAnalyzer()
    result = ta.correlation_analysis()
    if result.get("status") == "no_data":
        print("No incident data for correlation analysis.")
        return
    print(f"Correlation Analysis")
    print(f"  Total incidents: {result['total_incidents']}")
    print(f"  Unique APIs:     {result['unique_apis']}")
    print(f"  Mass attack windows: {result['mass_attack_windows']}")
    if result.get("widespread_attack_types"):
        print(f"  Widespread types:")
        for t, eps in result["widespread_attack_types"].items():
            print(f"    {t}: {', '.join(eps)}")


def cmd_explain_incident(args):
    engine = DispositionEngine()
    incidents = engine.get_incident_history()
    incident = next((i for i in incidents if i.get("id", "").startswith(args.incident_id)), None)
    if not incident:
        print(f"Incident '{args.incident_id}' not found.")
        return
    explainer = NlgExplainer()
    print(f"\n{'='*60}")
    print(f"Incident: {incident.get('id')}")
    print(f"{'='*60}")
    print(f"Explanation:\n  {explainer.explain_disposition(incident)}")
    print(f"\nRecommendation:\n  {explainer.generate_recommendation(incident)}")
    print(f"\nSummary:\n  {explainer.generate_incident_summary(incident)}")


def cmd_explain_last(args):
    engine = DispositionEngine()
    incidents = engine.get_incident_history()
    if not incidents:
        print("No incidents found.")
        return
    cmd_explain_incident(argparse.Namespace(incident_id=incidents[0].get("id", "")))


def cmd_ek_list(args):
    kb = EnterpriseKnowledgeBase()
    entries = kb.search(category=args.category,
                        tags=[args.tag] if args.tag else None,
                        endpoint=args.endpoint, severity=args.severity)
    if not entries:
        print("No enterprise knowledge entries found.")
        return
    print(f"{'ID':<14} {'Category':<14} {'Severity':<10} {'Eff':<6} {'Usage':<6} {'Title'}")
    print("-" * 90)
    for e in entries:
        print(f"{e.id:<14} {e.category:<14} {e.severity:<10} {e.effectiveness_score:<6.2f} {e.usage_count:<6} {e.title[:40]}")


def cmd_ek_search(args):
    kb = EnterpriseKnowledgeBase()
    entries = kb.search(query=args.query, category=args.category,
                        tags=[args.tag] if args.tag else None)
    if not entries:
        print("No matching entries found.")
        return
    print(f"{'ID':<14} {'Category':<14} {'Eff':<6} {'Title'}")
    print("-" * 60)
    for e in entries:
        print(f"{e.id:<14} {e.category:<14} {e.effectiveness_score:<6.2f} {e.title[:50]}")


def cmd_ek_get(args):
    kb = EnterpriseKnowledgeBase()
    e = kb.get_entry(args.entry_id)
    if not e:
        print(f"Entry '{args.entry_id}' not found.")
        return
    print(f"ID:       {e.id}")
    print(f"Title:    {e.title}")
    print(f"Category: {e.category}")
    print(f"Severity: {e.severity}")
    print(f"Source:   {e.source_type}")
    print(f"Effectiveness: {e.effectiveness_score:.2f}")
    print(f"Confidence:    {e.confidence:.2f}")
    print(f"Usage:    {e.usage_count}")
    print(f"Tags:     {', '.join(e.tags)}")
    if e.affected_endpoints:
        print(f"Endpoints: {', '.join(e.affected_endpoints)}")
    print(f"\nContent:\n{e.content}")
    if e.remediation:
        print(f"\nRemediation:\n{e.remediation}")
    print(f"\nCreated: {e.created_at}")
    print(f"Updated: {e.updated_at}")


def cmd_ek_add(args):
    import uuid
    from .models import EnterpriseKnowledgeEntry
    kb = EnterpriseKnowledgeBase()
    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    entry = EnterpriseKnowledgeEntry(
        id=uuid.uuid4().hex[:12],
        title=args.title,
        content=args.content,
        category=args.category,
        source_type="manual",
        tags=tags,
        severity=args.severity,
        remediation=args.remediation,
    )
    kb.add_entry(entry)
    print(f"Added enterprise knowledge entry: {entry.id} ({entry.title})")


def cmd_ek_delete(args):
    kb = EnterpriseKnowledgeBase()
    if kb.delete_entry(args.entry_id):
        print(f"Deleted entry {args.entry_id}")
    else:
        print(f"Entry {args.entry_id} not found")


def cmd_ek_stats(args):
    kb = EnterpriseKnowledgeBase()
    stats = kb.get_stats()
    if stats.get("status") == "no_data":
        print("No enterprise knowledge entries.")
        return
    print(f"Total entries: {stats['total']}")
    print(f"By category:   {stats['by_category']}")
    print(f"By severity:   {stats['by_severity']}")
    print(f"Avg effectiveness: {stats['avg_effectiveness']:.4f}")
    print(f"Total usage:   {stats['total_usage_count']}")


def cmd_ek_rebuild(args):
    kb = EnterpriseKnowledgeBase()
    result = kb.rebuild_from_sources()
    print(f"Rebuild complete: {result['created']} created, {result['updated']} updated, {result['skipped']} skipped")


def cmd_ek_seed(args):
    kb = EnterpriseKnowledgeBase()
    created = kb.seed_default_policies()
    print(f"Seeded {created} new security policies.")


def cmd_ek_context(args):
    kb = EnterpriseKnowledgeBase()
    ctx = kb.build_rag_context(
        incident_types=[args.incident_type] if args.incident_type else None,
        endpoints=[args.endpoint] if args.endpoint else None,
        severities=[args.severity] if args.severity else None,
    )
    if ctx:
        print(ctx)
    else:
        print("No enterprise knowledge context available.")


def cmd_report_generate(args):
    gen = SecurityReportGenerator()
    report = gen.generate()
    print(gen.format_markdown(report))


def cmd_report_save(args):
    gen = SecurityReportGenerator()
    path = gen.save_report(args.output)
    print(f"Report saved to: {path}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
