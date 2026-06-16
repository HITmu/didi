"""应急响应 Web 仪表盘。

提供 HTML 页面和 JSON API 的 FastAPI 应用。

用法：
    python -m incident_response.web.app
    # 或者
    uvicorn incident_response.web.app:app --host 0.0.0.0 --port 8080
"""

import os
import sys
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

_project_root = str(Path(__file__).parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from incident_response.disposition import DispositionEngine
from incident_response.health_tracker import HealthTracker
from incident_response.knowledge_internalizer import KnowledgeInternalizer
from incident_response.report_generator import SecurityReportGenerator
from incident_response.enterprise_knowledge import EnterpriseKnowledgeBase
from incident_response.knowledge_graph import KnowledgeGraph
from incident_response.traceability import TraceabilityAnalyzer
from incident_response.nlg_explainer import NlgExplainer
from incident_response import person_binding as pb

# ---- 单例 ----
engine = DispositionEngine()
health_tracker = HealthTracker()
knowledge_internalizer = KnowledgeInternalizer()

# ---- 模板 / 静态文件设置 ----
_web_dir = Path(__file__).parent
_templates = Jinja2Templates(directory=str(_web_dir / "templates"))

app = FastAPI(title="Incident Response Dashboard", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(_web_dir / "static")), name="static")


# ==================== 辅助函数 ====================

def _resolve_person(binding: dict) -> dict:
    person = pb.find_person(binding.get("person_id", ""))
    binding["person_name"] = person.name if person else "Unknown"
    return binding


# ==================== HTML 页面 ====================

@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")

@app.get("/dashboard")
async def dashboard_page(request: Request):
    return _templates.TemplateResponse("dashboard.html", {"request": request, "active_page": "dashboard"})

@app.get("/health")
async def health_page(request: Request):
    return _templates.TemplateResponse("health.html", {"request": request, "active_page": "health"})

@app.get("/incidents")
async def incidents_page(request: Request):
    return _templates.TemplateResponse("incidents.html", {"request": request, "active_page": "incidents"})

@app.get("/persons")
async def persons_page(request: Request):
    return _templates.TemplateResponse("persons.html", {"request": request, "active_page": "persons"})

@app.get("/knowledge")
async def knowledge_page(request: Request):
    return _templates.TemplateResponse("knowledge.html", {"request": request, "active_page": "knowledge"})

@app.get("/enterprise-knowledge")
async def enterprise_knowledge_page(request: Request):
    return _templates.TemplateResponse("enterprise_knowledge.html", {"request": request, "active_page": "enterprise_knowledge"})

@app.get("/report")
async def report_page(request: Request):
    return _templates.TemplateResponse("report.html", {"request": request, "active_page": "report"})

@app.get("/graph")
async def graph_page(request: Request):
    return _templates.TemplateResponse("graph.html", {"request": request, "active_page": "graph"})

@app.get("/traceability")
async def traceability_page(request: Request):
    return _templates.TemplateResponse("traceability.html", {"request": request, "active_page": "traceability"})

@app.get("/crawler")
async def crawler_page(request: Request):
    return _templates.TemplateResponse("crawler.html", {"request": request, "active_page": "crawler"})

@app.get("/api/crawler/summary")
async def api_crawler_summary():
    import json, os
    base = os.path.join(_project_root, "malicious_crawler", "results")
    paths = [
        os.path.join(base, "comprehensive_summary.json"),
        os.path.join(base, "pipeline_summary.json"),
    ]
    for p in paths:
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
    return {"error": "no crawler result available"}

@app.exception_handler(404)
async def not_found(request: Request, exc):
    return _templates.TemplateResponse("error.html", {"request": request, "status_code": 404, "message": "Page Not Found", "detail": "The page you requested does not exist."}, status_code=404)


# ==================== API：统计 ====================

@app.get("/api/stats")
async def api_stats():
    try:
        stats = engine.get_summary_stats()
        ks = knowledge_internalizer.get_summary()
        changes = health_tracker.get_all_changes()
        stats["total_knowledge"] = ks.get("total", 0)
        stats["avg_effectiveness"] = ks.get("avg_effectiveness", 0)
        stats["total_health_changes"] = len(changes)
        stats["critical_count"] = stats.get("by_severity", {}).get("CRITICAL", 0)
        return JSONResponse(content=stats)
    except Exception as e:
        return JSONResponse(content={"error": str(e), "total": 0}, status_code=500)


# ==================== API：健康 ====================

@app.get("/api/health/endpoints")
async def api_health_endpoints():
    try:
        endpoints = sorted(set(r.get("api_endpoint", "") for r in health_tracker._load_all()))
        return JSONResponse(content=endpoints)
    except Exception:
        return JSONResponse(content=[])

@app.get("/api/health/trend")
async def api_health_trend(endpoint: str = Query(...), window: int = Query(50, ge=1, le=500)):
    try:
        trend = health_tracker.get_health_trend(endpoint, window)
        all_records = health_tracker._load_all()
        records = [r for r in all_records if r.get("api_endpoint") == endpoint]
        records = records[-window:] if len(records) > window else records
        trend["records"] = records
        return JSONResponse(content=trend)
    except Exception as e:
        return JSONResponse(content={"error": str(e), "status": "unknown"}, status_code=500)

@app.get("/api/health/changes")
async def api_health_changes():
    try:
        return JSONResponse(content=health_tracker.get_all_changes())
    except Exception:
        return JSONResponse(content=[])

@app.post("/api/health/recalculate")
async def api_health_recalculate():
    try:
        return JSONResponse(content=health_tracker.recalculate_all_scores())
    except Exception as e:
        return JSONResponse(content={"error": str(e), "status": "error"}, status_code=500)


# ==================== API：人员 ====================

@app.get("/api/persons")
async def api_list_persons():
    try:
        return JSONResponse(content=[p.to_dict() for p in pb.list_persons()])
    except Exception:
        return JSONResponse(content=[])

@app.post("/api/persons")
async def api_add_person(request: Request):
    try:
        body = await request.json()
        p = pb.add_person(
            name=body.get("name", ""), email=body.get("email", ""),
            phone=body.get("phone", ""), role=body.get("role", "developer"),
        )
        return JSONResponse(content=p.to_dict(), status_code=201)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.put("/api/persons/{person_id}")
async def api_update_person(person_id: str, request: Request):
    try:
        body = await request.json()
        p = pb.update_person(person_id, **{k: v for k, v in body.items() if v is not None})
        if not p:
            raise HTTPException(404, "Person not found")
        return JSONResponse(content=p.to_dict())
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.delete("/api/persons/{person_id}")
async def api_delete_person(person_id: str):
    try:
        return JSONResponse(content={"deleted": pb.delete_person(person_id)})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ==================== API：绑定 ====================

@app.get("/api/bindings")
async def api_list_bindings():
    try:
        return JSONResponse(content=[_resolve_person(b.to_dict()) for b in pb.list_bindings()])
    except Exception:
        return JSONResponse(content=[])

@app.post("/api/bindings")
async def api_add_binding(request: Request):
    try:
        body = await request.json()
        b = pb.add_binding(
            api_pattern=body.get("api_pattern", ""),
            person_id=body.get("person_id", ""),
            priority=body.get("priority", 0),
            description=body.get("description", ""),
        )
        if not b:
            raise HTTPException(400, "Person not found")
        return JSONResponse(content=_resolve_person(b.to_dict()), status_code=201)
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.delete("/api/bindings/{binding_id}")
async def api_delete_binding(binding_id: str):
    try:
        return JSONResponse(content={"deleted": pb.remove_binding(binding_id)})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ==================== API：知识 ====================

@app.get("/api/knowledge")
async def api_list_knowledge():
    try:
        return JSONResponse(content=[k.to_dict() for k in knowledge_internalizer.get_all()])
    except Exception:
        return JSONResponse(content=[])

@app.get("/api/knowledge/search")
async def api_search_knowledge(
    api: Optional[str] = Query(None),
    incident_type: Optional[str] = Query(None),
    min_effectiveness: float = Query(0.0, ge=0.0, le=1.0),
):
    try:
        entries = knowledge_internalizer.search(
            api_endpoint=api, incident_type=incident_type, min_effectiveness=min_effectiveness,
        )
        return JSONResponse(content=[k.to_dict() for k in entries])
    except Exception:
        return JSONResponse(content=[])

@app.get("/api/knowledge/summary")
async def api_knowledge_summary():
    try:
        return JSONResponse(content=knowledge_internalizer.get_summary())
    except Exception:
        return JSONResponse(content={"total": 0})

@app.get("/api/knowledge/rag-context")
async def api_knowledge_rag_context(
    api: str = Query(...), incident_type: str = Query(...),
):
    try:
        context = knowledge_internalizer.build_rag_context(api_endpoint=api, incident_type=incident_type)
        entries = knowledge_internalizer.search(api_endpoint=api, incident_type=incident_type)
        return JSONResponse(content={"context": context, "entry_count": len(entries)})
    except Exception as e:
        return JSONResponse(content={"context": "Error building context", "entry_count": 0}, status_code=500)


# ==================== API：企业知识 ====================

@app.get("/api/enterprise-knowledge")
async def api_ek_list():
    try:
        return JSONResponse(content=[e.to_dict() for e in _enterprise_kb.get_all()])
    except Exception:
        return JSONResponse(content=[])

@app.get("/api/enterprise-knowledge/search")
async def api_ek_search(
    query: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    min_effectiveness: float = Query(0.0, ge=0.0, le=1.0),
    endpoint: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    try:
        entries = _enterprise_kb.search(
            query=query, category=category,
            tags=[tag] if tag else None,
            min_effectiveness=min_effectiveness,
            endpoint=endpoint, severity=severity,
        )
        return JSONResponse(content=[e.to_dict() for e in entries])
    except Exception:
        return JSONResponse(content=[])

@app.get("/api/enterprise-knowledge/get")
async def api_ek_get(id: str = Query(...)):
    try:
        entry = _enterprise_kb.get_entry(id)
        if not entry:
            return JSONResponse(content={"error": "Not found"}, status_code=404)
        return JSONResponse(content=entry.to_dict())
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/api/enterprise-knowledge")
async def api_ek_add(request: Request):
    try:
        body = await request.json()
        from incident_response.models import EnterpriseKnowledgeEntry
        import uuid
        tags = body.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        entry = EnterpriseKnowledgeEntry(
            id=uuid.uuid4().hex[:12],
            title=body.get("title", ""),
            content=body.get("content", ""),
            category=body.get("category", "best_practice"),
            source_type="manual",
            tags=tags,
            severity=body.get("severity", "MEDIUM"),
            remediation=body.get("remediation", ""),
            affected_endpoints=body.get("affected_endpoints", []),
        )
        _enterprise_kb.add_entry(entry)
        return JSONResponse(content=entry.to_dict(), status_code=201)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

@app.delete("/api/enterprise-knowledge/{entry_id}")
async def api_ek_delete(entry_id: str):
    try:
        return JSONResponse(content={"deleted": _enterprise_kb.delete_entry(entry_id)})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/api/enterprise-knowledge/stats")
async def api_ek_stats():
    try:
        return JSONResponse(content=_enterprise_kb.get_stats())
    except Exception:
        return JSONResponse(content={"total": 0, "status": "error"})

@app.post("/api/enterprise-knowledge/rebuild")
async def api_ek_rebuild():
    try:
        return JSONResponse(content=_enterprise_kb.rebuild_from_sources())
    except Exception as e:
        return JSONResponse(content={"error": str(e), "created": 0, "skipped": 0}, status_code=500)

@app.post("/api/enterprise-knowledge/seed")
async def api_ek_seed():
    try:
        return JSONResponse(content={"seeded": _enterprise_kb.seed_default_policies()})
    except Exception as e:
        return JSONResponse(content={"error": str(e), "seeded": 0}, status_code=500)

@app.get("/api/enterprise-knowledge/context")
async def api_ek_context(
    incident_types: Optional[str] = Query(None),
    endpoints: Optional[str] = Query(None),
    severities: Optional[str] = Query(None),
):
    try:
        it = [t.strip() for t in incident_types.split(",") if t.strip()] if incident_types else None
        eps = [e.strip() for e in endpoints.split(",") if e.strip()] if endpoints else None
        sevs = [s.strip() for s in severities.split(",") if s.strip()] if severities else None
        ctx = _enterprise_kb.build_rag_context(incident_types=it, endpoints=eps, severities=sevs)
        data = _enterprise_kb.query_for_report(incident_types=it, endpoints=eps, severities=sevs)
        return JSONResponse(content={"context": ctx, "entries": data.get("entries", 0)})
    except Exception as e:
        return JSONResponse(content={"context": "", "entries": 0, "error": str(e)}, status_code=500)


# ==================== API：事件 ====================

@app.get("/api/incidents")
async def api_list_incidents(
    api: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        return JSONResponse(content=engine.get_incident_history(api_endpoint=api, severity=severity, limit=limit))
    except Exception:
        return JSONResponse(content=[])

@app.get("/api/incidents/stats")
async def api_incidents_stats():
    try:
        return JSONResponse(content=engine.get_summary_stats())
    except Exception:
        return JSONResponse(content={"total": 0})


# ==================== API：图谱 ====================

_enterprise_kb = EnterpriseKnowledgeBase()

_graph = KnowledgeGraph()

@app.get("/api/graph/stats")
async def api_graph_stats():
    try:
        _graph.build()
        return JSONResponse(content=_graph.get_statistics())
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/api/graph/related")
async def api_graph_related(entity: str = Query(...), hops: int = Query(2, ge=1, le=5)):
    try:
        _graph.build()
        return JSONResponse(content=_graph.get_related(entity, max_hops=hops))
    except Exception as e:
        return JSONResponse(content={"error": str(e), "nodes": [], "edges": []}, status_code=500)

@app.get("/api/graph/export")
async def api_graph_export():
    try:
        _graph.build()
        return JSONResponse(content=_graph.to_cytoscape())
    except Exception as e:
        return JSONResponse(content={"error": str(e), "elements": []}, status_code=500)

@app.get("/api/graph/impact")
async def api_graph_impact(api: str = Query(...)):
    try:
        _graph.build()
        return JSONResponse(content=_graph.get_impact_analysis(api))
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ==================== API：报告 ====================

_report_generator = SecurityReportGenerator()

@app.get("/api/report")
async def api_report():
    try:
        return JSONResponse(content=_report_generator.generate())
    except Exception as e:
        return JSONResponse(content={"error": str(e), "executive_summary": {"total_incidents": 0, "status": "error"}}, status_code=500)


# ==================== API：溯源 ====================

_trace = TraceabilityAnalyzer()

@app.get("/api/traceability/timeline")
async def api_trace_timeline(api: str = Query(None)):
    try:
        return JSONResponse(content=_trace.analyze_api_timeline(api_endpoint=api))
    except Exception as e:
        return JSONResponse(content={"status": "error", "error": str(e)}, status_code=500)

@app.get("/api/traceability/patterns")
async def api_trace_patterns():
    try:
        return JSONResponse(content=_trace.analyze_attack_patterns())
    except Exception as e:
        return JSONResponse(content={"status": "error", "error": str(e)}, status_code=500)

@app.get("/api/traceability/trace")
async def api_trace_path(id: str = Query(None)):
    try:
        return JSONResponse(content=_trace.trace_attack_path(incident_id=id))
    except Exception as e:
        return JSONResponse(content={"status": "error", "error": str(e)}, status_code=500)

@app.get("/api/traceability/correlate")
async def api_trace_correlate():
    try:
        return JSONResponse(content=_trace.correlation_analysis())
    except Exception as e:
        return JSONResponse(content={"status": "error", "error": str(e)}, status_code=500)


# ==================== API：NLG 解释 ====================

_explainer = NlgExplainer()

@app.get("/api/explain/incident")
async def api_explain_incident(id: str = Query(...)):
    try:
        incidents = engine.get_incident_history()
        incident = next((i for i in incidents if i.get("id", "").startswith(id)), None)
        if not incident:
            return JSONResponse(content={"error": "Incident not found"}, status_code=404)
        return JSONResponse(content={
            "explanation": _explainer.explain_disposition(incident),
            "recommendation": _explainer.generate_recommendation(incident),
            "summary": _explainer.generate_incident_summary(incident),
        })
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ==================== 入口 ====================

def main():
    print("  IR Dashboard → http://0.0.0.0:8080/dashboard")
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")

if __name__ == "__main__":
    main()
