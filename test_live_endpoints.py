"""
Live HTTP Integration Tests for AI CODING HUB Phase 1 ACP API
Verifies live server endpoints without triggering unwanted background agent side-effects.
"""
import urllib.request
import urllib.error
import json

BASE_URL = "http://127.0.0.1:8000"

def request(path, method="GET", data=None):
    url = BASE_URL + path
    headers = {"Content-Type": "application/json"} if data else {}
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            res_body = res.read().decode("utf-8")
            try:
                parsed = json.loads(res_body)
            except Exception:
                parsed = res_body
            return res.status, parsed
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = err_body
        return e.code, parsed

def run_tests():
    print("--- STARTING LIVE HTTP INTEGRATION TESTS ---")

    # 1. GET /
    status, body = request("/")
    print("[1] GET / ->", status, body)
    assert status == 200
    assert body["status"] == "online"

    # 2. GET /health
    status, body = request("/health")
    print("[2] GET /health ->", status, body)
    assert status == 200
    assert body["status"] == "healthy"

    # 3. GET /dashboard
    status, body = request("/dashboard")
    print("[3] GET /dashboard ->", status, f"HTML length: {len(body)}")
    assert status == 200
    assert "Antigravity ACP Engine" in body
    assert "MANDATORY ACTION APPROVAL REQUIRED" in body
    assert "btnApproveAction" in body

    # 4. GET /static assets
    status, body = request("/static/css/dashboard.css")
    print("[4a] GET /static/css/dashboard.css ->", status, f"CSS length: {len(body)}")
    assert status == 200
    assert "badge-awaiting_action_approval" in body

    status, body = request("/static/js/dashboard.js")
    print("[4b] GET /static/js/dashboard.js ->", status, f"JS length: {len(body)}")
    assert status == 200
    assert "handleResolveActionPermission" in body
    assert "handleCancelTask" in body

    # 5. GET /api/agent/status
    status, body = request("/api/agent/status")
    print("[5] GET /api/agent/status ->", status, body)
    assert status == 200
    assert body["cli_version"] == "1.5.8"
    assert body["cli_exists"] is True
    assert body["approval_required"] is True
    assert body["action_approval_required"] is True
    assert body["protocol"] == "Agent Client Protocol (ACP)"
    assert body["configured_agent"] == "Antigravity ACP (Sole Active Agent)"
    assert body["vscode_bridge_status"] == "Disabled"

    # 6. POST /api/tasks (unauthorized workspace) -> 400
    status, body = request("/api/tasks", method="POST", data={
        "prompt": "Inspect routes",
        "workspace": "C:\\Windows\\System32"
    })
    print("[6] POST /api/tasks (unauthorized workspace) ->", status, body)
    assert status == 400
    assert "Unauthorized workspace" in body["detail"]

    # 6b. POST /api/tasks (disabled agent=vscode) -> 400
    status, body = request("/api/tasks", method="POST", data={
        "prompt": "Inspect routes",
        "workspace": "C:\\Users\\lovel\\Desktop\\AI-CODING-HUB",
        "agent": "vscode"
    })
    print("[6b] POST /api/tasks (disabled agent=vscode) ->", status, body)
    assert status == 400
    assert "Agent 'vscode' is disabled" in body["detail"]

    # 7. POST /api/tasks (valid task) -> 201 Created in PENDING_APPROVAL
    status, task1 = request("/api/tasks", method="POST", data={
        "prompt": "Test Task 1: Check routes",
        "workspace": "C:\\Users\\lovel\\Desktop\\AI-CODING-HUB"
    })
    print("[7] POST /api/tasks (valid) ->", status, task1["id"], "Status:", task1["status"])
    assert status == 201
    assert task1["status"] == "PENDING_APPROVAL"
    t1_id = task1["id"]

    # 8. GET /api/tasks/{task_id} -> 200
    status, t1_details = request(f"/api/tasks/{t1_id}")
    print("[8] GET /api/tasks/{task_id} ->", status, t1_details["id"], t1_details["status"])
    assert status == 200
    assert t1_details["status"] == "PENDING_APPROVAL"

    # 9. POST /api/tasks/{task_id}/reject -> 200
    status, t1_rejected = request(f"/api/tasks/{t1_id}/reject", method="POST", data={"reason": "User declined task"})
    print("[9] POST /api/tasks/{task_id}/reject ->", status, "Status:", t1_rejected["status"])
    assert status == 200
    assert t1_rejected["status"] == "REJECTED"

    # 10. POST /api/tasks/{task_id}/approve on REJECTED task -> 400
    status, body = request(f"/api/tasks/{t1_id}/approve", method="POST")
    print("[10] POST /api/tasks/{task_id}/approve (on rejected task) ->", status, body)
    assert status == 400
    assert "Only 'PENDING_APPROVAL' tasks can be approved" in body["detail"]

    # 11. POST /api/tasks/{task_id}/permission on non-awaiting task -> 400
    status, body = request(f"/api/tasks/{t1_id}/permission", method="POST", data={"decision": "allow_once"})
    print("[11] POST /api/tasks/{task_id}/permission (invalid state) ->", status, body)
    assert status == 400
    assert "Task is not currently awaiting action approval" in body["detail"]

    # 12. POST /api/tasks (valid task 2 for cancel test) -> 201 Created
    status, task2 = request("/api/tasks", method="POST", data={
        "prompt": "Test Task 2: Cancel flow verification",
        "workspace": "C:\\Users\\lovel\\Desktop\\AI-CODING-HUB"
    })
    print("[12] POST /api/tasks (valid task 2) ->", status, task2["id"])
    assert status == 201
    t2_id = task2["id"]

    # 13. POST /api/tasks/{task_id}/cancel -> 200 CANCELLED
    status, t2_cancelled = request(f"/api/tasks/{t2_id}/cancel", method="POST")
    print("[13] POST /api/tasks/{task_id}/cancel ->", status, "Status:", t2_cancelled["status"])
    assert status == 200
    assert t2_cancelled["status"] == "CANCELLED"

    # 14. POST /api/tasks/{task_id}/cancel on already cancelled task -> 400
    status, body = request(f"/api/tasks/{t2_id}/cancel", method="POST")
    print("[14] POST /api/tasks/{task_id}/cancel (repeat) ->", status, body)
    assert status == 400
    assert "already finalized" in body["detail"]

    # 15. GET /api/tasks/{task_id}/logs -> 200 with all ACP fields
    status, logs = request(f"/api/tasks/{t2_id}/logs")
    print("[15] GET /api/tasks/{task_id}/logs ->", status, "Status:", logs["status"])
    assert status == 200
    assert logs["task_id"] == t2_id
    assert "events" in logs
    assert "permission_history" in logs
    assert "pending_permission" in logs

    # 16. GET /api/tasks/{task_id}/stream -> 200 SSE Stream verification
    stream_url = f"{BASE_URL}/api/tasks/{t2_id}/stream"
    req_stream = urllib.request.Request(stream_url)
    with urllib.request.urlopen(req_stream, timeout=5) as sres:
        first_line = sres.readline().decode("utf-8")
        print("[16] GET /api/tasks/{task_id}/stream ->", sres.status, "First chunk:", first_line.strip()[:60])
        assert sres.status == 200
        assert first_line.startswith("data: ")

    print("\n>>> ALL 16 LIVE HTTP INTEGRATION TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run_tests()
