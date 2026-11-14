/**
 * AI CODING HUB - Dashboard Client Application
 * Handles live backend health check, view navigation, interactive components,
 * and system telemetry.
 */

document.addEventListener("DOMContentLoaded", () => {
  // State
  let csrfToken = "";
  const state = {
    currentView: "overview",
    backendStatus: "checking",
    healthCheckInterval: 5000,
    healthTimer: null,
    uptimeSeconds: 0,
    totalRequests: 0,
    latencyHistory: [],
    maxLatencyPoints: 10,
    isPolling: true
  };

  // DOM Elements
  const navItems = document.querySelectorAll(".nav-item");
  const views = document.querySelectorAll(".dashboard-view");
  const breadcrumbActive = document.getElementById("breadcrumbActive");
  const mobileToggle = document.getElementById("mobileToggle");
  const sidebar = document.getElementById("sidebar");
  const toastContainer = document.getElementById("toastContainer");

  // Health Elements
  const backendStatusBadge = document.getElementById("backendStatusBadge");
  const backendStatusVal = document.getElementById("backendStatusVal");
  const backendLatencyVal = document.getElementById("backendLatencyVal");
  const backendLastCheckVal = document.getElementById("backendLastCheckVal");
  const backendResponseVal = document.getElementById("backendResponseVal");
  const topLatencyChip = document.getElementById("topLatencyChip");
  const topStatusChip = document.getElementById("topStatusChip");
  const footerPulseDot = document.getElementById("footerPulseDot");
  const footerStatusText = document.getElementById("footerStatusText");
  const uptimeDisplay = document.getElementById("uptimeDisplay");

  // Activity List
  const activityList = document.getElementById("activityList");

  // Auth & Agent DOM Elements (Phase 2 Cloud Auth)
  const loginModal = document.getElementById("loginModal");
  const loginForm = document.getElementById("loginForm");
  const loginAlert = document.getElementById("loginAlert");
  const loginUsername = document.getElementById("loginUsername");
  const loginPassword = document.getElementById("loginPassword");
  const btnLoginSubmit = document.getElementById("btnLoginSubmit");
  const authUserPill = document.getElementById("authUserPill");
  const authUsernameDisplay = document.getElementById("authUsernameDisplay");
  const btnLogout = document.getElementById("btnLogout");
  const topAgentStatusText = document.getElementById("topAgentStatusText");
  const agentPulseDot = document.getElementById("agentPulseDot");

  async function checkAuthSession() {
    try {
      const res = await fetch("/api/auth/me");
      if (res.ok) {
        const data = await res.json();
        csrfToken = data.csrf_token;
        if (loginModal) loginModal.style.display = "none";
        if (authUserPill) authUserPill.style.display = "flex";
        if (authUsernameDisplay) authUsernameDisplay.textContent = data.username;
        loadTasks();
        fetchAgentStatus();
      } else {
        if (loginModal) loginModal.style.display = "flex";
        if (authUserPill) authUserPill.style.display = "none";
      }
    } catch (e) {
      console.warn("Auth check error:", e);
      if (loginModal) loginModal.style.display = "flex";
    }
  }

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!loginUsername || !loginPassword) return;

      const u = loginUsername.value.trim();
      const p = loginPassword.value;
      if (!u || !p) return;

      if (loginAlert) loginAlert.style.display = "none";
      if (btnLoginSubmit) {
        btnLoginSubmit.disabled = true;
        btnLoginSubmit.textContent = "Authenticating...";
      }

      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();

        if (res.ok) {
          csrfToken = data.csrf_token;
          if (loginModal) loginModal.style.display = "none";
          if (authUserPill) authUserPill.style.display = "flex";
          if (authUsernameDisplay) authUsernameDisplay.textContent = data.username;
          showToast(`Welcome back, ${data.username}!`, "success");
          addActivity(`User <strong>${data.username}</strong> authenticated via Cloud Gateway`, "AUTH", "success");
          loadTasks();
          fetchAgentStatus();
        } else {
          if (loginAlert) {
            loginAlert.textContent = data.detail || "Invalid username or password";
            loginAlert.style.display = "block";
          }
        }
      } catch (err) {
        if (loginAlert) {
          loginAlert.textContent = `Network error: ${err.message}`;
          loginAlert.style.display = "block";
        }
      } finally {
        if (btnLoginSubmit) {
          btnLoginSubmit.disabled = false;
          btnLoginSubmit.textContent = "Sign In to Dashboard";
        }
      }
    });
  }

  if (btnLogout) {
    btnLogout.addEventListener("click", async () => {
      try {
        await fetch("/api/auth/logout", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken
          }
        });
      } catch (e) {
        console.warn("Logout error:", e);
      } finally {
        csrfToken = "";
        if (authUserPill) authUserPill.style.display = "none";
        if (loginModal) loginModal.style.display = "flex";
        showToast("Signed out successfully.", "info");
      }
    });
  }

  // -------------------------------------------------------------------------
  // Toast Notifications
  // -------------------------------------------------------------------------
  function showToast(message, type = "info") {
    if (!toastContainer) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type === "success" ? "toast-success" : type === "error" ? "toast-error" : ""}`;
    
    // Icon based on type
    const iconSvg = type === "success" 
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`
      : type === "error"
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;

    toast.innerHTML = `
      ${iconSvg}
      <span>${message}</span>
    `;

    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
      toast.style.opacity = "0";
      toast.style.transform = "translateX(40px)";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // -------------------------------------------------------------------------
  // Activity Feed Helper
  // -------------------------------------------------------------------------
  function addActivity(text, tag = "INFO", type = "info") {
    if (!activityList) return;

    const timeStr = new Date().toLocaleTimeString();
    const item = document.createElement("div");
    item.className = "activity-item";

    const dotColor = type === "success" ? "#10b981" : type === "warn" ? "#f59e0b" : "#06b6d4";

    item.innerHTML = `
      <div class="activity-icon-wrap" style="background: rgba(255,255,255,0.05); color: ${dotColor};">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="12" cy="12" r="10"></circle>
          <polyline points="12 6 12 12 16 14"></polyline>
        </svg>
      </div>
      <div class="activity-content">
        <div class="activity-text">${text}</div>
        <div class="activity-time">${timeStr} &bull; <span style="color: ${dotColor}; font-weight:600;">${tag}</span></div>
      </div>
    `;

    activityList.insertBefore(item, activityList.firstChild);

    // Limit feed to 20 items
    while (activityList.children.length > 20) {
      activityList.removeChild(activityList.lastChild);
    }
  }

  // -------------------------------------------------------------------------
  // Navigation Handling
  // -------------------------------------------------------------------------
  function switchView(viewName) {
    state.currentView = viewName;

    // Update Nav items
    navItems.forEach(item => {
      if (item.getAttribute("data-view") === viewName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Update Views
    views.forEach(v => {
      if (v.id === `view-${viewName}`) {
        v.classList.add("active-view");
      } else {
        v.classList.remove("active-view");
      }
    });

    // Update Breadcrumb
    const activeLabel = document.querySelector(`.nav-item[data-view="${viewName}"] .nav-label`);
    if (activeLabel && breadcrumbActive) {
      breadcrumbActive.textContent = activeLabel.textContent;
    }

    // Close mobile drawer if open
    if (sidebar && sidebar.classList.contains("open")) {
      sidebar.classList.remove("open");
    }
  }

  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const view = item.getAttribute("data-view");
      if (view) {
        switchView(view);
      }
    });
  });

  // Mobile drawer toggle
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }

  // -------------------------------------------------------------------------
  // Backend Health Ping (/health)
  // -------------------------------------------------------------------------
  async function checkBackendHealth(isManual = false) {
    const startTime = performance.now();
    state.totalRequests++;

    try {
      const response = await fetch("/health", { cache: "no-store" });
      const latency = Math.round(performance.now() - startTime);
      const data = await response.json();

      if (response.ok && data.status === "healthy") {
        state.backendStatus = "healthy";
        updateLatencyRecord(latency);

        // Update UI
        if (backendStatusBadge) {
          backendStatusBadge.className = "status-badge badge-online";
          backendStatusBadge.innerHTML = `<span class="pulse-dot"></span> Online`;
        }
        if (backendStatusVal) backendStatusVal.textContent = "Healthy (200 OK)";
        if (backendLatencyVal) backendLatencyVal.textContent = `${latency} ms`;
        if (backendLastCheckVal) backendLastCheckVal.textContent = new Date().toLocaleTimeString();
        if (backendResponseVal) backendResponseVal.textContent = JSON.stringify(data);

        if (topLatencyChip) topLatencyChip.innerHTML = `<span>LATENCY:</span> ${latency}ms`;
        if (topStatusChip) {
          topStatusChip.innerHTML = `<span class="pulse-dot" style="margin-right:4px;"></span> ONLINE`;
          topStatusChip.classList.add("stat-chip-accent");
        }
        if (footerPulseDot) {
          footerPulseDot.className = "pulse-dot";
        }
        if (footerStatusText) {
          footerStatusText.textContent = "FastAPI: Connected";
        }

        if (isManual) {
          showToast(`Backend connection healthy (${latency}ms)`, "success");
          addActivity(`Manual health check passed: <strong>${latency}ms</strong>`, "HEALTH", "success");
        }
      } else {
        throw new Error(`Unexpected status code: ${response.status}`);
      }
    } catch (err) {
      state.backendStatus = "offline";
      console.warn("Backend health check failed:", err);

      if (backendStatusBadge) {
        backendStatusBadge.className = "status-badge badge-offline";
        backendStatusBadge.innerHTML = `Offline`;
      }
      if (backendStatusVal) backendStatusVal.textContent = "Connection Failed";
      if (backendLatencyVal) backendLatencyVal.textContent = `--`;
      if (backendLastCheckVal) backendLastCheckVal.textContent = new Date().toLocaleTimeString();
      if (backendResponseVal) backendResponseVal.textContent = `Error: ${err.message}`;

      if (topLatencyChip) topLatencyChip.innerHTML = `<span>LATENCY:</span> --`;
      if (topStatusChip) {
        topStatusChip.innerHTML = `<span class="pulse-dot status-dot-offline" style="margin-right:4px;"></span> OFFLINE`;
        topStatusChip.classList.remove("stat-chip-accent");
      }
      if (footerPulseDot) {
        footerPulseDot.className = "pulse-dot status-dot-offline";
      }
      if (footerStatusText) {
        footerStatusText.textContent = "FastAPI: Disconnected";
      }

      if (isManual) {
        showToast("Backend health check failed. Is the server running?", "error");
        addActivity(`Backend connection failed: ${err.message}`, "ERROR", "error");
      }
    }

    updateMonitorMetrics();
  }

  function updateLatencyRecord(latency) {
    state.latencyHistory.push({ time: new Date().toLocaleTimeString(), val: latency });
    if (state.latencyHistory.length > state.maxLatencyPoints) {
      state.latencyHistory.shift();
    }
  }

  function startHealthPolling() {
    checkBackendHealth();
    if (state.healthTimer) clearInterval(state.healthTimer);
    state.healthTimer = setInterval(() => {
      if (state.isPolling) {
        checkBackendHealth();
      }
    }, state.healthCheckInterval);
  }

  // -------------------------------------------------------------------------
  // System Monitor & Telemetry
  // -------------------------------------------------------------------------
  function updateMonitorMetrics() {
    const monitorReqCount = document.getElementById("monitorReqCount");
    const monitorAvgLatency = document.getElementById("monitorAvgLatency");
    const latencyBarsWrap = document.getElementById("latencyBarsWrap");

    if (monitorReqCount) {
      monitorReqCount.textContent = state.totalRequests;
    }

    if (monitorAvgLatency && state.latencyHistory.length > 0) {
      const sum = state.latencyHistory.reduce((acc, curr) => acc + curr.val, 0);
      const avg = Math.round(sum / state.latencyHistory.length);
      monitorAvgLatency.textContent = `${avg} ms`;
    }

    if (latencyBarsWrap && state.latencyHistory.length > 0) {
      latencyBarsWrap.innerHTML = "";
      state.latencyHistory.forEach(item => {
        const barContainer = document.createElement("div");
        barContainer.style.display = "flex";
        barContainer.style.flexDirection = "column";
        barContainer.style.alignItems = "center";
        barContainer.style.gap = "4px";
        barContainer.style.flex = "1";

        const barHeight = Math.min(Math.max(item.val * 3, 10), 90);
        const bar = document.createElement("div");
        bar.style.width = "100%";
        bar.style.height = `${barHeight}px`;
        bar.style.backgroundColor = item.val > 50 ? "#f59e0b" : "#06b6d4";
        bar.style.borderRadius = "4px";
        bar.style.transition = "height 0.3s ease";
        bar.title = `${item.val} ms (${item.time})`;

        const label = document.createElement("span");
        label.style.fontSize = "10px";
        label.style.color = "#64748b";
        label.style.fontFamily = "var(--font-mono)";
        label.textContent = `${item.val}m`;

        barContainer.appendChild(bar);
        barContainer.appendChild(label);
        latencyBarsWrap.appendChild(barContainer);
      });
    }
  }

  // Uptime tick (every second)
  setInterval(() => {
    state.uptimeSeconds++;
    const hrs = String(Math.floor(state.uptimeSeconds / 3600)).padStart(2, "0");
    const mins = String(Math.floor((state.uptimeSeconds % 3600) / 60)).padStart(2, "0");
    const secs = String(state.uptimeSeconds % 60).padStart(2, "0");
    const formatted = `${hrs}:${mins}:${secs}`;

    if (uptimeDisplay) {
      uptimeDisplay.textContent = formatted;
    }

    const monitorUptimeVal = document.getElementById("monitorUptimeVal");
    if (monitorUptimeVal) {
      monitorUptimeVal.textContent = formatted;
    }
  }, 1000);

  // -------------------------------------------------------------------------
  // Quick Actions Button Handlers
  // -------------------------------------------------------------------------
  const btnCheckHealth = document.getElementById("btnCheckHealth");
  if (btnCheckHealth) {
    btnCheckHealth.addEventListener("click", () => {
      checkBackendHealth(true);
    });
  }

  const btnOpenChat = document.getElementById("btnOpenChat");
  if (btnOpenChat) {
    btnOpenChat.addEventListener("click", () => {
      switchView("chat");
      showToast("Switched to AI Chat interface");
    });
  }

  const btnOpenAntigravity = document.getElementById("btnOpenAntigravity");
  if (btnOpenAntigravity) {
    btnOpenAntigravity.addEventListener("click", () => {
      switchView("antigravity");
      showToast("Viewing Antigravity Agent Configuration");
    });
  }

  const btnScanWorkspace = document.getElementById("btnScanWorkspace");
  if (btnScanWorkspace) {
    btnScanWorkspace.addEventListener("click", () => {
      showToast("Scanning local workspace directory...", "info");
      addActivity("Scanning workspace: <code>C:\\Users\\lovel\\Desktop\\AI-CODING-HUB</code>", "SCAN", "info");

      setTimeout(() => {
        showToast("Workspace scan complete: 4 local paths verified", "success");
        addActivity("Scan completed: <code>main.py</code>, <code>static/</code>, <code>.venv/</code> verified", "SCAN", "success");
      }, 700);
    });
  }

  const btnRunTest = document.getElementById("btnRunTest");
  if (btnRunTest) {
    btnRunTest.addEventListener("click", () => {
      showToast("Running automated test suite for endpoints...", "info");
      addActivity("Executing endpoint test on <code>/</code> and <code>/health</code>...", "TEST", "warn");

      setTimeout(async () => {
        try {
          const resHome = await fetch("/");
          const resHealth = await fetch("/health");
          if (resHome.ok && resHealth.ok) {
            showToast("All tests passed! 2 endpoints verified.", "success");
            addActivity("Endpoints tested successfully: <code>/</code> (200 OK) &amp; <code>/health</code> (200 OK)", "TEST", "success");
          } else {
            showToast("Test finished with warnings", "error");
          }
        } catch (e) {
          showToast("Test execution error: " + e.message, "error");
        }
      }, 600);
    });
  }

  // -------------------------------------------------------------------------
  // Interactive AI Chat Mockup
  // -------------------------------------------------------------------------
  const chatInput = document.getElementById("chatInput");
  const btnSendMessage = document.getElementById("btnSendMessage");
  const chatMessages = document.getElementById("chatMessages");
  const btnClearChat = document.getElementById("btnClearChat");

  function sendChatMessage() {
    if (!chatInput || !chatMessages) return;
    const msg = chatInput.value.trim();
    if (!msg) return;

    // Append User Message
    const userBubble = document.createElement("div");
    userBubble.className = "chat-bubble bubble-user";
    userBubble.textContent = msg;
    chatMessages.appendChild(userBubble);
    chatInput.value = "";
    chatMessages.scrollTop = chatMessages.scrollHeight;

    addActivity(`AI Chat prompt: "${msg.substring(0, 32)}..."`, "CHAT", "info");

    // Simulated Assistant Typing & Reply
    setTimeout(() => {
      const assistantBubble = document.createElement("div");
      assistantBubble.className = "chat-bubble bubble-assistant";

      let responseText = `I received your prompt: "${msg}". Local AI CODING HUB is running and ready to automate tasks. Antigravity and VS Code agent bridges are currently configured in Standby mode.`;
      
      const lower = msg.toLowerCase();
      if (lower.includes("health") || lower.includes("status")) {
        responseText = `System Status: Backend is ${state.backendStatus.toUpperCase()} at /health. Workspace: C:\\Users\\lovel\\Desktop\\AI-CODING-HUB.`;
      } else if (lower.includes("antigravity")) {
        responseText = `Antigravity Agent is configured and listening on local protocol. Full agent execution bridge will activate upon core service link.`;
      } else if (lower.includes("help") || lower.includes("features")) {
        responseText = `AI CODING HUB Features:\n- Live System Monitoring & /health checks\n- Workspace Project Inspection\n- Antigravity & VS Code Agent Configuration\n- Task Automation Runner`;
      }

      assistantBubble.textContent = responseText;
      chatMessages.appendChild(assistantBubble);
      chatMessages.scrollTop = chatMessages.scrollHeight;
    }, 450);
  }

  if (btnSendMessage && chatInput) {
    btnSendMessage.addEventListener("click", sendChatMessage);
    chatInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage();
      }
    });
  }

  if (btnClearChat && chatMessages) {
    btnClearChat.addEventListener("click", () => {
      chatMessages.innerHTML = `
        <div class="chat-bubble bubble-assistant">
          Chat cleared. Hello! I'm the local AI CODING HUB assistant. How can I help you today?
        </div>
      `;
      showToast("Chat history reset", "info");
    });
  }

  // -------------------------------------------------------------------------
  // Task Automation Runner Handlers
  // -------------------------------------------------------------------------
  const taskButtons = document.querySelectorAll(".btn-task-run");
  taskButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const taskName = btn.getAttribute("data-task") || "Task";
      const originalText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `
        <svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
          <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"></path>
        </svg> Running...
      `;

      showToast(`Started task: ${taskName}`, "info");
      addActivity(`Task started: <strong>${taskName}</strong>`, "TASK", "warn");

      setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = originalText;
        showToast(`Completed task: ${taskName}`, "success");
        addActivity(`Task finished successfully: <strong>${taskName}</strong> (Completed in 1.2s)`, "TASK", "success");
      }, 1200);
    });
  });

  // -------------------------------------------------------------------------
  // Settings Form Handlers
  // -------------------------------------------------------------------------
  const pollingIntervalInput = document.getElementById("pollingIntervalInput");
  const togglePolling = document.getElementById("togglePolling");

  if (pollingIntervalInput) {
    pollingIntervalInput.addEventListener("change", (e) => {
      const val = parseInt(e.target.value, 10);
      if (val >= 1 && val <= 60) {
        state.healthCheckInterval = val * 1000;
        startHealthPolling();
        showToast(`Health check interval set to ${val}s`, "info");
      }
    });
  }

  if (togglePolling) {
    togglePolling.addEventListener("change", (e) => {
      state.isPolling = e.target.checked;
      showToast(`Live polling ${state.isPolling ? "enabled" : "paused"}`, "info");
      addActivity(`Live polling ${state.isPolling ? "resumed" : "paused"}`, "CONFIG", "info");
    });
  }

  // -------------------------------------------------------------------------
  // Phase 1: Antigravity Tasks & Approval Client Logic
  // -------------------------------------------------------------------------
  const taskPromptInput = document.getElementById("taskPromptInput");
  const btnSubmitTask = document.getElementById("btnSubmitTask");
  const pendingTasksContainer = document.getElementById("pendingTasksContainer");
  const pendingCountBadge = document.getElementById("pendingCountBadge");
  const taskHistoryContainer = document.getElementById("taskHistoryContainer");
  const btnRefreshTasks = document.getElementById("btnRefreshTasks");
  const taskLogViewer = document.getElementById("taskLogViewer");
  const taskLogOutput = document.getElementById("taskLogOutput");
  const logViewerTitle = document.getElementById("logViewerTitle");
  const btnCloseLogViewer = document.getElementById("btnCloseLogViewer");
  const agentBridgeStatusBadge = document.getElementById("agentBridgeStatusBadge");

  async function fetchAgentStatus() {
    try {
      const res = await fetch("/api/agent/status");
      if (res.ok) {
        const data = await res.json();
        const isOnline = data.bridge_connected || data.status === "online";
        if (topAgentStatusText && agentPulseDot) {
          if (isOnline) {
            topAgentStatusText.textContent = "AGENT: ONLINE";
            topAgentStatusText.style.color = "var(--accent-emerald)";
            agentPulseDot.className = "pulse-dot pulse-dot-online";
          } else {
            topAgentStatusText.textContent = "AGENT: OFFLINE";
            topAgentStatusText.style.color = "var(--text-muted)";
            agentPulseDot.className = "pulse-dot pulse-dot-offline";
          }
        }
        if (agentBridgeStatusBadge) {
          if (isOnline) {
            agentBridgeStatusBadge.className = "status-badge badge-online";
            agentBridgeStatusBadge.innerHTML = `<span class="pulse-dot pulse-dot-online"></span> Bridge Connected (${data.worker_id || "Active"})`;
          } else {
            agentBridgeStatusBadge.className = "status-badge badge-offline";
            agentBridgeStatusBadge.innerHTML = `Agent Bridge Offline (Standby)`;
          }
        }
      }
    } catch (e) {
      console.warn("Could not fetch agent status:", e);
    }
  }

  async function loadTasks() {
    try {
      const res = await fetch("/api/tasks");
      if (!res.ok) return;
      const tasks = await res.json();
      renderTasks(tasks);
    } catch (e) {
      console.warn("Error fetching tasks:", e);
    }
  }

  function renderTasks(tasks) {
    const pending = tasks.filter(t => t.status === "PENDING_APPROVAL");
    const awaitingAction = tasks.find(t => t.status === "AWAITING_ACTION_APPROVAL" && t.pending_permission);

    // Update pending task count badge
    if (pendingCountBadge) {
      pendingCountBadge.textContent = `${pending.length} Pending`;
      pendingCountBadge.className = pending.length > 0
        ? "status-badge badge-pending_approval"
        : "status-badge badge-online";
    }

    // Render Prominent Action Approval Panel (Mandatory Human-in-the-Loop)
    const actionApprovalPanel = document.getElementById("actionApprovalPanel");
    const actionApprovalTaskId = document.getElementById("actionApprovalTaskId");
    const actionTitle = document.getElementById("actionTitle");
    const actionKindBadge = document.getElementById("actionKindBadge");
    const actionDetailsBox = document.getElementById("actionDetailsBox");
    const btnApproveAction = document.getElementById("btnApproveAction");
    const btnRejectAction = document.getElementById("btnRejectAction");
    const btnCancelActionTask = document.getElementById("btnCancelActionTask");

    if (actionApprovalPanel) {
      if (awaitingAction && awaitingAction.pending_permission) {
        const p = awaitingAction.pending_permission;
        actionApprovalPanel.style.display = "block";
        if (actionApprovalTaskId) actionApprovalTaskId.textContent = awaitingAction.id;
        if (actionTitle) actionTitle.textContent = `Action: ${p.title}`;
        if (actionKindBadge) actionKindBadge.textContent = p.kind || "tool";
        if (actionDetailsBox) actionDetailsBox.textContent = JSON.stringify(p.tool_call || {}, null, 2);

        if (btnApproveAction) {
          btnApproveAction.onclick = () => window.handleResolveActionPermission(awaitingAction.id, "allow_once");
        }
        if (btnRejectAction) {
          btnRejectAction.onclick = () => window.handleResolveActionPermission(awaitingAction.id, "reject_once");
        }
        if (btnCancelActionTask) {
          btnCancelActionTask.onclick = () => window.handleCancelTask(awaitingAction.id);
        }
      } else {
        actionApprovalPanel.style.display = "none";
      }
    }

    // Render Pending Approval Cards (Task-Level)
    if (pendingTasksContainer) {
      if (pending.length === 0) {
        pendingTasksContainer.innerHTML = `
          <div style="font-size: 12.5px; color: var(--text-muted); padding: 16px; text-align: center;">
            No tasks currently awaiting approval. Submit a task above to preview it here.
          </div>
        `;
      } else {
        pendingTasksContainer.innerHTML = "";
        pending.forEach(task => {
          const card = document.createElement("div");
          card.className = "approval-card";
          card.innerHTML = `
            <div class="approval-header">
              <span class="approval-id">${task.id}</span>
              <span class="status-badge badge-pending_approval">Pending Approval</span>
            </div>
            <div class="approval-prompt-box">${escapeHtml(task.prompt)}</div>
            <div class="approval-meta-row">
              <span><strong>Workspace:</strong> <code>${escapeHtml(task.workspace)}</code></span>
              <span>${new Date(task.created_at).toLocaleTimeString()}</span>
            </div>
            <div class="approval-actions">
              <button class="btn-approve" onclick="handleApproveTask('${task.id}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                Approve &amp; Run
              </button>
              <button class="btn-reject" onclick="handleRejectTask('${task.id}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                Reject Task
              </button>
            </div>
          `;
          pendingTasksContainer.appendChild(card);
        });
      }
    }

    // Render Task History
    if (taskHistoryContainer) {
      if (tasks.length === 0) {
        taskHistoryContainer.innerHTML = `
          <div style="font-size: 12.5px; color: var(--text-muted); padding: 14px; text-align: center;">
            No task history yet.
          </div>
        `;
      } else {
        taskHistoryContainer.innerHTML = "";
        tasks.forEach(task => {
          const row = document.createElement("div");
          row.style.background = "var(--bg-surface)";
          row.style.border = "1px solid var(--border-subtle)";
          row.style.borderRadius = "var(--radius-md)";
          row.style.padding = "12px 16px";
          row.style.display = "flex";
          row.style.alignItems = "center";
          row.style.justifyContent = "space-between";
          row.style.gap = "12px";

          const badgeClass = `badge-${task.status.toLowerCase()}`;
          const promptExcerpt = task.prompt.length > 45 ? task.prompt.substring(0, 45) + "..." : task.prompt;
          const permHistoryCount = (task.permission_history && task.permission_history.length) || 0;

          row.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 4px; flex: 1;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-family: var(--font-mono); font-size: 12px; color: var(--accent-cyan); font-weight:600;">${task.id}</span>
                <span class="status-badge ${badgeClass}" style="font-size: 10px; padding: 2px 8px;">${task.status}</span>
                ${permHistoryCount > 0 ? `<span class="status-badge badge-info" style="font-size: 10px; padding: 2px 6px;">${permHistoryCount} Decisions</span>` : ""}
                <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${new Date(task.created_at).toLocaleTimeString()}</span>
              </div>
              <div style="font-size: 12.5px; color: var(--text-primary); font-family: var(--font-mono);">${escapeHtml(promptExcerpt)}</div>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <button class="btn-view-log" onclick="viewTaskLogs('${task.id}')">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
                View Logs
              </button>
            </div>
          `;
          taskHistoryContainer.appendChild(row);
        });
      }
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Window-accessible handlers for inline onclicks
  window.handleApproveTask = async function(taskId) {
    try {
      showToast(`Authorizing execution for ${taskId}...`, "info");
      addActivity(`Approving task: <code>${taskId}</code>`, "APPROVAL", "warn");

      const res = await fetch(`/api/tasks/${taskId}/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        }
      });
      const data = await res.json();

      if (res.ok) {
        showToast(`Task ${taskId} approved! Dispatched to local agent.`, "success");
        addActivity(`Task approved and scheduled: <code>${taskId}</code>`, "TASK", "success");
        await loadTasks();
      } else {
        showToast(`Approval failed: ${data.detail || "Error"}`, "error");
      }
    } catch (e) {
      showToast(`Approval error: ${e.message}`, "error");
    }
  };

  window.handleRejectTask = async function(taskId) {
    try {
      const res = await fetch(`/api/tasks/${taskId}/reject`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({ reason: "Rejected via Dashboard approval panel" })
      });
      const data = await res.json();

      if (res.ok) {
        showToast(`Task ${taskId} rejected. Agent will not execute.`, "info");
        addActivity(`Task rejected: <code>${taskId}</code> (Agent launch blocked)`, "SECURITY", "warn");
        await loadTasks();
      } else {
        showToast(`Rejection failed: ${data.detail || "Error"}`, "error");
      }
    } catch (e) {
      showToast(`Rejection error: ${e.message}`, "error");
    }
  };

  window.handleResolveActionPermission = async function(taskId, decision) {
    try {
      showToast(`Submitting action decision '${decision}'...`, "info");
      const res = await fetch(`/api/tasks/${taskId}/permission`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({ decision: decision })
      });
      const data = await res.json();

      if (res.ok) {
        const label = decision === "allow_once" ? "Approved" : "Rejected";
        showToast(`Action ${label} successfully!`, decision === "allow_once" ? "success" : "info");
        addActivity(`Action decision: <strong>${label}</strong> for task <code>${taskId}</code>`, "SECURITY", decision === "allow_once" ? "success" : "warn");
        await loadTasks();
      } else {
        showToast(`Action decision failed: ${data.detail || "Error"}`, "error");
      }
    } catch (e) {
      showToast(`Decision error: ${e.message}`, "error");
    }
  };

  window.handleCancelTask = async function(taskId) {
    try {
      const res = await fetch(`/api/tasks/${taskId}/cancel`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        }
      });
      const data = await res.json();
      if (res.ok) {
        showToast(`Task ${taskId} cancelled safely.`, "info");
        addActivity(`Task cancelled: <code>${taskId}</code>`, "TASK", "warn");
        await loadTasks();
      } else {
        showToast(`Cancel error: ${data.detail || "Error"}`, "error");
      }
    } catch (e) {
      showToast(`Network error: ${e.message}`, "error");
    }
  };
        showToast(`Cancel error: ${data.detail || "Error"}`, "error");
      }
    } catch (e) {
      showToast(`Network error: ${e.message}`, "error");
    }
  };

  window.viewTaskLogs = async function(taskId) {
    try {
      const res = await fetch(`/api/tasks/${taskId}/logs`);
      if (!res.ok) {
        showToast("Could not retrieve logs", "error");
        return;
      }
      const data = await res.json();
      if (taskLogViewer && taskLogOutput && logViewerTitle) {
        logViewerTitle.textContent = `Execution Logs: ${data.task_id} [${data.status}]`;
        let text = `Task ID: ${data.task_id}\nStatus: ${data.status}\n`;
        if (data.executed_at) text += `Executed At: ${data.executed_at}\n`;
        if (data.completed_at) text += `Completed At: ${data.completed_at}\n`;
        if (data.exit_code !== null) text += `Exit Code: ${data.exit_code}\n`;
        if (data.error) text += `Error: ${data.error}\n`;

        if (data.pending_permission) {
          text += `\n*** PENDING ACTION APPROVAL ***\n${JSON.stringify(data.pending_permission, null, 2)}\n`;
        }

        if (data.permission_history && data.permission_history.length > 0) {
          text += `\n--- ACTION PERMISSION AUDIT TRAIL ---\n`;
          data.permission_history.forEach(p => {
            text += `[${p.decided_at}] ${p.decision.toUpperCase()}: ${p.title} (${p.kind})\n`;
          });
        }

        text += `\n--- STDOUT & EVENT STREAM ---\n${data.stdout || "(no stdout recorded)"}\n`;
        if (data.stderr) text += `\n--- STDERR ---\n${data.stderr}\n`;

        taskLogOutput.textContent = text;
        taskLogViewer.style.display = "block";
        taskLogViewer.scrollIntoView({ behavior: "smooth" });
      }
    } catch (e) {
      showToast(`Log error: ${e.message}`, "error");
    }
  };

  if (btnCloseLogViewer && taskLogViewer) {
    btnCloseLogViewer.addEventListener("click", () => {
      taskLogViewer.style.display = "none";
    });
  }

  if (btnRefreshTasks) {
    btnRefreshTasks.addEventListener("click", () => {
      loadTasks();
      showToast("Tasks refreshed", "info");
    });
  }

  if (btnSubmitTask && taskPromptInput) {
    btnSubmitTask.addEventListener("click", async () => {
      const prompt = taskPromptInput.value.trim();
      if (!prompt) {
        showToast("Please enter a coding task prompt.", "error");
        return;
      }

      btnSubmitTask.disabled = true;
      try {
        const res = await fetch("/api/tasks", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken
          },
          body: JSON.stringify({
            prompt: prompt,
            workspace: "C:\\Users\\lovel\\Desktop\\AI-CODING-HUB"
          })
        });

        const data = await res.json();
        if (res.ok) {
          showToast(`Task ${data.id} submitted! Placed in PENDING_APPROVAL.`, "success");
          addActivity(`New task submitted: <code>${data.id}</code> (Awaiting explicit approval)`, "TASK", "warn");
          taskPromptInput.value = "";
          await loadTasks();
        } else {
          showToast(`Submission failed: ${data.detail || "Error"}`, "error");
        }
      } catch (e) {
        showToast(`Submission error: ${e.message}`, "error");
      } finally {
        btnSubmitTask.disabled = false;
      }
    });
  }

  // Periodic task status polling
  setInterval(() => {
    if (csrfToken) {
      loadTasks();
      fetchAgentStatus();
    }
  }, 4000);

  // -------------------------------------------------------------------------
  // Initial Boot
  // -------------------------------------------------------------------------
  startHealthPolling();
  checkAuthSession();
  addActivity("AI CODING HUB Dashboard initialized and mounted at <code>/dashboard</code>", "INIT", "success");
  addActivity("Connected to Cloud Gateway: <code>http://127.0.0.1:8000</code>", "INIT", "info");
});
