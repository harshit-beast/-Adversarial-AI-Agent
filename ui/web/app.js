const state = {
  target: "",
  webUrl: "",
  recon: {},
  webtests: {},
  simulation: {},
  risk: { score: 0, level: "N/A", reasons: [] },
};

const healthBadge = document.getElementById("health-badge");
const targetInput = document.getElementById("target-input");
const webUrlInput = document.getElementById("web-url-input");
const reconOutput = document.getElementById("recon-output");
const webOutput = document.getElementById("web-output");
const simOutput = document.getElementById("sim-output");
const riskLevel = document.getElementById("risk-level");
const riskScore = document.getElementById("risk-score");
const toast = document.getElementById("toast");

const runReconBtn = document.getElementById("run-recon-btn");
const runWebBtn = document.getElementById("run-web-btn");
const runSimBtn = document.getElementById("run-sim-btn");
const runFullBtn = document.getElementById("run-full-btn");
const clearBtn = document.getElementById("clear-btn");
const exportBtn = document.getElementById("export-btn");

function showToast(message, ms = 2600) {
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), ms);
}

function selectedValues(groupId) {
  return Array.from(document.querySelectorAll(`#${groupId} input[type="checkbox"]:checked`)).map((el) => el.value);
}

function setButtonLoading(btn, loading, loadingText = "Running...") {
  if (!btn) return;
  if (!btn.dataset.originalText) {
    btn.dataset.originalText = btn.textContent;
  }
  btn.disabled = loading;
  btn.textContent = loading ? loadingText : btn.dataset.originalText;
}

async function postJson(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

function prettyBlock(data) {
  return JSON.stringify(data, null, 2);
}

function updateRisk(risk) {
  if (!risk) return;
  state.risk = risk;
  riskLevel.textContent = String(risk.level || "N/A").toUpperCase();
  riskScore.textContent = `Score: ${risk.score ?? 0}/10`;
}

function captureInputs() {
  state.target = targetInput.value.trim();
  state.webUrl = webUrlInput.value.trim();
}

runReconBtn.addEventListener("click", async () => {
  captureInputs();
  setButtonLoading(runReconBtn, true);
  try {
    const data = await postJson("/api/recon", {
      target: state.target,
      modules: selectedValues("recon-checks"),
    });
    state.recon = data.recon || {};
    reconOutput.textContent = prettyBlock(state.recon);
    updateRisk(data.risk);
    showToast("Recon complete");
  } catch (err) {
    showToast(err.message);
  } finally {
    setButtonLoading(runReconBtn, false);
  }
});

runWebBtn.addEventListener("click", async () => {
  captureInputs();
  setButtonLoading(runWebBtn, true);
  try {
    const data = await postJson("/api/webtest", {
      url: state.webUrl,
      tests: selectedValues("web-checks"),
    });
    state.webtests = data.webtests || {};
    webOutput.textContent = prettyBlock(state.webtests);
    updateRisk(data.risk);
    showToast("Web testing complete");
  } catch (err) {
    showToast(err.message);
  } finally {
    setButtonLoading(runWebBtn, false);
  }
});

runSimBtn.addEventListener("click", async () => {
  captureInputs();
  setButtonLoading(runSimBtn, true);
  try {
    const data = await postJson("/api/simulate", {
      target: state.target,
      phases: selectedValues("sim-checks"),
    });
    state.simulation = data.simulation || {};
    simOutput.textContent = prettyBlock(state.simulation);
    showToast("Simulation complete");
  } catch (err) {
    showToast(err.message);
  } finally {
    setButtonLoading(runSimBtn, false);
  }
});

runFullBtn.addEventListener("click", async () => {
  captureInputs();
  setButtonLoading(runFullBtn, true);
  try {
    const includeWeb = Boolean(state.webUrl);
    const data = await postJson("/api/full-pipeline", {
      target: state.target,
      include_webtests: includeWeb,
      webtest_url: state.webUrl,
      recon_modules: selectedValues("recon-checks"),
      simulation_phases: selectedValues("sim-checks"),
      web_tests: selectedValues("web-checks"),
    });

    state.recon = data.recon || {};
    state.simulation = data.simulation || {};
    state.webtests = data.webtests || {};
    reconOutput.textContent = prettyBlock(state.recon);
    simOutput.textContent = prettyBlock(state.simulation);
    webOutput.textContent = prettyBlock(state.webtests);
    updateRisk(data.risk);
    showToast("Full pipeline complete");
  } catch (err) {
    showToast(err.message);
  } finally {
    setButtonLoading(runFullBtn, false, "Run Full Pipeline");
  }
});

clearBtn.addEventListener("click", () => {
  state.recon = {};
  state.webtests = {};
  state.simulation = {};
  state.risk = { score: 0, level: "N/A", reasons: [] };
  reconOutput.textContent = "Run recon to see results.";
  webOutput.textContent = "Run web tests to see results.";
  simOutput.textContent = "Run simulation to see results.";
  updateRisk(state.risk);
  showToast("Cleared");
});

exportBtn.addEventListener("click", async () => {
  captureInputs();
  setButtonLoading(exportBtn, true, "Exporting...");
  try {
    const data = await postJson("/api/report", {
      title: "AI Cybersecurity Assessment",
      target: state.target || "unspecified-target",
      recon: state.recon,
      webtests: state.webtests,
      simulation: state.simulation,
    });
    updateRisk(data.risk);
    showToast(`Report saved: ${data.html_report}`);
  } catch (err) {
    showToast(err.message);
  } finally {
    setButtonLoading(exportBtn, false);
  }
});

for (const btn of document.querySelectorAll("button[data-check-group]")) {
  btn.addEventListener("click", () => {
    const groupId = btn.getAttribute("data-check-group");
    const boxes = Array.from(document.querySelectorAll(`#${groupId} input[type=checkbox]`));
    const allChecked = boxes.every((b) => b.checked);
    boxes.forEach((box) => {
      box.checked = !allChecked;
    });
  });
}

(async function checkHealth() {
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    if (res.ok && data.ok) {
      healthBadge.textContent = "API Online";
      healthBadge.classList.add("ok");
      return;
    }
    throw new Error("Health check failed");
  } catch (_err) {
    healthBadge.textContent = "API Unreachable";
    healthBadge.classList.add("error");
  }
})();
