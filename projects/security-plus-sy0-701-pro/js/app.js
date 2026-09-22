// Simple but solid app logic
let revisionMode = false;
let history = JSON.parse(localStorage.getItem("secplus_history") || "[]");

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    document.querySelectorAll(".panel").forEach(p => p.classList.add("hide"));
    document.getElementById("view-" + tab.dataset.view).classList.remove("hide");
    if (tab.dataset.view === "stats") renderStats();
    if (tab.dataset.view === "plan") updateProgress();
  });
});

function getFiltered() {
  const search = document.getElementById("search").value.toLowerCase();
  const diff = document.getElementById("difficulty").value;
  const domains = [...document.querySelectorAll(".dfilt:checked")].map(c => +c.value);

  return QUESTIONS.filter(q => {
    if (domains.length && !domains.includes(q.d)) return false;
    if (diff && q.e !== diff) return false;
    if (search) {
      const text = (q.s + " " + q.o.join(" ") + " " + (q.x||"") + " " + (q.r||"")).toLowerCase();
      if (!text.includes(search)) return false;
    }
    return true;
  });
}

function renderBrowse() {
  const list = document.getElementById("qlist");
  const qs = getFiltered();
  list.innerHTML = `<p style="color:var(--muted);margin-bottom:12px">${qs.length} questions</p>`;

  qs.forEach((q, i) => {
    const div = document.createElement("div");
    div.className = "q";
    div.innerHTML = `
      <div class="meta">
        <span class="badge domain-${q.d}">D${q.d}</span>
        <span class="badge">${q.e}</span>
      </div>
      <h3>${q.s}</h3>
      <div class="opts">
        ${q.o.map((opt, idx) => `
          <div class="opt ${revisionMode && idx === q.c ? 'correct' : ''}" data-idx="${idx}">
            ${String.fromCharCode(65+idx)}. ${opt}
          </div>`).join("")}
      </div>
      ${revisionMode ? `
        <div class="explain"><strong>Explication :</strong> ${q.x}</div>
        <div class="trap"><strong>Piège :</strong> ${q.r}</div>
      ` : ""}
    `;
    list.appendChild(div);
  });
}

document.getElementById("search").addEventListener("input", renderBrowse);
document.getElementById("difficulty").addEventListener("change", renderBrowse);
document.querySelectorAll(".dfilt").forEach(c => c.addEventListener("change", renderBrowse));

document.getElementById("revBtn").addEventListener("click", () => {
  revisionMode = !revisionMode;
  document.getElementById("revBtn").textContent = revisionMode ? "Revision mode ON" : "Revision mode OFF";
  renderBrowse();
});

document.getElementById("quizStart").addEventListener("click", startQuiz);

function startQuiz() {
  const size = +document.getElementById("quizSize").value;
  const diffFocus = document.getElementById("quizDiff").value;
  let pool = [...QUESTIONS];
  if (diffFocus) pool = pool.filter(q => q.e === diffFocus);
  pool = pool.sort(() => Math.random() - 0.5).slice(0, size);

  const area = document.getElementById("quizArea");
  area.innerHTML = "";
  let current = 0;
  let score = 0;

  function showQuestion() {
    if (current >= pool.length) {
      area.innerHTML = `<h2>Score : ${score} / ${pool.length}</h2>
        <button onclick="location.reload()">Retour</button>`;
      history.push({date: new Date().toISOString(), score, total: pool.length});
      localStorage.setItem("secplus_history", JSON.stringify(history));
      return;
    }
    const q = pool[current];
    area.innerHTML = `
      <div class="q">
        <div class="meta">Question ${current+1}/${pool.length} • D${q.d} • ${q.e}</div>
        <h3>${q.s}</h3>
        <div class="opts" id="quizOpts">
          ${q.o.map((opt, idx) => `<div class="opt" data-idx="${idx}">${String.fromCharCode(65+idx)}. ${opt}</div>`).join("")}
        </div>
      </div>`;
    document.querySelectorAll("#quizOpts .opt").forEach(opt => {
      opt.addEventListener("click", () => {
        const idx = +opt.dataset.idx;
        if (idx === q.c) score++;
        current++;
        showQuestion();
      });
    });
  }
  showQuestion();
}

function renderStats() {
  const area = document.getElementById("statsArea");
  if (!history.length) {
    area.innerHTML = "<p>Aucune session encore.</p>";
    return;
  }
  const totalQ = history.reduce((a, h) => a + h.total, 0);
  const totalCorrect = history.reduce((a, h) => a + h.score, 0);
  const avg = Math.round((totalCorrect / totalQ) * 100);
  area.innerHTML = `
    <div class="cell"><div class="v">${history.length}</div><div class="l">Sessions</div></div>
    <div class="cell"><div class="v">${totalQ}</div><div class="l">Questions</div></div>
    <div class="cell"><div class="v">${avg}%</div><div class="l">Moyenne</div></div>
  `;
}

function updateProgress() {
  const day = +document.getElementById("currentDay").value || 1;
  const pct = Math.min(100, (day / 40) * 100);
  document.getElementById("progressFill").style.width = pct + "%";
  document.getElementById("progressText").textContent = `Day ${day} / 40`;
}
document.getElementById("currentDay")?.addEventListener("input", updateProgress);

document.getElementById("exportBtn").addEventListener("click", () => {
  const data = {questions: QUESTIONS, history};
  const blob = new Blob([JSON.stringify(data, null, 2)], {type: "application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "security-plus-export.json";
  a.click();
});

// Initial render
renderBrowse();