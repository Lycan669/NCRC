// ====================== APP.JS AMÉLIORÉ ======================
let revisionMode = false;
let history = JSON.parse(localStorage.getItem("secplus_history") || "[]");

// ========== TABS ==========
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

// ========== FILTERS ==========
function getFiltered() {
  const search = document.getElementById("search").value.toLowerCase();
  const diff = document.getElementById("difficulty").value;
  const domains = [...document.querySelectorAll(".dfilt:checked")].map(c => +c.value);

  return QUESTIONS.filter(q => {
    if (domains.length && !domains.includes(q.d)) return false;
    if (diff && q.e !== diff) return false;
    if (search) {
      const text = (q.s + " " + q.o.join(" ") + " " + (q.x || "") + " " + (q.r || "")).toLowerCase();
      if (!text.includes(search)) return false;
    }
    return true;
  });
}

function renderBrowse() {
  const list = document.getElementById("qlist");
  const qs = getFiltered();
  list.innerHTML = `<p style="color:var(--muted);margin-bottom:12px">${qs.length} questions</p>`;

  qs.forEach((q) => {
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
          <div class="opt ${revisionMode && idx === q.c ? 'correct' : ''}">
            ${String.fromCharCode(65 + idx)}. ${opt}
          </div>`).join("")}
      </div>
      ${revisionMode ? `
        <div class="explain"><strong>Explication :</strong> ${q.x || "Non disponible"}</div>
        <div class="trap"><strong>Piège :</strong> ${q.r || "Non disponible"}</div>
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

// ========== QUIZ MODE (AMÉLIORÉ) ==========
document.getElementById("quizStart").addEventListener("click", startQuiz);

function startQuiz() {
  const size = +document.getElementById("quizSize").value || 20;
  const diffFocus = document.getElementById("quizDiff").value;

  let pool = [...QUESTIONS];
  if (diffFocus) pool = pool.filter(q => q.e === diffFocus);
  
  // Mélange aléatoire
  pool = pool.sort(() => Math.random() - 0.5).slice(0, size);

  const area = document.getElementById("quizArea");
  area.innerHTML = "";
  
  let current = 0;
  let score = 0;
  const userAnswers = []; // On stocke les réponses de l'utilisateur

  function showQuestion() {
    // ===== FIN DU QUIZ → AFFICHAGE DE LA CORRECTION =====
    if (current >= pool.length) {
      showCorrection(pool, userAnswers, score);
      return;
    }

    const q = pool[current];
    area.innerHTML = `
      <div class="q">
        <div class="meta">
          Question ${current + 1} / ${pool.length} • Domain ${q.d} • ${q.e}
        </div>
        <h3>${q.s}</h3>
        <div class="opts" id="quizOpts">
          ${q.o.map((opt, idx) => `
            <div class="opt" data-idx="${idx}">
              ${String.fromCharCode(65 + idx)}. ${opt}
            </div>
          `).join("")}
        </div>
      </div>
    `;

    document.querySelectorAll("#quizOpts .opt").forEach(opt => {
      opt.addEventListener("click", () => {
        const idx = +opt.dataset.idx;
        userAnswers.push(idx);
        if (idx === q.c) score++;
        current++;
        showQuestion();
      });
    });
  }

  showQuestion();
}

// ========== AFFICHAGE DE LA CORRECTION ==========
function showCorrection(questions, userAnswers, score) {
  const area = document.getElementById("quizArea");
  area.innerHTML = "";

  // Score final
  const percentage = Math.round((score / questions.length) * 100);
  const scoreHtml = `
    <div style="text-align:center; margin-bottom:30px; padding:20px; background:#1a1a2e; border-radius:12px;">
      <h2 style="margin:0 0 10px 0; color:#60a5fa;">Résultat de l'examen</h2>
      <div style="font-size:2rem; font-weight:700; color:#4ade80;">
        ${score} / ${questions.length}
      </div>
      <div style="font-size:1.3rem; color:#94a3b8; margin-top:5px;">
        ${percentage}%
      </div>
    </div>
  `;
  area.innerHTML = scoreHtml;

  // Détail de chaque question
  questions.forEach((q, index) => {
    const userAnswer = userAnswers[index];
    const isCorrect = userAnswer === q.c;

    const questionDiv = document.createElement("div");
    questionDiv.className = "q";
    questionDiv.style.marginBottom = "25px";

    let optionsHtml = "";
    q.o.forEach((opt, optIndex) => {
      let classes = "opt";
      let label = "";

      // Bonne réponse → toujours vert
      if (optIndex === q.c) {
        classes += " correct";
        label = " ✅ Bonne réponse";
      }

      // Réponse de l'utilisateur
      if (optIndex === userAnswer) {
        if (isCorrect) {
          classes += " correct";
        } else {
          classes += " wrong";
          label = " ❌ Votre réponse";
        }
      }

      optionsHtml += `
        <div class="${classes}">
          ${String.fromCharCode(65 + optIndex)}. ${opt}${label}
        </div>
      `;
    });

    questionDiv.innerHTML = `
      <div class="meta">
        Question ${index + 1} • Domain ${q.d} • ${q.e}
        ${isCorrect ? '<span style="color:#4ade80; margin-left:10px;">✔ Correct</span>' : '<span style="color:#f87171; margin-left:10px;">✘ Incorrect</span>'}
      </div>
      <h3>${q.s}</h3>
      <div class="opts">
        ${optionsHtml}
      </div>
      <div class="explain" style="margin-top:12px;">
        <strong>Explication :</strong> ${q.x || "Non disponible"}
      </div>
      <div class="trap">
        <strong>Piège :</strong> ${q.r || "Non disponible"}
      </div>
    `;

    area.appendChild(questionDiv);
  });

  // Bouton retour
  const btn = document.createElement("button");
  btn.textContent = "Retour à l'accueil";
  btn.style.marginTop = "20px";
  btn.style.padding = "12px 24px";
  btn.onclick = () => location.reload();
  area.appendChild(btn);

  // Sauvegarde dans l'historique
  history.push({
    date: new Date().toISOString(),
    score: score,
    total: questions.length
  });
  localStorage.setItem("secplus_history", JSON.stringify(history));
}

// ========== STATS ==========
function renderStats() {
  const area = document.getElementById("statsArea");
  if (!history.length) {
    area.innerHTML = "<p>Aucune session encore.</p>";
    return;
  }

  const totalQ = history.reduce((a, h) => a + h.total, 0);
  const totalCorrect = history.reduce((a, h) => a + h.score, 0);
  const avg = totalQ ? Math.round((totalCorrect / totalQ) * 100) : 0;

  area.innerHTML = `
    <div class="cell"><div class="v">${history.length}</div><div class="l">Sessions</div></div>
    <div class="cell"><div class="v">${totalQ}</div><div class="l">Questions</div></div>
    <div class="cell"><div class="v">${avg}%</div><div class="l">Moyenne</div></div>
  `;
}

// ========== 40-DAY PLAN ==========
function updateProgress() {
  const day = +document.getElementById("currentDay")?.value || 1;
  const pct = Math.min(100, (day / 40) * 100);
  const fill = document.getElementById("progressFill");
  const text = document.getElementById("progressText");
  if (fill) fill.style.width = pct + "%";
  if (text) text.textContent = `Day ${day} / 40`;
}
document.getElementById("currentDay")?.addEventListener("input", updateProgress);

// ========== EXPORT ==========
document.getElementById("exportBtn")?.addEventListener("click", () => {
  const data = { questions: QUESTIONS, history };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "security-plus-export.json";
  a.click();
});

// ========== INIT ==========
renderBrowse();