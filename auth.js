const loginForm = document.getElementById('login-form');
const signupForm = document.getElementById('signup-form');
const toggleBtn = document.getElementById('toggle-btn');
const toggleText = document.getElementById('toggle-text');
const formTitle = document.getElementById('form-title');

let isLogin = true;

toggleBtn.addEventListener('click', (e) => {
  e.preventDefault();
  isLogin = !isLogin;
  if (isLogin) {
    loginForm.style.display = 'block';
    signupForm.style.display = 'none';
    formTitle.textContent = 'Connexion';
    toggleText.textContent = 'Pas encore de compte ?';
    toggleBtn.textContent = "S'inscrire";
  } else {
    loginForm.style.display = 'none';
    signupForm.style.display = 'block';
    formTitle.textContent = 'Créer un compte';
    toggleText.textContent = 'Déjà inscrit ?';
    toggleBtn.textContent = 'Se connecter';
  }
});

loginForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  document.getElementById('login-message').textContent = 
    `Connexion simulée pour ${email} (backend à connecter)`;
});

signupForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('signup-email').value;
  document.getElementById('signup-message').textContent = 
    `Compte créé pour ${email} (backend à connecter)`;
});