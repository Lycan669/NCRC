import { auth, db } from "./firebase-config.js";
import { 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword 
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";
import { 
  doc, setDoc 
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-firestore.js";

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

// CONNEXION
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  const messageEl = document.getElementById('login-message');

  try {
    await signInWithEmailAndPassword(auth, email, password);
    messageEl.style.color = '#00ffcc';
    messageEl.textContent = 'Connexion réussie ! Redirection...';
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1000);
  } catch (error) {
    messageEl.style.color = '#ff5c5c';
    if (error.code === 'auth/invalid-credential' || error.code === 'auth/wrong-password' || error.code === 'auth/user-not-found') {
      messageEl.textContent = 'Email ou mot de passe incorrect';
    } else {
      messageEl.textContent = 'Erreur : ' + error.message;
    }
  }
});

// INSCRIPTION
signupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('signup-name').value;
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;
  const messageEl = document.getElementById('signup-message');

  try {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    await setDoc(doc(db, "users", user.uid), {
      name: name,
      email: email,
      createdAt: new Date().toISOString()
    });

    messageEl.style.color = '#00ffcc';
    messageEl.textContent = 'Compte créé ! Redirection...';
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1000);
  } catch (error) {
    messageEl.style.color = '#ff5c5c';
    if (error.code === 'auth/email-already-in-use') {
      messageEl.textContent = 'Cet email est déjà utilisé';
    } else if (error.code === 'auth/weak-password') {
      messageEl.textContent = 'Mot de passe trop faible (6 caractères min)';
    } else {
      messageEl.textContent = 'Erreur : ' + error.message;
    }
  }
});