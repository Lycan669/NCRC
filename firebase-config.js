import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyA_XyYW0lYibsz9PofAbfpTIEvghnFAQds",
  authDomain: "ncrc-c13f9.firebaseapp.com",
  projectId: "ncrc-c13f9",
  storageBucket: "ncrc-c13f9.firebasestorage.app",
  messagingSenderId: "223298485519",
  appId: "1:223298485519:web:a177040239d0285b09527a",
  measurementId: "G-FCBL340SK3"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);