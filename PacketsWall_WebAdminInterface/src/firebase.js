// Import the functions you need
import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyAWQD6gLm8bUVoozgdNczoeTLcTUD7Qi0I",
  authDomain: "packetswall.firebaseapp.com",
  projectId: "packetswall",
  storageBucket: "packetswall.firebasestorage.app",
  messagingSenderId: "98728983152",
  appId: "1:98728983152:web:046585931d21a66c1212b5",
  measurementId: "G-3VQYJ78ZFL"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// ✅ هذا هو المطلوب تصديره
export const db = getFirestore(app);