import { useState, useEffect } from "react";
import { doc, getDoc, updateDoc } from "firebase/firestore";
import { db } from "./firebase";

function EmailToggle() {
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSetting = async () => {
      try {
        const docSnap = await getDoc(doc(db, "settings", "email_notifications"));
        if (docSnap.exists()) {
          setEnabled(docSnap.data().enabled);
        }
      } catch (err) {
        console.error("Error fetching email setting:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchSetting();
  }, []);

  const handleToggle = async () => {
    try {
      const newValue = !enabled;
      setEnabled(newValue);
      await updateDoc(doc(db, "settings", "email_notifications"), { enabled: newValue });
    } catch (err) {
      console.error("Failed to update email toggle:", err);
    }
  };

  return (
    <button
      onClick={handleToggle}
      disabled={loading}
      className={`px-4 py-2 rounded font-semibold transition duration-300 shadow-md border ${
        enabled ? "bg-green-600 hover:bg-green-700" : "bg-gray-500 hover:bg-gray-600"
      } text-white`}
    >
      {enabled ? "✅ Email Alerts: ON" : "✖️ Email Alerts: OFF"}
    </button>
  );
}

export default EmailToggle;
