import firebase_admin
from firebase_admin import credentials, firestore
import os
import sys

def resource_path(relative_path):
    """يحصل على المسار الصحيح للملفات داخل .exe أو بيئة التطوير"""
    try:
        base_path = sys._MEIPASS  # لما يكون شغّال من .exe
    except AttributeError:
        base_path = os.path.abspath(".")  # لما يكون شغّال من Python مباشرة
    return os.path.join(base_path, relative_path)

# المسار إلى ملف المفاتيح
FIREBASE_KEY_PATH = resource_path("packetswall-firebase-key.json")

# تهيئة الاتصال (مرة واحدة فقط)
if not firebase_admin._apps:
    cred = credentials.Certificate(FIREBASE_KEY_PATH)
    firebase_admin.initialize_app(cred)

# عميل قاعدة البيانات
db = firestore.client()

def upload_log(log_data: dict, collection="network_logs"):
    """
    يرفع سجل إلى Firestore
    """
    try:
        doc_ref = db.collection(collection).add(log_data)
        print(f"✅ Uploaded to Firestore: {doc_ref}")
    except Exception as e:
        print(f"❌ Upload failed: {e}")
