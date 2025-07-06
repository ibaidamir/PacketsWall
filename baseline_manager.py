# baseline_manager.py

import firebase_admin
from firebase_admin import credentials, firestore
import os
import time
import logging

# إعداد logging
logger = logging.getLogger('BaselineManager')

# ✅ اسم ملف المفاتيح الحالي
FIREBASE_CREDENTIAL_FILE = "packetswall-firebase-key.json"

# تأكد من تحميل Firebase فقط مرة واحدة
if not firebase_admin._apps:
    cred = credentials.Certificate(FIREBASE_CREDENTIAL_FILE)
    firebase_admin.initialize_app(cred)

db = firestore.client()

class BaselineManager:
    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self.cache = {}  # كاش داخلي لتقليل القراءات المتكررة
        self.last_save_time = {}  # تتبع آخر وقت حفظ لكل protocol
        self.save_interval = 30  # حفظ كل 30 ثانية كحد أقصى
        
    def load_max_adaptive_threshold(self, protocol: str) -> float:
        """تحميل أعلى adaptive threshold محفوظ من فايربيس لبروتوكول معين"""
        cache_key = f"max_adaptive_{protocol}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            doc_ref = db.collection("max_adaptive_thresholds").document(protocol)
            doc = doc_ref.get()
            if doc.exists:
                data = doc.to_dict()
                value = data.get("max_threshold", 0.0)
                self.cache[cache_key] = value
                logger.info(f"[Firebase] Loaded {protocol.upper()} max adaptive threshold: {value:.2f}")
                return value
            else:
                logger.info(f"[Firebase] No max adaptive threshold found for {protocol.upper()}, using default")
                return 0.0
        except Exception as e:
            logger.error(f"[Firebase] Error loading max adaptive threshold for {protocol}: {e}")
            return 0.0

    def save_max_adaptive_threshold(self, protocol: str, threshold: float):
        """حفظ أعلى adaptive threshold في فايربيس (فقط إذا كان أعلى من المحفوظ)"""
        try:
            cache_key = f"max_adaptive_{protocol}"
            current_max = self.load_max_adaptive_threshold(protocol)
            
            # احفظ فقط إذا كانت القيمة الجديدة أعلى
            if threshold > current_max:
                self.cache[cache_key] = threshold
                current_time = time.time()
                
                # حفظ البيانات مع timestamp
                db.collection("max_adaptive_thresholds").document(protocol).set({
                    "max_threshold": threshold,
                    "last_updated": current_time,
                    "timestamp": firestore.SERVER_TIMESTAMP
                })
                
                logger.info(f"[Firebase] Updated {protocol.upper()} max adaptive threshold: {current_max:.2f} → {threshold:.2f}")
                return True
            else:
                logger.debug(f"[Firebase] {protocol.upper()} threshold {threshold:.2f} not higher than max {current_max:.2f}")
                return False
            
        except Exception as e:
            logger.error(f"[Firebase] Error saving max adaptive threshold for {protocol}: {e}")
            return False

    def reset_max_adaptive_threshold(self, protocol: str):
        """إعادة تعيين max adaptive threshold لبروتوكول معين"""
        try:
            cache_key = f"max_adaptive_{protocol}"
            if cache_key in self.cache:
                del self.cache[cache_key]
            
            db.collection("max_adaptive_thresholds").document(protocol).delete()
            logger.info(f"[Firebase] Reset max adaptive threshold for {protocol.upper()}")
            
        except Exception as e:
            logger.error(f"[Firebase] Error resetting max adaptive threshold for {protocol}: {e}")

    def get_all_max_adaptive_thresholds(self) -> dict:
        """الحصول على جميع max adaptive thresholds المحفوظة"""
        try:
            docs = db.collection("max_adaptive_thresholds").stream()
            thresholds = {}
            
            for doc in docs:
                data = doc.to_dict()
                thresholds[doc.id] = {
                    'max_threshold': data.get('max_threshold', 0.0),
                    'last_updated': data.get('last_updated', 0),
                    'timestamp': data.get('timestamp')
                }
            
            return thresholds
            
        except Exception as e:
            logger.error(f"[Firebase] Error getting all max adaptive thresholds: {e}")
            return {}

    # ✅ الدوال القديمة للـ baseline (للتوافق مع الكود الموجود)
    def load_baseline(self, protocol: str) -> float:
        """دالة للتوافق مع الكود القديم - ترجع 0 دائماً"""
        return 0.0

    def save_baseline(self, protocol: str, value: float):
        """دالة للتوافق مع الكود القديم - لا تفعل شيء"""
        pass

    def update_baseline(self, protocol: str, new_value: float, is_ddos: bool = False):
        """دالة للتوافق مع الكود القديم - لا تفعل شيء"""
        pass

    def is_ddos_detected(self, protocol: str, current_traffic: float, threshold_multiplier: float = 2.0) -> bool:
        """دالة للتوافق مع الكود القديم - ترجع False دائماً"""
        return False

    def get_adaptive_threshold(self, protocol: str, multiplier: float = 1.5) -> float:
        """دالة للتوافق مع الكود القديم - ترجع 0 دائماً"""
        return 0.0

    def reset_baseline(self, protocol: str):
        """دالة للتوافق مع الكود القديم - لا تفعل شيء"""
        pass

    def get_all_baselines(self) -> dict:
        """دالة للتوافق مع الكود القديم - ترجع dict فارغ"""
        return {}

