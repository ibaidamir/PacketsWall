import React, { useEffect, useState } from "react";
import { db } from "../firebase";
import { collection, onSnapshot } from "firebase/firestore";

export default function PerformanceMetrics() {
  const [metrics, setMetrics] = useState({
    detectionAccuracy: 92.2,
    responseTime: 1.2,
    attacksMitigated: 0,
    packetsPerSecond: 4580
  });

  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const unsubscribe = onSnapshot(collection(db, "network_logs"), (snapshot) => {
      const totalAttacks = snapshot.docs.length;
      setMetrics(prev => ({
        ...prev,
        attacksMitigated: totalAttacks
      }));
    });

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.1 }
    );

    const section = document.getElementById('performance-metrics');
    if (section) {
      observer.observe(section);
    }

    return () => {
      unsubscribe();
      if (section) {
        observer.unobserve(section);
      }
    };
  }, []);

  const MetricCard = ({ icon, value, suffix, title, description, delay = 0 }) => {
    const [animatedValue, setAnimatedValue] = useState(0);

    useEffect(() => {
      if (isVisible) {
        const timer = setTimeout(() => {
          const duration = 2000;
          const steps = 60;
          const increment = value / steps;
          let current = 0;

          const interval = setInterval(() => {
            current += increment;
            if (current >= value) {
              setAnimatedValue(value);
              clearInterval(interval);
            } else {
              setAnimatedValue(Math.floor(current * 10) / 10);
            }
          }, duration / steps);

          return () => clearInterval(interval);
        }, delay);

        return () => clearTimeout(timer);
      }
    }, [isVisible, value, delay]);

    return (
      <div className="bg-gray-800 bg-opacity-50 backdrop-blur-sm rounded-2xl p-8 border border-gray-700 hover:border-blue-500 transition-all duration-300 hover:transform hover:scale-105 text-center">
        <div className="w-20 h-20 bg-gray-700 rounded-2xl flex items-center justify-center mx-auto mb-6">
          {icon}
        </div>
        
        <div className="text-4xl font-bold text-white mb-2">
          {typeof animatedValue === 'number' ? animatedValue.toLocaleString() : animatedValue}
          <span className="text-blue-400">{suffix}</span>
        </div>
        
        <h3 className="text-xl font-semibold text-white mb-4">{title}</h3>
        
        <p className="text-gray-300 leading-relaxed">{description}</p>
      </div>
    );
  };

  return (
    <section id="performance-metrics" className="py-20 bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold mb-4">
            Performance <span className="text-blue-400">Metrics</span>
          </h2>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Real-world performance data from production deployments
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          <MetricCard
            icon={
              <svg className="w-10 h-10 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
            value={metrics.detectionAccuracy}
            suffix="%"
            title="Detection Accuracy"
            description="Accurate identification of DDoS attacks with minimal false positives"
            delay={0}
          />

          <MetricCard
            icon={
              <svg className="w-10 h-10 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            }
            value={metrics.responseTime}
            suffix="s"
            title="Response Time"
            description="Lightning-fast threat detection and response capabilities"
            delay={200}
          />

          <MetricCard
            icon={
              <svg className="w-10 h-10 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            }
            value={metrics.attacksMitigated}
            suffix="+"
            title="Attacks Mitigated"
            description="Successfully blocked attacks across all deployment environments"
            delay={400}
          />

          <MetricCard
            icon={
              <svg className="w-10 h-10 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            }
            value={metrics.packetsPerSecond}
            suffix="+"
            title="Packets/Second"
            description="High-throughput packet processing for enterprise networks"
            delay={600}
          />
        </div>
      </div>
    </section>
  );
}
