import React, { useEffect, useState } from "react";
import { db } from "../firebase";
import { collection, onSnapshot } from "firebase/firestore";

export default function HeroSection() {
  const [stats, setStats] = useState({
    totalLogs: 0,
    uptime: 99.2,
    responseTime: 1.2,
    protocolCounts: {}
  });

  useEffect(() => {
    const unsubscribe = onSnapshot(collection(db, "network_logs"), (snapshot) => {
      const totalLogs = snapshot.docs.length;
      const protocolCounts = {};

      snapshot.docs.forEach((doc) => {
        const data = doc.data();
        const protocol = data.protocol || "Unknown";
        protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
      });

      setStats({
        totalLogs,
        uptime: 99.2,
        responseTime: 1.2,
        protocolCounts
      });
    });

    return () => unsubscribe();
  }, []);

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black">
        <div className="absolute inset-0 opacity-20">
          {[...Array(50)].map((_, i) => (
            <div
              key={i}
              className="absolute w-1 h-1 bg-white rounded-full animate-pulse"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 3}s`,
                animationDuration: `${2 + Math.random() * 3}s`
              }}
            />
          ))}
        </div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <div className="mb-8">
          <span className="inline-block px-4 py-2 bg-gray-800 rounded-full text-sm font-medium text-gray-300 mb-6">
            Advanced DDoS Protection
          </span>
        </div>

        <div className="flex flex-col lg:flex-row items-center justify-between gap-12">
          {/* Left Content */}
          <div className="lg:w-1/2 text-left">
            <h1 className="text-5xl lg:text-6xl font-bold mb-6 leading-tight">
              Protecting Your
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
                Network From
              </span>
              <br />
              Cyber Threats
            </h1>

            {/* ✅ الجملة بنمط text-justify */}
            <p className="text-xl text-gray-300 mb-8 leading-relaxed text-justify max-w-prose">
              PacketsWall is an advanced DDoS detection and prevention system designed to safeguard 
              networks from various types of cyber attacks including TCP SYN Flood, UDP Flood, HTTP 
              Flood, and ICMP Flood attacks.
            </p>

            {/* Real-time Stats */}
            <div className="grid grid-cols-3 gap-6 mb-8">
              <div className="text-center">
                <div className="text-3xl font-bold text-white mb-1">
                  {stats.uptime}%
                </div>
                <div className="text-sm text-gray-400">Uptime</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-white mb-1">
                  +30
                </div>
                <div className="text-sm text-gray-400">Threats Blocked</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-white mb-1">
                  {stats.responseTime}s
                </div>
                <div className="text-sm text-gray-400">Response Time</div>
              </div>
            </div>
          </div>

          {/* Right Content */}
          <div className="lg:w-1/2 flex justify-center">
            <div className="relative">
              {/* Outer rotating rings */}
              <div className="absolute inset-0 w-80 h-80 rounded-full border border-gray-600 animate-spin-slow opacity-30"></div>
              <div className="absolute inset-4 w-72 h-72 rounded-full border border-gray-500 animate-spin-reverse opacity-40"></div>
              <div className="absolute inset-8 w-64 h-64 rounded-full border border-gray-400 animate-spin-slow opacity-50"></div>

              {/* Central logo */}
              <div className="relative w-80 h-80 flex items-center justify-center">
                <img
                  src="/packetswall-logo-white.png"
                  alt="PacketsWall Logo"
                  className="w-150 h-150 object-contain hover:scale-110 transition-transform duration-300"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes spin-slow {
          from {
            transform: rotate(0deg);
          }
          to {
            transform: rotate(360deg);
          }
        }
        @keyframes spin-reverse {
          from {
            transform: rotate(360deg);
          }
          to {
            transform: rotate(0deg);
          }
        }
        .animate-spin-slow {
          animation: spin-slow 20s linear infinite;
        }
        .animate-spin-reverse {
          animation: spin-reverse 15s linear infinite;
        }
      `}</style>
    </section>
  );
}
