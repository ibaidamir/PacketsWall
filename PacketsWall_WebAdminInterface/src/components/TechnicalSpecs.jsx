import React from "react";

export default function TechnicalSpecs() {
  const coretech = [
    { name: "Python 3.x",},
    { name: "Scapy 2.6.1+" },
    { name: "Tkinter GUI"},
    { name: "Firebase Realtime Database" }
  ];

  const detection = [
    { name: "TCP SYN Flood"},
    { name: "UDP Flood" },
    { name: "HTTP Flood" },
    { name: "ICMP Flood" }
  ];

  const requirements = [
    { name: "Windows 10/11" },
    { name: "Linux (Ubuntu/CentOS)" },
    { name: "4GB+ RAM"},
    { name: "Admin Privileges"}
  ];

  return (
    <section className="py-20 bg-black">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold mb-4">
            Technical <span className="text-blue-400">Specifications</span>
          </h2>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Built with cutting-edge technologies for maximum performance
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Core Technologies */}
          <div className="bg-black rounded-2xl p-6 border border-gray-700">
            <h3 className="text-2xl font-semibold text-white mb-6 text-center">
              Core Technologies
            </h3>
            <div className="space-y-4">
              {coretech.map((tech, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-4 p-4 bg-gray-700 bg-opacity-50 rounded-xl hover:bg-opacity-70 transition-all duration-300"
                >
                  <span className="text-2xl">{tech.icon}</span>
                  <span className="text-white font-medium">{tech.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Detection Capabilities */}
          <div className="bg-black rounded-2xl p-6 border border-gray-700">
            <h3 className="text-2xl font-semibold text-white mb-6 text-center">
              Detection Capabilities
            </h3>
            <div className="space-y-4">
              {detection.map((capability, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-4 p-4 bg-gray-700 bg-opacity-50 rounded-xl hover:bg-opacity-70 transition-all duration-300"
                >
                  <span className="text-2xl">{capability.icon}</span>
                  <span className="text-white font-medium">{capability.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* System Requirements */}
          <div className="bg-black rounded-2xl p-6 border border-gray-700">
            <h3 className="text-2xl font-semibold text-white mb-6 text-center">
              System Requirements
            </h3>
            <div className="space-y-4">
              {requirements.map((req, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-4 p-4 bg-gray-700 bg-opacity-50 rounded-xl hover:bg-opacity-70 transition-all duration-300"
                >
                  <span className="text-2xl">{req.icon}</span>
                  <span className="text-white font-medium">{req.name}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
