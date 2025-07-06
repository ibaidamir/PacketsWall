import React, { useEffect, useState } from "react";
import { db } from "../firebase";
import { collection, onSnapshot, query, orderBy, limit } from "firebase/firestore";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid
} from "recharts";

const COLORS = ["#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6", "#06B6D4"];

export default function LiveDashboard() {
  const [protocolCounts, setProtocolCounts] = useState([]);
  const [recentLogs, setRecentLogs] = useState([]);
  const [attackTrends, setAttackTrends] = useState([]);

  useEffect(() => {
    // Protocol distribution
    const unsubscribeProtocols = onSnapshot(collection(db, "network_logs"), (snapshot) => {
      const counts = {};
      snapshot.docs.forEach((doc) => {
        const data = doc.data();
        const protocol = data.protocol || "Unknown";
        counts[protocol] = (counts[protocol] || 0) + 1;
      });
      const chartData = Object.keys(counts).map((key) => ({
        name: key,
        value: counts[key],
      }));
      setProtocolCounts(chartData);
    });

    // Recent logs
    const q = query(collection(db, "network_logs"), orderBy("timestamp", "desc"), limit(10));
    const unsubscribeLogs = onSnapshot(q, (snapshot) => {
      const logsData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      setRecentLogs(logsData);
    });

    // Attack trends (simulated for demo)
    const generateTrends = () => {
      const trends = [];
      for (let i = 23; i >= 0; i--) {
        const hour = new Date();
        hour.setHours(hour.getHours() - i);
        trends.push({
          time: hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
          attacks: Math.floor(Math.random() * 50) + 10
        });
      }
      setAttackTrends(trends);
    };

    generateTrends();
    const interval = setInterval(generateTrends, 60000); // Update every minute

    return () => {
      unsubscribeProtocols();
      unsubscribeLogs();
      clearInterval(interval);
    };
  }, []);

  return (
    <section className="py-20 bg-gradient-to-b from-black to-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold mb-4">
            Live Network <span className="text-blue-400">Monitoring</span>
          </h2>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Real-time insights into network security threats and system performance
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
          {/* Protocol Distribution */}
          <div className="bg-gray-800 bg-opacity-50 backdrop-blur-sm rounded-2xl p-6 border border-gray-700">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-white">Attack Distribution by Protocol</h3>
              <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={protocolCounts}
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {protocolCounts.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Attack Trends */}
          <div className="bg-gray-800 bg-opacity-50 backdrop-blur-sm rounded-2xl p-6 border border-gray-700">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-white">24-Hour Attack Trends</h3>
              <div className="w-3 h-3 bg-blue-400 rounded-full animate-pulse"></div>
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={attackTrends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" fontSize={12} />
                <YAxis stroke="#9CA3AF" fontSize={12} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1F2937', 
                    border: '1px solid #374151',
                    borderRadius: '8px'
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="attacks" 
                  stroke="#3B82F6" 
                  strokeWidth={2}
                  dot={{ fill: '#3B82F6', strokeWidth: 2, r: 4 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Threats Table */}
        <div className="bg-gray-800 bg-opacity-50 backdrop-blur-sm rounded-2xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-white">Recent Threat Detections</h3>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-400 rounded-full animate-pulse"></div>
              <span className="text-sm text-gray-400">Live Updates</span>
            </div>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 font-semibold text-gray-300">Timestamp</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-300">Protocol</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-300">Source IP</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-300">Threat Type</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-300">Status</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="text-center py-8 text-gray-400">
                      No recent threats detected
                    </td>
                  </tr>
                ) : (
                  recentLogs.map((log, index) => (
                    <tr key={log.id} className="border-b border-gray-700 hover:bg-gray-700 hover:bg-opacity-30 transition-colors">
                      <td className="py-3 px-4 text-gray-300 font-mono text-sm">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          log.protocol === 'HTTP' ? 'bg-blue-900 text-blue-300' :
                          log.protocol === 'TCP' ? 'bg-green-900 text-green-300' :
                          log.protocol === 'UDP' ? 'bg-yellow-900 text-yellow-300' :
                          'bg-purple-900 text-purple-300'
                        }`}>
                          {log.protocol}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-300 font-mono text-sm">
                        {log.suspect_ip}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-900 text-red-300">
                          {log.type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-1 rounded-full text-xs font-medium bg-green-900 text-green-300">
                          Blocked
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  );
}

