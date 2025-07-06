import React, { useEffect, useState } from "react";
import { db } from "./firebase";
import { collection, onSnapshot } from "firebase/firestore";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import LiveChart from "./LiveChart";

const COLORS = ["#8884d8", "#82ca9d", "#ffc658", "#ff6666"];

export default function DashboardLogs() {
  const [protocolCounts, setProtocolCounts] = useState([]);

  useEffect(() => {
    const unsubscribe = onSnapshot(collection(db, "network_logs"), (snapshot) => {
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
    return () => unsubscribe();
  }, []);

  return (
    <div className="flex flex-col lg:flex-row gap-6 mb-6">
      {/* Pie Chart */}
      <div className="w-full lg:w-1/2 bg-gradient-to-br from-gray-900 to-black text-white rounded-2xl p-4 shadow">
        <h2 className="text-xl font-semibold mb-4">📊 Attack Distribution by Protocol</h2>
        <ResponsiveContainer width="100%" height={280}>
          <PieChart>
            <Pie
              data={protocolCounts}
              cx="50%"
              cy="50%"
              outerRadius={100}
              fill="#8884d8"
              dataKey="value"
              label
            >
              {protocolCounts.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Live Chart */}
      <div className="w-full lg:w-1/2 bg-gradient-to-br from-gray-900 to-black text-white rounded-2xl p-4 shadow">
        <h2 className="text-xl font-semibold mb-4">📈 Live Attack Rate</h2>
        <LiveChart />
      </div>
    </div>
  );
}
