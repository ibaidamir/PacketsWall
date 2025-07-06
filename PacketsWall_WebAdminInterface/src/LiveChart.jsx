import React, { useEffect, useState } from "react";
import { db } from "./firebase";
import { collection, onSnapshot } from "firebase/firestore";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

export default function LiveChart() {
  const [data, setData] = useState([]);

  useEffect(() => {
    const unsubscribe = onSnapshot(collection(db, "network_logs"), (snapshot) => {
      const logs = [];
      snapshot.forEach((doc) => {
        const { timestamp } = doc.data();
        if (timestamp) {
          logs.push(timestamp);
        }
      });

      const grouped = {};
      logs.forEach((ts) => {
        const time = ts.split(" ")[1]?.slice(0, 5); // "13:30"
        if (!time) return;
        grouped[time] = (grouped[time] || 0) + 1;
      });

      const chartData = Object.entries(grouped).map(([time, count]) => ({
        time,
        count,
      }));

      chartData.sort((a, b) => (a.time > b.time ? 1 : -1));
      setData(chartData);
    });

    return () => unsubscribe();
  }, []);

  return (
    <ResponsiveContainer width="100%" height={280}>
      <LineChart data={data}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis allowDecimals={false} />
        <Tooltip />
        <Line
          type="monotone"
          dataKey="count"
          stroke="#00bcd4"
          strokeWidth={3}
          dot={{ r: 4 }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}