import { useEffect, useState } from "react";
import { collection, query, orderBy, onSnapshot } from "firebase/firestore";
import { db } from "./firebase";

function LogsTable() {
  const [logs, setLogs] = useState([]);
  const [searchIp, setSearchIp] = useState("");
  const [filterProtocol, setFilterProtocol] = useState("");
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    const q = query(collection(db, "network_logs"), orderBy("timestamp", "desc"));

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const logsData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      setLogs(logsData);
    });

    return () => unsubscribe(); // تنظيف الاشتراك عند إغلاق المكون
  }, []);

  const filteredLogs = logs.filter(log => {
    const matchesIp = searchIp === "" || log.suspect_ip?.includes(searchIp);
    const matchesProtocol = filterProtocol === "" || log.protocol === filterProtocol;
    return matchesIp && matchesProtocol;
  });

  const toggleTheme = () => setDarkMode(!darkMode);

  return (
    <div className={`min-h-screen ${darkMode ? "bg-gradient-to-br from-gray-900 to-black text-white" : "bg-white text-gray-900"} p-6`}>
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-4xl font-extrabold drop-shadow"> Network Logs</h1>
        <button
          onClick={toggleTheme}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold"
        >
          {darkMode ? "☀️ Light Mode" : "🌙 Dark Mode"}
        </button>
      </div>

      <div className="flex flex-col md:flex-row items-center gap-4 mb-6">
        <input
          type="text"
          placeholder=" Search by IP"
          className="px-4 py-2 w-full md:w-64 rounded-lg text-black focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={searchIp}
          onChange={(e) => setSearchIp(e.target.value)}
        />

        <select
          className="px-4 py-2 w-full md:w-52 rounded-lg text-black focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={filterProtocol}
          onChange={(e) => setFilterProtocol(e.target.value)}
        >
          <option value=""> All Protocols</option>
          <option value="HTTP">HTTP</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
        </select>
      </div>

      <div className={`overflow-x-auto ${darkMode ? "bg-white bg-opacity-5 text-white" : "bg-gray-100 text-black"} rounded-xl shadow-lg`}>
        <table className="min-w-full table-auto">
          <thead>
            <tr className={darkMode ? "bg-white bg-opacity-10" : "bg-gray-300"}>
              <th className="px-6 py-3 text-left font-semibold tracking-wide"> Timestamp</th>
              <th className="px-6 py-3 text-left font-semibold tracking-wide"> Protocol</th>
              <th className="px-6 py-3 text-left font-semibold tracking-wide"> Suspect IP</th>
              <th className="px-6 py-3 text-left font-semibold tracking-wide"> Type</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="4" className="text-center py-6 text-gray-400">
                   No logs found.
                </td>
              </tr>
            ) : (
              filteredLogs.map(log => (
                <tr key={log.id} className="hover:bg-white hover:bg-opacity-10 transition">
                  <td className="px-6 py-3 border-b border-white border-opacity-10">{log.timestamp}</td>
                  <td className="px-6 py-3 border-b border-white border-opacity-10">{log.protocol}</td>
                  <td className="px-6 py-3 border-b border-white border-opacity-10">{log.suspect_ip}</td>
                  <td className="px-6 py-3 border-b border-white border-opacity-10 font-bold text-red-400">
                    {log.type}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default LogsTable;
