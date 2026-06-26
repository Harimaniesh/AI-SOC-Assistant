import React, { useEffect, useState } from 'react';
import { ShieldAlert, AlertTriangle, Info, Terminal, TrendingUp, UserMinus, ShieldCheck } from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';
import { api } from '../utils/api';

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement);

export default function Dashboard({ onViewAlert }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchStats = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/dashboard/stats');
      setStats(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // Set up auto-refresh every 30 seconds for live SOC feel
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px]">
        <div className="w-12 h-12 rounded-full border-4 border-cyber-accent border-t-transparent animate-spin mb-4" />
        <p className="text-cyber-text text-sm font-mono tracking-widest uppercase">FETCHING SOC METRICS...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 font-mono text-center">
        {error}
      </div>
    );
  }

  // Fallbacks if database is empty
  const total = stats?.total_alerts || 0;
  const critical = stats?.critical_alerts || 0;
  const medium = stats?.medium_alerts || 0;
  const low = stats?.low_alerts || 0;

  // Chart Data: Threat Types Pie Chart
  const threatTypeLabels = Object.keys(stats?.threat_types || {});
  const threatTypeDataPoints = Object.values(stats?.threat_types || {});
  
  const pieChartData = {
    labels: threatTypeLabels.length ? threatTypeLabels : ['No Detections'],
    datasets: [{
      data: threatTypeDataPoints.length ? threatTypeDataPoints : [1],
      backgroundColor: [
        '#ef4444', // Red (Critical/Malware)
        '#f97316', // Orange (Port scan/Brute force)
        '#3b82f6', // Blue (Suspicious IP)
        '#10b981', // Green (Privilege escalation/other)
        '#8b5cf6', // Purple
      ].slice(0, threatTypeLabels.length ? threatTypeLabels.length : 1),
      borderColor: '#0f172a',
      borderWidth: 2,
    }]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#cbd5e1',
          font: { family: 'Outfit', size: 11 }
        }
      },
      tooltip: {
        backgroundColor: '#090d16',
        titleFont: { family: 'Outfit', size: 12 },
        bodyFont: { family: 'Outfit', size: 12 },
        borderColor: '#1e293b',
        borderWidth: 1
      }
    }
  };

  // Timeline Bar Chart Data
  const recentAlerts = stats?.recent_timeline || [];
  const barChartData = {
    labels: recentAlerts.slice(0, 8).map(a => new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })).reverse(),
    datasets: [{
      label: 'Severity Level',
      data: recentAlerts.slice(0, 8).map(a => a.severity).reverse(),
      backgroundColor: recentAlerts.slice(0, 8).map(a => {
        if (a.severity >= 9) return '#ef4444';
        if (a.severity >= 7) return '#f97316';
        if (a.severity >= 4) return '#3b82f6';
        return '#10b981';
      }).reverse(),
      borderRadius: 4,
    }]
  };

  const barChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#090d16',
        borderColor: '#1e293b',
        borderWidth: 1
      }
    },
    scales: {
      y: {
        min: 0,
        max: 10,
        grid: { color: '#1e293b' },
        ticks: { color: '#94a3b8', font: { family: 'Outfit' } }
      },
      x: {
        grid: { display: false },
        ticks: { color: '#94a3b8', font: { family: 'Outfit' } }
      }
    }
  };

  return (
    <div className="space-y-6 font-sans">
      
      {/* 4 Stat Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Total Alerts */}
        <div className="bg-cyber-card/50 border border-cyber-border rounded-xl p-5 shadow-2xl relative overflow-hidden group hover:border-cyber-accent/40 transition-all duration-300">
          <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
            <Terminal className="w-20 h-20 text-cyber-accent" />
          </div>
          <p className="text-xs uppercase tracking-wider text-cyber-text font-mono">Total Threats Logged</p>
          <p className="text-4xl font-extrabold text-slate-100 mt-2 font-sans tracking-tight">{total}</p>
          <div className="mt-3 flex items-center text-xs text-cyber-accent font-mono">
            <TrendingUp className="w-3.5 h-3.5 mr-1" />
            <span>Active monitoring live</span>
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-cyber-card/50 border border-cyber-border rounded-xl p-5 shadow-2xl relative overflow-hidden group hover:border-red-500/40 transition-all duration-300">
          <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
            <ShieldAlert className="w-20 h-20 text-red-500" />
          </div>
          <p className="text-xs uppercase tracking-wider text-cyber-text font-mono">Critical (9-10)</p>
          <p className="text-4xl font-extrabold text-red-500 mt-2 font-sans tracking-tight">{critical}</p>
          <div className="mt-3 flex items-center text-xs text-red-400 font-mono">
            <AlertTriangle className="w-3.5 h-3.5 mr-1 text-red-500" />
            <span>Requires containment</span>
          </div>
        </div>

        {/* High/Medium Alerts */}
        <div className="bg-cyber-card/50 border border-cyber-border rounded-xl p-5 shadow-2xl relative overflow-hidden group hover:border-orange-500/40 transition-all duration-300">
          <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
            <AlertTriangle className="w-20 h-20 text-orange-500" />
          </div>
          <p className="text-xs uppercase tracking-wider text-cyber-text font-mono">Medium/High (4-8)</p>
          <p className="text-4xl font-extrabold text-orange-500 mt-2 font-sans tracking-tight">{medium}</p>
          <div className="mt-3 flex items-center text-xs text-orange-400 font-mono">
            <Info className="w-3.5 h-3.5 mr-1 text-orange-500" />
            <span>Investigation recommended</span>
          </div>
        </div>

        {/* Low Alerts */}
        <div className="bg-cyber-card/50 border border-cyber-border rounded-xl p-5 shadow-2xl relative overflow-hidden group hover:border-emerald-500/40 transition-all duration-300">
          <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
            <ShieldCheck className="w-20 h-20 text-emerald-500" />
          </div>
          <p className="text-xs uppercase tracking-wider text-cyber-text font-mono">Low Severity (1-3)</p>
          <p className="text-4xl font-extrabold text-emerald-500 mt-2 font-sans tracking-tight">{low}</p>
          <div className="mt-3 flex items-center text-xs text-emerald-400 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-500" />
            <span>No immediate threat</span>
          </div>
        </div>

      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Threat Type Breakdown Pie Chart */}
        <div className="bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col h-[320px]">
          <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono mb-4 border-b border-cyber-border pb-2">
            Threat Vectors Distribution
          </h2>
          <div className="flex-1 relative min-h-0">
            {threatTypeLabels.length ? (
              <Pie data={pieChartData} options={chartOptions} />
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-sm">
                No telemetry threats registered.
              </div>
            )}
          </div>
        </div>

        {/* Attack Volume Timeline */}
        <div className="bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col h-[320px]">
          <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono mb-4 border-b border-cyber-border pb-2">
            Recent Alert Severity Timeline
          </h2>
          <div className="flex-1 relative min-h-0">
            {recentAlerts.length ? (
              <Bar data={barChartData} options={barChartOptions} />
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-sm">
                Timeline telemetry empty.
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Attacker IPs and Recent Timeline logs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Top 5 Attacker IPs */}
        <div className="bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl h-[400px] flex flex-col">
          <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono mb-3 border-b border-cyber-border pb-2">
            Top Attacker IPs
          </h2>
          <div className="flex-1 overflow-y-auto">
            {stats?.top_attackers?.length ? (
              <div className="divide-y divide-cyber-border">
                {stats.top_attackers.map((item, index) => (
                  <div key={item.ip} className="flex justify-between items-center py-3">
                    <div className="flex items-center space-x-3">
                      <span className="text-xs font-mono font-bold w-5 text-cyber-accent">#{index + 1}</span>
                      <span className="font-mono text-sm text-slate-100">{item.ip}</span>
                    </div>
                    <span className="px-2.5 py-1 rounded bg-cyber-bg border border-cyber-border text-xs font-mono text-slate-300">
                      {item.count} alerts
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-xs">
                No attacker data.
              </div>
            )}
          </div>
        </div>

        {/* Live Attack Timeline Feed */}
        <div className="lg:col-span-2 bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl h-[400px] flex flex-col">
          <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono mb-3 border-b border-cyber-border pb-2">
            Live Threat Stream
          </h2>
          <div className="flex-1 overflow-y-auto">
            {recentAlerts.length ? (
              <div className="divide-y divide-cyber-border">
                {recentAlerts.map(alert => {
                  let badgeStyles = 'bg-slate-800 text-slate-300';
                  if (alert.severity >= 9) badgeStyles = 'bg-red-500/10 border border-red-500/20 text-red-400';
                  else if (alert.severity >= 7) badgeStyles = 'bg-orange-500/10 border border-orange-500/20 text-orange-400';
                  else if (alert.severity >= 4) badgeStyles = 'bg-blue-500/10 border border-blue-500/20 text-blue-400';
                  else badgeStyles = 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400';

                  return (
                    <div 
                      key={alert.id} 
                      onClick={() => onViewAlert(alert.id)}
                      className="flex items-center justify-between py-3 hover:bg-cyber-bg/40 cursor-pointer px-2 rounded-lg transition-colors group"
                    >
                      <div className="flex flex-col space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-semibold text-sm text-slate-200 group-hover:text-cyber-accent transition-colors">
                            {alert.threat_type}
                          </span>
                          <span className="text-xs text-slate-500 font-mono">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <span className="text-xs text-cyber-text font-mono">Source IP: {alert.source_ip}</span>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${badgeStyles}`}>
                          Sev {alert.severity}
                        </span>
                        <span className="text-xs text-slate-500 border border-cyber-border px-1.5 py-0.5 rounded uppercase font-mono">
                          {alert.status}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-xs">
                Log stream empty. Please upload logs to analyze.
              </div>
            )}
          </div>
        </div>

      </div>

    </div>
  );
}
