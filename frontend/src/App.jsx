import React, { useEffect, useState } from 'react';
import { 
  LayoutDashboard, 
  UploadCloud, 
  ShieldAlert, 
  FileText, 
  Terminal, 
  LogOut, 
  Activity, 
  User as UserIcon,
  ShieldAlert as ShieldIcon
} from 'lucide-react';
import { getAuthUser, clearAuth } from './utils/api';
import Auth from './components/Auth';
import Dashboard from './components/Dashboard';
import AlertTable from './components/AlertTable';
import LogUpload from './components/LogUpload';
import IncidentReports from './components/IncidentReports';
import Chatbot from './components/Chatbot';

export default function App() {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [highlightAlertId, setHighlightAlertId] = useState(null);
  const [chatbotAlertContext, setChatbotAlertContext] = useState(null);
  const [systemTime, setSystemTime] = useState(new Date());

  // Check login state on load
  useEffect(() => {
    const activeUser = getAuthUser();
    if (activeUser) {
      setUser(activeUser);
    }

    // Refresh clock
    const clock = setInterval(() => setSystemTime(new Date()), 1000);
    return () => clearInterval(clock);
  }, []);

  const handleLogout = () => {
    clearAuth();
    setUser(null);
    setActiveTab('dashboard');
    setHighlightAlertId(null);
    setChatbotAlertContext(null);
    window.location.reload(); // Full reload to clear memory state
  };

  const handleViewAlertDetails = (alertId) => {
    setHighlightAlertId(alertId);
    setActiveTab('alerts');
  };

  const handleLoadChatContext = (alert) => {
    setChatbotAlertContext(alert);
    setActiveTab('chat');
  };

  if (!user) {
    return <Auth onLoginSuccess={(profile) => setUser(profile)} />;
  }

  // Sidebar Links config
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'upload', label: 'Log Ingestion', icon: UploadCloud },
    { id: 'alerts', label: 'Threat Log DB', icon: ShieldAlert },
    { id: 'reports', label: 'Incident Desk', icon: FileText },
    { id: 'chat', label: 'Analyst Chatbot', icon: Terminal },
  ];

  return (
    <div className="min-h-screen flex bg-cyber-bg text-slate-100 font-sans antialiased overflow-hidden">
      
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-cyber-card border-r border-cyber-border flex flex-col justify-between z-10">
        <div>
          {/* Logo Banner */}
          <div className="p-5 border-b border-cyber-border flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded bg-gradient-to-tr from-cyber-accent to-cyber-glow flex items-center justify-center shadow-glow-teal">
              <ShieldIcon className="w-5 h-5 text-cyber-bg stroke-[2.5]" />
            </div>
            <div>
              <span className="font-bold tracking-wider text-sm text-slate-100">AI SOC CORES</span>
              <span className="block text-[9px] font-mono text-cyber-accent tracking-widest leading-none">MONITOR LIVE</span>
            </div>
          </div>

          {/* User Profile Info */}
          <div className="p-4 mx-4 my-4 rounded-lg bg-cyber-bg/50 border border-cyber-border flex items-center space-x-3">
            <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-slate-400">
              <UserIcon className="w-4.5 h-4.5" />
            </div>
            <div className="flex-1 min-w-0">
              <span className="block text-xs font-semibold text-slate-200 truncate">{user.username}</span>
              <span className="block text-[9px] font-mono text-cyber-accent uppercase tracking-wider">{user.role}</span>
            </div>
          </div>

          {/* Links */}
          <nav className="px-3 space-y-1">
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setActiveTab(item.id);
                    if (item.id !== 'alerts') setHighlightAlertId(null);
                  }}
                  className={`w-full flex items-center space-x-3 px-4.5 py-3 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all ${
                    isActive 
                      ? 'bg-cyber-accent/15 border border-cyber-accent/30 text-cyber-accent shadow-glow-teal' 
                      : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-bg/40 border border-transparent'
                  }`}
                >
                  <Icon className="w-4.5 h-4.5" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Logout bottom */}
        <div className="p-4 border-t border-cyber-border">
          <button
            onClick={handleLogout}
            className="w-full flex items-center space-x-3 px-4 py-2.5 rounded border border-cyber-border hover:border-red-500/30 hover:bg-red-500/5 text-xs text-slate-400 hover:text-red-400 font-semibold tracking-wider uppercase transition-all"
          >
            <LogOut className="w-4 h-4" />
            <span>Terminate Shell</span>
          </button>
        </div>
      </aside>

      {/* Main Panel Content Area */}
      <main className="flex-1 flex flex-col min-w-0 relative">
        
        {/* Top Header bar */}
        <header className="h-16 border-b border-cyber-border bg-cyber-card/20 px-6 flex items-center justify-between z-10">
          <div className="flex items-center space-x-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              {navItems.find(n => n.id === activeTab)?.label}
            </h2>
            <div className="hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-cyber-accent/5 border border-cyber-accent/20 text-[10px] text-cyber-accent font-mono animate-pulse">
              <Activity className="w-3.5 h-3.5" />
              <span>CORE SEC ENGINE ONLINE</span>
            </div>
          </div>

          <div className="text-right text-xs font-mono text-slate-500">
            {systemTime.toLocaleDateString()} | {systemTime.toLocaleTimeString()}
          </div>
        </header>

        {/* Tab Body Contents scroll container */}
        <div className="flex-1 overflow-y-auto p-6 relative">
          <div className="max-w-7xl mx-auto space-y-6">
            
            {activeTab === 'dashboard' && (
              <Dashboard onViewAlert={handleViewAlertDetails} />
            )}

            {activeTab === 'upload' && (
              <LogUpload onUploadSuccess={() => setActiveTab('alerts')} />
            )}

            {activeTab === 'alerts' && (
              <AlertTable 
                highlightAlertId={highlightAlertId} 
                onClearHighlight={() => setHighlightAlertId(null)}
                onExplainAlert={handleLoadChatContext}
              />
            )}

            {activeTab === 'reports' && (
              <IncidentReports />
            )}

            {activeTab === 'chat' && (
              <Chatbot 
                contextAlert={chatbotAlertContext} 
                onClearContext={() => setChatbotAlertContext(null)} 
              />
            )}

          </div>
        </div>

      </main>

    </div>
  );
}
