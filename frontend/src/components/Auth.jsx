import React, { useState } from 'react';
import { Shield, Lock, User as UserIcon, HelpCircle, Eye, EyeOff } from 'lucide-react';
import { api, setAuthToken, setAuthUser } from '../utils/api';

export default function Auth({ onLoginSuccess }) {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Analyst'); // Analyst or Admin
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isRegister) {
        // Register API Call
        await api.post('/api/auth/register', { username, password, role });
        // After registration, auto-login
      }

      // Login API Call
      const data = await api.post('/api/auth/login', { username, password });
      setAuthToken(data.access_token);
      setAuthUser(data.username, data.role);
      onLoginSuccess({ username: data.username, role: data.role });
    } catch (err) {
      setError(err.message || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center px-4 py-12 bg-cyber-bg overflow-hidden font-sans">
      <div className="cyber-grid" />
      
      {/* Background Neon Glow Orbs */}
      <div className="absolute top-1/4 left-1/4 w-80 h-80 rounded-full bg-cyber-accent/10 blur-[100px] animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 rounded-full bg-cyber-glow/10 blur-[100px] animate-pulse" />

      <div className="w-full max-w-md bg-cyber-card/70 backdrop-blur-md border border-cyber-border rounded-xl p-8 shadow-2xl relative z-10">
        
        {/* Branding header */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-full bg-gradient-to-tr from-cyber-accent to-cyber-glow flex items-center justify-center mb-3 shadow-glow-teal">
            <Shield className="w-9 h-9 text-cyber-bg stroke-[2]" />
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-slate-100 font-sans">AI SOC ASSISTANT</h1>
          <p className="text-cyber-text text-sm mt-1">Autonomous Security Operations Center Assistant</p>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 text-sm text-center">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Username</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <UserIcon className="w-5 h-5" />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                minLength={3}
                placeholder="Enter username..."
                className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-cyber-border bg-cyber-bg/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all duration-200"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Password</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <Lock className="w-5 h-5" />
              </span>
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                placeholder="Enter password..."
                className="w-full pl-10 pr-10 py-2.5 rounded-lg border border-cyber-border bg-cyber-bg/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-all duration-200"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {isRegister && (
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">SOC Role Mapping</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setRole('Analyst')}
                  className={`py-2 px-4 rounded-lg border text-sm font-semibold tracking-wide transition-all ${
                    role === 'Analyst'
                      ? 'border-cyber-accent bg-cyber-accent/10 text-cyber-accent'
                      : 'border-cyber-border bg-cyber-bg/30 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  Analyst (L1/L2)
                </button>
                <button
                  type="button"
                  onClick={() => setRole('Admin')}
                  className={`py-2 px-4 rounded-lg border text-sm font-semibold tracking-wide transition-all ${
                    role === 'Admin'
                      ? 'border-cyber-accent bg-cyber-accent/10 text-cyber-accent'
                      : 'border-cyber-border bg-cyber-bg/30 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  Admin (L3/Lead)
                </button>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 px-4 mt-2 rounded-lg bg-gradient-to-r from-cyber-accent to-cyber-glow text-cyber-bg font-bold tracking-wider hover:opacity-90 active:scale-[0.98] transition-all disabled:opacity-50 disabled:scale-100 shadow-glow-teal"
          >
            {loading ? 'PROCESSING SECURE VERIFICATION...' : (isRegister ? 'CREATE ACCOUNT' : 'SECURE SIGN IN')}
          </button>
        </form>

        <div className="mt-6 text-center">
          <button
            type="button"
            onClick={() => {
              setIsRegister(!isRegister);
              setError('');
            }}
            className="text-xs text-cyber-accent hover:underline tracking-wider"
          >
            {isRegister ? 'ALREADY REGISTERED? LOG IN HERE' : "DON'T HAVE AN ACCOUNT? REGISTER HERE"}
          </button>
        </div>
      </div>
    </div>
  );
}
