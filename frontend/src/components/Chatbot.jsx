import React, { useEffect, useState, useRef } from 'react';
import { Send, Terminal, Cpu, Info, ShieldAlert, Sparkles, RefreshCw } from 'lucide-react';
import { api } from '../utils/api';

export default function Chatbot({ contextAlert, onClearContext }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef(null);

  // Initialize chatbot messages
  useEffect(() => {
    // Standard starting greetings
    const greetings = [
      {
        id: 'init-1',
        sender: 'ai',
        text: 'Greetings. I am the AI Security Assistant. I can help analyze log anomalies, explain MITRE ATT&CK techniques, or detail containment and remediation processes.',
        timestamp: new Date()
      }
    ];

    if (contextAlert) {
      greetings.push({
        id: 'init-context',
        sender: 'ai',
        text: `Active investigation alert loaded: **${contextAlert.threat_type}** (${contextAlert.mitre_id || 'N/A'}) from source IP \`${contextAlert.source_ip}\`. You can ask questions relative to this context.`,
        timestamp: new Date(),
        isContext: true
      });
    }

    setMessages(greetings);
  }, [contextAlert]);

  // Scroll to bottom on new messages
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (textToSend) => {
    const text = textToSend || input;
    if (!text.trim()) return;

    if (!textToSend) setInput('');

    // Append user message
    const userMsg = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: text,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    try {
      const response = await api.post('/api/chat', {
        message: text,
        alert_id: contextAlert ? contextAlert.id : null
      });

      const aiMsg = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: response.response,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      const errMsg = {
        id: `ai-err-${Date.now()}`,
        sender: 'ai',
        text: `Error communicating with AI Security core: ${err.message}`,
        timestamp: new Date(),
        isError: true
      };
      setMessages(prev => [...prev, errMsg]);
    } finally {
      setLoading(false);
    }
  };

  // Handler for quick buttons
  const handleQuickQuestion = (question) => {
    handleSend(question);
  };

  // Helper to format chatbot message markdown output nicely
  const formatText = (text) => {
    return text.split('\n').map((line, idx) => {
      // Bold Markdown
      let formattedLine = line.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
      // Inline Code Markdown
      formattedLine = formattedLine.replace(/`(.*?)`/g, '<code class="bg-cyber-bg px-1 py-0.5 rounded text-cyber-accent font-mono text-xs">$1</code>');
      
      if (line.startsWith('### ')) {
        return <h4 key={idx} className="text-slate-100 font-bold mt-3 mb-1 text-sm border-b border-cyber-border/40 pb-1">{formattedLine.replace('### ', '')}</h4>;
      }
      if (line.startsWith('#### ')) {
        return <h5 key={idx} className="text-slate-200 font-bold mt-2 mb-1 text-xs">{formattedLine.replace('#### ', '')}</h5>;
      }
      if (line.startsWith('- ') || line.startsWith('* ')) {
        return <li key={idx} className="list-disc ml-4 mt-1 text-xs" dangerouslySetInnerHTML={{ __html: formattedLine.substring(2) }} />;
      }
      return <p key={idx} className="mt-1.5 leading-relaxed text-xs" dangerouslySetInnerHTML={{ __html: formattedLine }} />;
    });
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 min-h-[500px] h-[calc(100vh-170px)] font-sans">
      
      {/* Active Investigation Context panel (Left Side on large screens) */}
      <div className="lg:col-span-1 bg-cyber-card/40 border border-cyber-border rounded-xl p-4 flex flex-col justify-between shadow-xl">
        <div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono mb-3 border-b border-cyber-border pb-2 flex items-center">
            <Cpu className="w-3.5 h-3.5 text-cyber-accent mr-1.5" />
            Alert Context Desk
          </h3>
          
          {contextAlert ? (
            <div className="space-y-4">
              <div className="p-3 rounded bg-cyber-bg/50 border border-cyber-border text-xs space-y-2.5">
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">Threat Type</span>
                  <span className="font-semibold text-slate-200">{contextAlert.threat_type}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">MITRE ATT&CK ID</span>
                  <span className="font-mono text-cyber-accent font-semibold">{contextAlert.mitre_id || 'N/A'}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">Attacker IP Source</span>
                  <span className="font-mono text-slate-300">{contextAlert.source_ip}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">Incident Severity</span>
                  <span className="font-mono font-bold text-red-400">{contextAlert.severity}/10</span>
                </div>
              </div>

              <button
                onClick={onClearContext}
                className="w-full py-1.5 text-center text-xs border border-cyber-border rounded text-slate-400 hover:text-slate-200 bg-cyber-bg/20 hover:border-slate-600 transition-colors font-mono"
              >
                Clear Alert Context
              </button>
            </div>
          ) : (
            <div className="text-center py-10 text-slate-500 text-xs leading-relaxed font-mono">
              No alert loaded. <br/>
              Select "Eye" view details on any alert table record to analyze in context.
            </div>
          )}
        </div>

        {/* Quick helper prompts */}
        {contextAlert && (
          <div className="space-y-2 mt-4">
            <span className="block text-[10px] uppercase font-mono text-cyber-text tracking-widest">Incident Checklist</span>
            <button
              onClick={() => handleQuickQuestion(`Explain the alert: ${contextAlert.threat_type}`)}
              className="w-full text-left p-2 rounded bg-cyber-bg/20 hover:bg-cyber-bg/50 border border-cyber-border text-[11px] text-slate-300 hover:text-cyber-accent transition-colors font-sans"
            >
              Explain this alert
            </button>
            <button
              onClick={() => handleQuickQuestion(`What is MITRE technique ${contextAlert.mitre_id}?`)}
              className="w-full text-left p-2 rounded bg-cyber-bg/20 hover:bg-cyber-bg/50 border border-cyber-border text-[11px] text-slate-300 hover:text-cyber-accent transition-colors font-sans"
            >
              What is {contextAlert.mitre_id}?
            </button>
            <button
              onClick={() => handleQuickQuestion(`How to remediate the attack from IP ${contextAlert.source_ip}?`)}
              className="w-full text-left p-2 rounded bg-cyber-bg/20 hover:bg-cyber-bg/50 border border-cyber-border text-[11px] text-slate-300 hover:text-cyber-accent transition-colors font-sans"
            >
              How to remediate this?
            </button>
          </div>
        )}
      </div>

      {/* Main Chat Interface (Right Side) */}
      <div className="lg:col-span-3 bg-cyber-card/40 border border-cyber-border rounded-xl flex flex-col shadow-xl overflow-hidden h-full">
        
        {/* Chat window header */}
        <div className="p-3.5 bg-cyber-card border-b border-cyber-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyber-accent animate-pulse" />
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono">
              AI SOC Analyst Bot
            </h2>
          </div>
          <span className="text-[10px] font-mono text-slate-500 border border-cyber-border px-1.5 py-0.5 rounded uppercase">
            Interactive Reasoning Shell
          </span>
        </div>

        {/* Chat messages list */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map(msg => {
            const isAI = msg.sender === 'ai';
            return (
              <div 
                key={msg.id}
                className={`flex ${isAI ? 'justify-start' : 'justify-end'}`}
              >
                <div className={`max-w-[85%] rounded-lg p-3.5 border ${
                  isAI 
                    ? msg.isError 
                      ? 'bg-red-500/10 border-red-500/20 text-red-400'
                      : msg.isContext 
                        ? 'bg-cyber-accent/5 border-cyber-accent/10 text-slate-200'
                        : 'bg-cyber-card border-cyber-border text-slate-200' 
                    : 'bg-cyber-accent/10 border-cyber-accent/30 text-slate-100 shadow-glow-teal'
                }`}>
                  <div className="flex items-center space-x-1.5 mb-1.5 border-b border-cyber-border/40 pb-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider font-mono text-slate-400">
                      {isAI ? 'SOC-Agent-AI' : 'Security-Analyst'}
                    </span>
                    <span className="text-[9px] font-mono text-slate-600">
                      {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {isAI ? formatText(msg.text) : <p className="text-xs">{msg.text}</p>}
                  </div>
                </div>
              </div>
            );
          })}
          
          {loading && (
            <div className="flex justify-start">
              <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 max-w-[80%] flex items-center space-x-3">
                <RefreshCw className="w-4 h-4 text-cyber-accent animate-spin" />
                <span className="text-xs font-mono text-cyber-text tracking-wider">AI AGENT CALCULATING containment MATRIX...</span>
              </div>
            </div>
          )}
          
          <div ref={chatEndRef} />
        </div>

        {/* Input form */}
        <form 
          onSubmit={(e) => { e.preventDefault(); handleSend(); }}
          className="p-4 bg-cyber-bg border-t border-cyber-border flex space-x-3"
        >
          <input
            type="text"
            placeholder={contextAlert ? "Ask about current alert (e.g. How high is the threat?)..." : "Ask security queries (e.g. What is T1110?)..."}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            className="flex-1 px-4 py-2.5 rounded-lg border border-cyber-border bg-cyber-bg/50 text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyber-accent"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-2 rounded-lg bg-cyber-accent text-cyber-bg font-bold hover:opacity-90 active:scale-[0.98] transition-all disabled:opacity-30 disabled:scale-100 flex items-center"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>

      </div>

    </div>
  );
}
