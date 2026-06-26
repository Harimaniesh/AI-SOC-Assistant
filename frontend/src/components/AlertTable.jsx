import React, { useEffect, useState } from 'react';
import { Search, Eye, Filter, CheckCircle, RefreshCw, X, ChevronLeft, ChevronRight, HelpCircle } from 'lucide-react';
import { api } from '../utils/api';

export default function AlertTable({ highlightAlertId, onClearHighlight, onExplainAlert }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Filtering states
  const [searchIp, setSearchIp] = useState('');
  const [threatType, setThreatType] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  // Selected Alert for Details Modal
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [aiExplanation, setAiExplanation] = useState('');
  const [aiLoading, setAiLoading] = useState(false);

  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      setError('');
      
      const queryParams = new URLSearchParams();
      if (searchIp) queryParams.append('source_ip', searchIp);
      if (threatType) queryParams.append('threat_type', threatType);
      if (severityFilter) queryParams.append('severity', severityFilter);
      if (statusFilter) queryParams.append('status', statusFilter);
      if (dateFrom) queryParams.append('date_from', dateFrom);
      if (dateTo) queryParams.append('date_to', dateTo);

      const data = await api.get(`/api/alerts?${queryParams.toString()}`);
      setAlerts(data);
      
      // If there's a highlighted alert, open its details automatically on load
      if (highlightAlertId) {
        const found = data.find(a => a.id === highlightAlertId);
        if (found) {
          handleOpenDetails(found);
          onClearHighlight();
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to retrieve logs database');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [searchIp, threatType, severityFilter, statusFilter, dateFrom, dateTo]);

  // Handle open details modal
  const handleOpenDetails = async (alert) => {
    setSelectedAlert(alert);
    setAiExplanation('');
    setAiLoading(true);
    try {
      const data = await api.get(`/api/alerts/${alert.id}/ai-explain`);
      setAiExplanation(data.explanation);
    } catch (err) {
      setAiExplanation('Error generating AI analysis report. Local heuristics only.');
    } finally {
      setAiLoading(false);
    }
  };

  // Handle status update
  const handleUpdateStatus = async (alertId, newStatus) => {
    try {
      const updated = await api.put(`/api/alerts/${alertId}/status`, { status: newStatus });
      setAlerts(prev => prev.map(a => a.id === alertId ? updated : a));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(prev => ({ ...prev, status: newStatus }));
      }
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  // Reset Filters
  const handleResetFilters = () => {
    setSearchIp('');
    setThreatType('');
    setSeverityFilter('');
    setStatusFilter('');
    setDateFrom('');
    setDateTo('');
    setCurrentPage(1);
  };

  // Pagination logic
  const totalPages = Math.ceil(alerts.length / itemsPerPage);
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentAlerts = alerts.slice(indexOfFirstItem, indexOfLastItem);

  return (
    <div className="space-y-6 font-sans">
      
      {/* Search & Filter Controls Card */}
      <div className="bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between mb-4 pb-2 border-b border-cyber-border">
          <div className="flex items-center space-x-2 text-slate-200 font-mono text-sm font-semibold uppercase">
            <Filter className="w-4 h-4 text-cyber-accent" />
            <span>Search & Threat Filters</span>
          </div>
          <button 
            onClick={handleResetFilters}
            className="text-xs font-mono text-cyber-accent hover:underline"
          >
            Reset Filters
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
          
          {/* IP search */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Source IP</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-500">
                <Search className="w-3.5 h-3.5" />
              </span>
              <input
                type="text"
                placeholder="Search IP..."
                value={searchIp}
                onChange={(e) => { setSearchIp(e.target.value); setCurrentPage(1); }}
                className="w-full pl-8 pr-3 py-1.5 text-sm rounded bg-cyber-bg border border-cyber-border text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
              />
            </div>
          </div>

          {/* Threat Type */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Threat Type</label>
            <select
              value={threatType}
              onChange={(e) => { setThreatType(e.target.value); setCurrentPage(1); }}
              className="w-full px-2.5 py-1.5 text-sm rounded bg-cyber-bg border border-cyber-border text-slate-300 focus:outline-none focus:border-cyber-accent"
            >
              <option value="">All Threats</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Port Scanning">Port Scanning</option>
              <option value="Malware Execution">Malware Execution</option>
              <option value="Privilege Escalation">Privilege Escalation</option>
            </select>
          </div>

          {/* Severity */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
              className="w-full px-2.5 py-1.5 text-sm rounded bg-cyber-bg border border-cyber-border text-slate-300 focus:outline-none focus:border-cyber-accent"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical (9-10)</option>
              <option value="high">High (7-8)</option>
              <option value="medium">Medium (4-6)</option>
              <option value="low">Low (1-3)</option>
            </select>
          </div>

          {/* Status */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }}
              className="w-full px-2.5 py-1.5 text-sm rounded bg-cyber-bg border border-cyber-border text-slate-300 focus:outline-none focus:border-cyber-accent"
            >
              <option value="">All Statuses</option>
              <option value="New">New</option>
              <option value="In Progress">In Progress</option>
              <option value="Resolved">Resolved</option>
              <option value="Dismissed">Dismissed</option>
            </select>
          </div>

          {/* Date From */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Date From</label>
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => { setDateFrom(e.target.value); setCurrentPage(1); }}
              className="w-full px-2 py-1 text-sm rounded bg-cyber-bg border border-cyber-border text-slate-300 focus:outline-none focus:border-cyber-accent"
            />
          </div>

          {/* Date To */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Date To</label>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => { setDateTo(e.target.value); setCurrentPage(1); }}
              className="w-full px-2 py-1 text-sm rounded bg-cyber-bg border border-cyber-border text-slate-300 focus:outline-none focus:border-cyber-accent"
            />
          </div>

        </div>
      </div>

      {/* Alerts Table Card */}
      <div className="bg-cyber-card/40 border border-cyber-border rounded-xl shadow-xl overflow-hidden">
        
        {loading ? (
          <div className="py-12 flex flex-col items-center justify-center">
            <RefreshCw className="w-8 h-8 text-cyber-accent animate-spin mb-3" />
            <p className="text-xs font-mono uppercase text-cyber-text tracking-widest">LOADING DATABASE RECORDS...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="py-16 text-center text-slate-500 font-mono text-sm">
            No threats detected matching these search filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-cyber-card border-b border-cyber-border text-slate-400 font-mono uppercase text-[11px] tracking-wider">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Threat Type</th>
                  <th className="p-4">Source IP</th>
                  <th className="p-4">Destination IP</th>
                  <th className="p-4 text-center">Severity</th>
                  <th className="p-4">MITRE Mapping</th>
                  <th className="p-4">Status</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border text-sm">
                {currentAlerts.map(alert => {
                  let sevColor = 'bg-slate-800 text-slate-400';
                  if (alert.severity >= 9) sevColor = 'bg-red-500/10 text-red-400 border border-red-500/30';
                  else if (alert.severity >= 7) sevColor = 'bg-orange-500/10 text-orange-400 border border-orange-500/30';
                  else if (alert.severity >= 4) sevColor = 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
                  else sevColor = 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';

                  return (
                    <tr key={alert.id} className="hover:bg-cyber-card/30 transition-colors">
                      <td className="p-4 font-mono text-xs text-slate-400">
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                      <td className="p-4 font-semibold text-slate-200">{alert.threat_type}</td>
                      <td className="p-4 font-mono text-slate-300">{alert.source_ip}</td>
                      <td className="p-4 font-mono text-slate-400">{alert.destination_ip || '0.0.0.0'}</td>
                      <td className="p-4 text-center">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${sevColor}`}>
                          {alert.severity}/10
                        </span>
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded bg-cyber-bg border border-cyber-border text-xs font-mono text-cyber-accent">
                          {alert.mitre_id || 'N/A'}
                        </span>
                      </td>
                      <td className="p-4">
                        <select
                          value={alert.status}
                          onChange={(e) => handleUpdateStatus(alert.id, e.target.value)}
                          className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyber-accent"
                        >
                          <option value="New">New</option>
                          <option value="In Progress">In Progress</option>
                          <option value="Resolved">Resolved</option>
                          <option value="Dismissed">Dismissed</option>
                        </select>
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => handleOpenDetails(alert)}
                          className="p-1 text-cyber-accent hover:bg-cyber-accent/10 border border-transparent hover:border-cyber-accent/30 rounded transition-all"
                          title="View Log Context & AI Explanation"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination footer */}
        {totalPages > 1 && (
          <div className="bg-cyber-card p-4 border-t border-cyber-border flex items-center justify-between">
            <span className="text-xs text-cyber-text font-mono">
              Showing {indexOfFirstItem + 1}-{Math.min(indexOfLastItem, alerts.length)} of {alerts.length} threats
            </span>
            <div className="flex items-center space-x-2">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                className="p-1 rounded border border-cyber-border text-slate-400 disabled:opacity-30 hover:border-slate-600 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs font-mono text-slate-300 px-2">Page {currentPage} of {totalPages}</span>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                className="p-1 rounded border border-cyber-border text-slate-400 disabled:opacity-30 hover:border-slate-600 transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

      </div>

      {/* Alert Details & AI Analysis Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-cyber-bg/80 backdrop-blur-sm">
          <div className="bg-cyber-card border border-cyber-border w-full max-w-3xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh] animate-scale-up">
            
            {/* Modal header */}
            <div className="flex items-center justify-between p-4 bg-cyber-bg border-b border-cyber-border">
              <div className="flex flex-col">
                <h3 className="text-base font-bold text-slate-100 flex items-center">
                  <span className="text-cyber-accent mr-2 font-mono">ALERT DETAILS</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-cyber-border border border-slate-700 text-slate-400 font-mono font-normal uppercase">
                    {selectedAlert.status}
                  </span>
                </h3>
                <span className="text-xs text-cyber-text font-mono mt-0.5">ID: {selectedAlert.id}</span>
              </div>
              <button 
                onClick={() => setSelectedAlert(null)}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal content body */}
            <div className="flex-1 p-6 space-y-5 overflow-y-auto">
              
              {/* Alert Meta grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-lg bg-cyber-bg/50 border border-cyber-border">
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">Threat Type</span>
                  <span className="font-semibold text-slate-200 text-sm">{selectedAlert.threat_type}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">MITRE Mapping</span>
                  <span className="font-semibold text-cyber-accent text-sm font-mono">{selectedAlert.mitre_id || 'N/A'}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">Source IP</span>
                  <span className="font-semibold text-slate-300 text-sm font-mono">{selectedAlert.source_ip}</span>
                </div>
                <div>
                  <span className="block text-[10px] uppercase font-mono text-cyber-text">Severity Rating</span>
                  <span className="font-bold text-red-400 text-sm font-mono">{selectedAlert.severity}/10</span>
                </div>
              </div>

              {/* Description */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">Telemetry Alert Description</h4>
                <p className="text-sm text-slate-300 leading-relaxed p-3 bg-cyber-bg/30 rounded border border-cyber-border">
                  {selectedAlert.description}
                </p>
              </div>

              {/* Raw payload */}
              {selectedAlert.raw_log_payload && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">Raw Event Log Snippet</h4>
                  <pre className="p-3 bg-cyber-bg font-mono text-xs text-cyber-accent rounded border border-cyber-border overflow-x-auto whitespace-pre-wrap">
                    {selectedAlert.raw_log_payload}
                  </pre>
                </div>
              )}

              {/* AI Explanation & Recommendations */}
              <div className="space-y-3 pt-3 border-t border-cyber-border">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-cyber-accent uppercase tracking-wider font-mono flex items-center">
                    <span className="relative flex h-2 w-2 mr-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-accent opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-accent"></span>
                    </span>
                    AI Analyst Brief & Containment
                  </h4>
                  <button 
                    onClick={() => {
                      setSelectedAlert(null);
                      onExplainAlert(selectedAlert);
                    }}
                    className="text-xs text-cyber-glow flex items-center hover:underline"
                  >
                    <HelpCircle className="w-3.5 h-3.5 mr-1" />
                    Ask AI Assistant chatbot
                  </button>
                </div>

                {aiLoading ? (
                  <div className="p-6 rounded border border-cyber-accent/20 bg-cyber-accent/5 flex flex-col items-center justify-center">
                    <RefreshCw className="w-6 h-6 text-cyber-accent animate-spin mb-2" />
                    <p className="text-xs font-mono text-cyber-text tracking-widest">AI AGENT REASONING OUT THREAT MATRIX...</p>
                  </div>
                ) : (
                  <div className="p-4 rounded border border-cyber-accent/20 bg-cyber-accent/5 text-sm text-slate-300 space-y-3 font-sans max-h-[300px] overflow-y-auto">
                    {aiExplanation ? (
                      <div className="prose prose-invert max-w-none text-xs leading-relaxed space-y-2">
                        {aiExplanation.split('\n').map((line, idx) => {
                          if (line.startsWith('### ') || line.startsWith('#### ')) {
                            return <h5 key={idx} className="font-bold text-slate-200 mt-3 mb-1 uppercase tracking-wider">{line.replace(/#+\s*/, '')}</h5>;
                          }
                          if (line.startsWith('**') && line.endsWith('**')) {
                            return <p key={idx} className="font-bold text-slate-100">{line.replace(/\*\*/g, '')}</p>;
                          }
                          if (line.startsWith('- ') || line.startsWith('* ')) {
                            return <li key={idx} className="list-disc ml-4 text-slate-300">{line.substring(2)}</li>;
                          }
                          if (line.match(/^\d+\.\s/)) {
                            return <p key={idx} className="pl-2 font-semibold text-slate-200 mt-1">{line}</p>;
                          }
                          return <p key={idx} className="text-slate-300">{line}</p>;
                        })}
                      </div>
                    ) : (
                      <p className="text-slate-400 font-mono text-xs">No analysis compiled.</p>
                    )}
                  </div>
                )}
              </div>

            </div>

            {/* Modal footer */}
            <div className="p-4 bg-cyber-bg border-t border-cyber-border flex justify-end space-x-3">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 text-xs font-semibold rounded bg-cyber-border hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Close
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
