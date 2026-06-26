import React, { useEffect, useState } from 'react';
import { FileDown, FilePlus, RefreshCw, AlertTriangle, ShieldCheck, CheckCircle } from 'lucide-react';
import { api } from '../utils/api';

export default function IncidentReports() {
  const [reports, setReports] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Creation Form states
  const [selectedAlertId, setSelectedAlertId] = useState('');
  const [summary, setSummary] = useState('');
  const [remediation, setRemediation] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState('');

  const fetchReportsAndAlerts = async () => {
    try {
      setLoading(true);
      setError('');
      
      const reportsData = await api.get('/api/reports/history');
      setReports(reportsData);

      // Fetch all alerts to populate the form dropdown
      const alertsData = await api.get('/api/alerts');
      setAlerts(alertsData);
    } catch (err) {
      setError(err.message || 'Failed to retrieve reports telemetry database');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReportsAndAlerts();
  }, []);

  // Autofill summary/remediation when alert changes
  const handleAlertSelect = (alertId) => {
    setSelectedAlertId(alertId);
    setSummary('');
    setRemediation('');
    setSubmitSuccess('');

    if (!alertId) return;

    const alert = alerts.find(a => a.id === parseInt(alertId));
    if (alert) {
      // Create defaults
      setSummary(
        `On ${new Date(alert.timestamp).toLocaleString()}, a security alert of type "${alert.threat_type}" ` +
        `was triggered by source IP address ${alert.source_ip} targeting ${alert.target_system || 'system boundary'}. ` +
        `The incident was rated with a severity risk score of ${alert.severity}/10.`
      );

      // Fill in remediation advice based on threat type
      let advice = '';
      if (alert.threat_type === 'Brute Force') {
        advice = '1. Terminate current SSH/RDP/Login sessions from source IP.\n2. Add the source IP to blacklists in core firewall ACLs.\n3. Verify account passwords are updated and force MFA enrollment.';
      } else if (alert.threat_type === 'Port Scanning') {
        advice = '1. Block the source scanning IP at perimeter firewalls.\n2. Run auditing scan to verify closed ports do not leak internal system structures.\n3. Review active public API routes.';
      } else if (alert.threat_type === 'Malware Execution') {
        advice = '1. Quarantine and isolate host network interface.\n2. Kill execution processes and delete associated binaries.\n3. Run a deep system EDR/AV sweep.';
      } else if (alert.threat_type === 'Privilege Escalation') {
        advice = '1. Kill user shells and revoke credential access token keys.\n2. Reset administrative passwords.\n3. Review privilege group memberships and patch local server dependencies.';
      } else {
        advice = '1. Investigate the anomalous traffic patterns.\n2. Standard containment procedures.';
      }
      setRemediation(advice);
    }
  };

  const handleGenerateReport = async (e) => {
    e.preventDefault();
    if (!selectedAlertId) return;

    setSubmitting(true);
    setError('');
    setSubmitSuccess('');

    try {
      const data = await api.post('/api/reports/generate', {
        alert_id: parseInt(selectedAlertId),
        summary: summary,
        recommended_remediation: remediation
      });

      setSubmitSuccess(`Report successfully created! PDF has been generated.`);
      setSelectedAlertId('');
      setSummary('');
      setRemediation('');
      
      // Refresh list
      fetchReportsAndAlerts();
    } catch (err) {
      setError(err.message || 'Could not compile incident report');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDownloadPDF = async (reportId, filename) => {
    try {
      const blob = await api.get(`/api/reports/${reportId}/download`);
      // Trigger browser file download
      const url = window.URL.createObjectURL(new Blob([blob]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename || `incident_report_${reportId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      alert(`Download failed: ${err.message}`);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-sans">
      
      {/* Generate Report Form (Left Column) */}
      <div className="lg:col-span-1 bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl h-fit">
        <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono mb-4 border-b border-cyber-border pb-2 flex items-center">
          <FilePlus className="w-4 h-4 text-cyber-accent mr-1.5" />
          Compile Incident Report
        </h2>

        {submitSuccess && (
          <div className="mb-4 p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-xs flex items-center">
            <CheckCircle className="w-4 h-4 mr-2" />
            <span>{submitSuccess}</span>
          </div>
        )}

        <form onSubmit={handleGenerateReport} className="space-y-4">
          
          {/* Select Alert Dropdown */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Select Trigger Alert</label>
            <select
              required
              value={selectedAlertId}
              onChange={(e) => handleAlertSelect(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs rounded bg-cyber-bg border border-cyber-border text-slate-300 focus:outline-none focus:border-cyber-accent"
            >
              <option value="">-- Choose Target Alert --</option>
              {alerts.map(a => (
                <option key={a.id} value={a.id}>
                  ID {a.id} | {a.threat_type} | {a.source_ip} (Sev {a.severity})
                </option>
              ))}
            </select>
          </div>

          {/* Summary Input */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Incident Threat Summary</label>
            <textarea
              required
              rows={4}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Detailed threat brief..."
              className="w-full p-2.5 rounded bg-cyber-bg/50 border border-cyber-border text-slate-200 placeholder-slate-500 text-xs focus:outline-none focus:border-cyber-accent"
            />
          </div>

          {/* Remediation Input */}
          <div>
            <label className="block text-xs text-slate-400 uppercase tracking-wider font-mono mb-1.5">Remediation Checklist</label>
            <textarea
              required
              rows={4}
              value={remediation}
              onChange={(e) => setRemediation(e.target.value)}
              placeholder="Containment instructions..."
              className="w-full p-2.5 rounded bg-cyber-bg/50 border border-cyber-border text-slate-200 placeholder-slate-500 text-xs focus:outline-none focus:border-cyber-accent"
            />
          </div>

          <button
            type="submit"
            disabled={submitting || !selectedAlertId}
            className="w-full py-2.5 rounded-lg bg-cyber-accent text-cyber-bg font-bold text-xs tracking-wider uppercase hover:opacity-90 active:scale-[0.98] transition-all disabled:opacity-30 shadow-glow-teal"
          >
            {submitting ? 'GENERATING PDF DOSSIER...' : 'GENERATE INCIDENT PDF'}
          </button>
        </form>
      </div>

      {/* Reports List (Right Columns) */}
      <div className="lg:col-span-2 bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col min-h-[400px]">
        <div className="flex justify-between items-center mb-4 pb-2 border-b border-cyber-border">
          <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono">
            Security Incident Reports History
          </h2>
          <button 
            onClick={fetchReportsAndAlerts} 
            className="text-xs text-cyber-accent hover:underline flex items-center font-mono"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1" />
            Refresh
          </button>
        </div>

        {error && (
          <div className="p-3 mb-4 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 font-mono text-xs">
            {error}
          </div>
        )}

        {reports.length === 0 ? (
          <div className="flex-1 flex items-center justify-center text-slate-500 font-mono text-xs">
            No incident reports registered. Use the panel on the left to compile.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-cyber-bg/40 text-slate-400 font-mono uppercase text-[10px] border-b border-cyber-border">
                  <th className="p-3 pl-4">Report ID</th>
                  <th className="p-3">Alert Details</th>
                  <th className="p-3">Compiled At</th>
                  <th className="p-3 text-right pr-4">Document</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border">
                {reports.map(report => {
                  // Find corresponding alert details
                  const matchingAlert = alerts.find(a => a.id === report.alert_id);
                  const threatText = matchingAlert ? `${matchingAlert.threat_type} (${matchingAlert.source_ip})` : `Alert ID ${report.alert_id}`;

                  return (
                    <tr key={report.id} className="hover:bg-cyber-card/20 transition-colors">
                      <td className="p-3 pl-4 font-mono font-bold text-slate-200">
                        INC-{report.id}
                      </td>
                      <td className="p-3">
                        <div className="font-semibold text-slate-300">{threatText}</div>
                        <div className="text-[10px] text-slate-500 font-mono truncate max-w-[280px]">
                          {report.summary}
                        </div>
                      </td>
                      <td className="p-3 font-mono text-slate-400">
                        {new Date(report.created_at).toLocaleString()}
                      </td>
                      <td className="p-3 text-right pr-4">
                        <button
                          onClick={() => handleDownloadPDF(report.id, `Incident_Report_INC-${report.id}.pdf`)}
                          className="px-3 py-1.5 rounded bg-cyber-bg border border-cyber-border hover:border-cyber-accent text-cyber-accent font-semibold transition-colors flex items-center space-x-1 float-right"
                        >
                          <FileDown className="w-3.5 h-3.5" />
                          <span>PDF</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
