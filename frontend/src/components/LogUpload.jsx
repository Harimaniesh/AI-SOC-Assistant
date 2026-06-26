import React, { useEffect, useState } from 'react';
import { Upload, FileText, CheckCircle2, AlertCircle, FileSpreadsheet, RefreshCw } from 'lucide-react';
import { api } from '../utils/api';

export default function LogUpload({ onUploadSuccess }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const fetchHistory = async () => {
    try {
      const data = await api.get('/api/logs/history');
      setHistory(data);
    } catch (err) {
      console.error('Failed to retrieve log upload history', err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      await uploadFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = async (e) => {
    if (e.target.files && e.target.files[0]) {
      await uploadFile(e.target.files[0]);
    }
  };

  const uploadFile = async (file) => {
    setError('');
    setSuccessMsg('');
    
    // Client-side validations
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!['.csv', '.json', '.txt'].includes(ext)) {
      setError('Unsupported file type. Only CSV, JSON, and TXT log files are accepted.');
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      setError('File exceeds the 5MB size limit.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    setLoading(true);

    try {
      const result = await api.post('/api/logs/upload', formData, true);
      setSuccessMsg(`File "${file.name}" uploaded and parsed successfully!`);
      fetchHistory();
      if (onUploadSuccess) onUploadSuccess();
    } catch (err) {
      setError(err.message || 'Log upload and analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      
      {/* Upload Drag & Drop Box */}
      <div className="bg-cyber-card/40 border border-cyber-border rounded-xl p-5 shadow-xl">
        <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase font-mono mb-4 border-b border-cyber-border pb-2">
          Secure Log Ingestion Module
        </h2>

        {error && (
          <div className="mb-4 p-3 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 text-sm flex items-center">
            <AlertCircle className="w-4 h-4 mr-2" />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-sm flex items-center">
            <CheckCircle2 className="w-4 h-4 mr-2" />
            <span>{successMsg}</span>
          </div>
        )}

        <form 
          onDragEnter={handleDrag} 
          onDragOver={handleDrag} 
          onDragLeave={handleDrag} 
          onDrop={handleDrop}
          onSubmit={(e) => e.preventDefault()}
          className={`relative border-2 border-dashed rounded-lg p-10 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-200 ${
            dragActive 
              ? 'border-cyber-accent bg-cyber-accent/5' 
              : 'border-cyber-border bg-cyber-bg/30 hover:border-slate-600'
          }`}
        >
          <input
            type="file"
            id="log-file-input"
            accept=".csv,.json,.txt"
            onChange={handleFileChange}
            disabled={loading}
            className="hidden"
          />

          <label htmlFor="log-file-input" className="cursor-pointer flex flex-col items-center">
            <div className="w-14 h-14 rounded-full bg-cyber-card border border-cyber-border flex items-center justify-center mb-4 group-hover:border-cyber-accent">
              {loading ? (
                <RefreshCw className="w-7 h-7 text-cyber-accent animate-spin" />
              ) : (
                <Upload className="w-7 h-7 text-cyber-text" />
              )}
            </div>
            <p className="text-sm font-semibold text-slate-200">
              {loading ? 'PARSING TELEMETRY SOURCE LOGS...' : 'Drag and drop log file, or click to browse'}
            </p>
            <p className="text-xs text-slate-500 mt-1.5 font-mono">
              Accepted formats: .csv, .json, .txt (Max size: 5MB)
            </p>
          </label>
        </form>
      </div>

      {/* Upload History Table */}
      <div className="bg-cyber-card/40 border border-cyber-border rounded-xl shadow-xl overflow-hidden">
        <div className="p-4 bg-cyber-card border-b border-cyber-border flex justify-between items-center">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
            Ingestion Telemetry Log History
          </h3>
          <button 
            onClick={fetchHistory} 
            className="text-xs text-cyber-accent hover:underline flex items-center font-mono"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1" />
            Refresh
          </button>
        </div>

        {history.length === 0 ? (
          <div className="py-10 text-center text-slate-500 font-mono text-sm">
            No logs ingested. Use the panel above to upload log samples.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="bg-cyber-bg/40 text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-cyber-border">
                  <th className="p-3 pl-5">Uploaded At</th>
                  <th className="p-3">Original Filename</th>
                  <th className="p-3">File Size</th>
                  <th className="p-3 text-center">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border">
                {history.map(log => {
                  let statusBadge = 'bg-slate-800 text-slate-400';
                  if (log.status === 'Parsed') statusBadge = 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
                  if (log.status === 'Failed') statusBadge = 'bg-red-500/10 text-red-400 border border-red-500/20';
                  if (log.status === 'Pending') statusBadge = 'bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse';

                  return (
                    <tr key={log.id} className="hover:bg-cyber-card/20 transition-colors">
                      <td className="p-3 pl-5 font-mono text-xs text-slate-400">
                        {new Date(log.uploaded_at).toLocaleString()}
                      </td>
                      <td className="p-3 font-semibold text-slate-200 flex items-center">
                        {log.original_filename.endsWith('.csv') ? (
                          <FileSpreadsheet className="w-4 h-4 mr-2 text-emerald-500" />
                        ) : (
                          <FileText className="w-4 h-4 mr-2 text-cyber-accent" />
                        )}
                        {log.original_filename}
                      </td>
                      <td className="p-3 font-mono text-xs text-slate-400">
                        {(log.file_size / 1024).toFixed(2)} KB
                      </td>
                      <td className="p-3 text-center">
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${statusBadge}`}>
                          {log.status}
                        </span>
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
