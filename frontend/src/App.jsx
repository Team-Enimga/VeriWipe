import React, { useState, useEffect } from 'react';
import { 
  Shield, HardDrive, Zap, Trash2, Search, Link2, 
  CheckCircle2, AlertTriangle, RefreshCw, Terminal, 
  FileText, Activity, Lock, Cpu, Database
} from 'lucide-react';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [devices, setDevices] = useState([]);
  const [systemStatus, setSystemStatus] = useState(null);
  const [blocks, setBlocks] = useState([]);
  const [labDisks, setLabDisks] = useState([]);

  // Wipe Form State
  const [wipeTarget, setWipeTarget] = useState('');
  const [wipeMethod, setWipeMethod] = useState('NIST_800_88_PURGE');
  const [wipeProgress, setWipeProgress] = useState({ percent: 0, text: 'Idle', throughput: 0 });
  const [wipeResult, setWipeResult] = useState(null);

  // Carve Form State
  const [carveSource, setCarveSource] = useState('./test_artifacts/forensic_demo.img');
  const [carveFormat, setCarveFormat] = useState('ALL');
  const [carveProgress, setCarveProgress] = useState({ percent: 0, text: 'Idle', count: 0 });
  const [carveResult, setCarveResult] = useState(null);

  // Autonuke State
  const [autonukeLog, setAutonukeLog] = useState('Awaiting execution. Boot media protected.');
  const [countdown, setCountdown] = useState(null);

  // Blockchain Verification State
  const [chainVerify, setChainVerify] = useState(null);

  useEffect(() => {
    loadStatus();
    loadDevices();
    loadBlockchain();
    loadLab();

    // Connect SSE
    const sse = new EventSource(`${API_BASE}/events`);
    sse.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);
        if (ev.type === 'WIPE_PROGRESS') {
          setWipeProgress({
            percent: ev.percent,
            text: `[Pass ${ev.pass}/${ev.total_passes}] ${(ev.written_bytes / (1024*1024)).toFixed(0)} MB written`,
            throughput: ev.throughput_mbps
          });
        } else if (ev.type === 'CARVE_PROGRESS') {
          setCarveProgress({
            percent: ev.percent,
            text: `Carving sector stream: ${ev.percent.toFixed(1)}%`,
            count: ev.artifacts_found
          });
        }
      } catch (err) {}
    };

    return () => sse.close();
  }, []);

  const loadStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      setSystemStatus(await res.json());
    } catch (e) {}
  };

  const loadDevices = async () => {
    try {
      const res = await fetch(`${API_BASE}/devices`);
      const data = await res.json();
      setDevices(data.devices || []);
    } catch (e) {}
  };

  const loadBlockchain = async () => {
    try {
      const res = await fetch(`${API_BASE}/blockchain`);
      const data = await res.json();
      setBlocks(data.blocks || []);
      const vRes = await fetch(`${API_BASE}/blockchain/verify`);
      setChainVerify(await vRes.json());
    } catch (e) {}
  };

  const loadLab = async () => {
    try {
      const res = await fetch(`${API_BASE}/lab/list`);
      const data = await res.json();
      setLabDisks(data.disks || []);
    } catch (e) {}
  };

  const executeWipe = async () => {
    if (!wipeTarget) return alert('Enter target device path');
    setWipeProgress({ percent: 10, text: 'Executing OEM hardware commands & multi-pass wipe...', throughput: 0 });
    setWipeResult(null);

    try {
      const res = await fetch(`${API_BASE}/wipe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: wipeTarget, method: wipeMethod, verify_percentage: 100 })
      });
      const data = await res.json();
      if (data.success) {
        setWipeProgress({ percent: 100, text: 'Complete & Verified!', throughput: data.result.throughput_mbps });
        setWipeResult(data.result);
        loadBlockchain();
      } else {
        alert('Wipe Error: ' + data.error);
        setWipeProgress({ percent: 0, text: 'Error', throughput: 0 });
      }
    } catch (e) {
      alert('Network error: ' + e);
    }
  };

  const executeCarve = async () => {
    if (!carveSource) return alert('Enter source path');
    setCarveProgress({ percent: 10, text: 'Parsing raw sector stream with format validators...', count: 0 });
    setCarveResult(null);

    try {
      const res = await fetch(`${API_BASE}/carve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: carveSource, format: carveFormat })
      });
      const data = await res.json();
      if (data.success) {
        setCarveProgress({ percent: 100, text: `Carved ${data.result.provenance.total_artifacts_recovered} files!`, count: data.result.provenance.total_artifacts_recovered });
        setCarveResult(data.result);
        loadBlockchain();
      } else {
        alert('Carve Error: ' + data.error);
        setCarveProgress({ percent: 0, text: 'Error', count: 0 });
      }
    } catch (e) {
      alert('Network error: ' + e);
    }
  };

  const createTestDisk = async () => {
    try {
      const res = await fetch(`${API_BASE}/lab/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ size_mb: 20 })
      });
      const data = await res.json();
      if (data.success) {
        alert('Synthetic 20MB forensic test disk generated!');
        setWipeTarget(data.manifest.image_path);
        setCarveSource(data.manifest.image_path);
        loadLab();
      }
    } catch (e) {}
  };

  const triggerAutonuke = async (dryRun) => {
    setAutonukeLog(`Starting ${dryRun ? 'DRY-RUN SIMULATION' : 'AUTONOMOUS ONE-SHOT SANITIZATION'}...\n`);
    try {
      const res = await fetch(`${API_BASE}/autonuke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dry_run: dryRun, countdown_seconds: 5 })
      });
      const data = await res.json();
      if (data.success) {
        setAutonukeLog(prev => prev + `Targets Detected: ${data.report.targets_detected}\nSanitized: ${data.report.targets_sanitized}\nSession ID: ${data.report.session_id}\n\nOperation complete. Certificates saved to USB.\n`);
        loadBlockchain();
      } else {
        setAutonukeLog(prev => prev + `Error: ${data.error}\n`);
      }
    } catch (e) {
      setAutonukeLog(prev => prev + `Failed: ${e}\n`);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <header style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '16px 36px', background: 'rgba(11, 17, 32, 0.85)', backdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(6, 182, 212, 0.25)', sticky: 'top', zIndex: 100
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '42px', height: '42px', background: 'linear-gradient(135deg, #06b6d4, #10b981)',
            borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 20px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={24} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 800, background: 'linear-gradient(to right, #fff, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              VERIWIPE
            </h1>
            <p style={{ fontSize: '11px', color: '#22d3ee', fontFamily: 'var(--font-mono)' }}>
              NTRO PS 26149 • 100% PURE RUST APPLIANCE
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(6,182,212,0.25)', padding: '6px 14px', borderRadius: '20px', fontSize: '12px', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 10px #10b981' }} className="pulse-emerald"></span>
            <span>RUST DAEMON ONLINE</span>
          </div>
          <div style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(6,182,212,0.25)', padding: '6px 14px', borderRadius: '20px', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
            BLOCKCHAIN #{blocks.length}
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', flex: 1, maxWidth: '1600px', margin: '0 auto', width: '100%', padding: '24px', gap: '24px' }}>
        {/* Sidebar */}
        <aside style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <button 
            className={`btn-outline ${activeTab === 'dashboard' ? 'active' : ''}`}
            style={{ width: '100%', justifyContent: 'flex-start', padding: '12px 16px', background: activeTab === 'dashboard' ? 'rgba(6,182,212,0.15)' : 'transparent', borderColor: activeTab === 'dashboard' ? '#06b6d4' : 'transparent' }}
            onClick={() => setActiveTab('dashboard')}
          >
            <HardDrive size={18} /> Storage Overview
          </button>
          <button 
            className={`btn-outline ${activeTab === 'autonuke' ? 'active' : ''}`}
            style={{ width: '100%', justifyContent: 'flex-start', padding: '12px 16px', background: activeTab === 'autonuke' ? 'rgba(244,63,94,0.15)' : 'transparent', borderColor: activeTab === 'autonuke' ? '#f43f5e' : 'transparent', color: activeTab === 'autonuke' ? '#fda4af' : '#94a3b8' }}
            onClick={() => setActiveTab('autonuke')}
          >
            <Zap size={18} /> One-Shot Autonuke
          </button>
          <button 
            className={`btn-outline ${activeTab === 'sanitizer' ? 'active' : ''}`}
            style={{ width: '100%', justifyContent: 'flex-start', padding: '12px 16px', background: activeTab === 'sanitizer' ? 'rgba(6,182,212,0.15)' : 'transparent', borderColor: activeTab === 'sanitizer' ? '#06b6d4' : 'transparent' }}
            onClick={() => setActiveTab('sanitizer')}
          >
            <Trash2 size={18} /> Certified Sanitizer
          </button>
          <button 
            className={`btn-outline ${activeTab === 'carver' ? 'active' : ''}`}
            style={{ width: '100%', justifyContent: 'flex-start', padding: '12px 16px', background: activeTab === 'carver' ? 'rgba(6,182,212,0.15)' : 'transparent', borderColor: activeTab === 'carver' ? '#06b6d4' : 'transparent' }}
            onClick={() => setActiveTab('carver')}
          >
            <Search size={18} /> Forensic Carver
          </button>
          <button 
            className={`btn-outline ${activeTab === 'blockchain' ? 'active' : ''}`}
            style={{ width: '100%', justifyContent: 'flex-start', padding: '12px 16px', background: activeTab === 'blockchain' ? 'rgba(6,182,212,0.15)' : 'transparent', borderColor: activeTab === 'blockchain' ? '#06b6d4' : 'transparent' }}
            onClick={() => setActiveTab('blockchain')}
          >
            <Link2 size={18} /> Blockchain Ledger
          </button>
          <button 
            className={`btn-outline ${activeTab === 'lab' ? 'active' : ''}`}
            style={{ width: '100%', justifyContent: 'flex-start', padding: '12px 16px', background: activeTab === 'lab' ? 'rgba(6,182,212,0.15)' : 'transparent', borderColor: activeTab === 'lab' ? '#06b6d4' : 'transparent' }}
            onClick={() => setActiveTab('lab')}
          >
            <Activity size={18} /> Synthetic Test Lab
          </button>
        </aside>

        {/* Content Pane */}
        <main style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* TAB 1: STORAGE DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div className="glass-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <HardDrive size={20} color="#06b6d4" /> Discovered Storage Media & Isolation Status
                </h2>
                <button className="btn-outline" onClick={loadDevices}><RefreshCw size={14} /> Rescan Devices</button>
              </div>

              <table>
                <thead>
                  <tr>
                    <th>Device Node</th>
                    <th>Bus Type</th>
                    <th>Capacity</th>
                    <th>Hardware Model</th>
                    <th>Safety Lock</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d, i) => (
                    <tr key={i}>
                      <td style={{ color: '#22d3ee', fontWeight: 'bold' }}>{d.path}</td>
                      <td>{d.bus_type}</td>
                      <td>{d.size_gb.toFixed(1)} GB</td>
                      <td>
                        {d.model}
                        <div style={{ fontSize: '10px', color: '#64748b' }}>SN: {d.serial_number}</div>
                      </td>
                      <td>
                        <span className={d.is_protected ? 'badge-locked' : 'badge-ready'}>
                          {d.is_protected ? 'LOCKED 🔒' : 'READY ✅'}
                        </span>
                        <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '4px' }}>
                          {d.protection_reason || 'Safe to wipe'}
                        </div>
                      </td>
                      <td>
                        {!d.is_protected ? (
                          <button className="btn-outline" style={{ padding: '4px 10px', fontSize: '11px' }} onClick={() => { setWipeTarget(d.path); setActiveTab('sanitizer'); }}>
                            Select
                          </button>
                        ) : (
                          <span style={{ color: '#64748b', fontSize: '11px' }}>Protected</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 2: AUTONUKE */}
          {activeTab === 'autonuke' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{
                background: 'linear-gradient(145deg, rgba(244, 63, 94, 0.12), rgba(15, 23, 42, 0.8))',
                border: '2px dashed rgba(244, 63, 94, 0.4)', borderRadius: '14px', padding: '36px',
                textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px'
              }}>
                <h2 style={{ fontSize: '24px', fontWeight: 800, color: '#fda4af', letterSpacing: '1px' }}>
                  ONE-SHOT BARE-METAL AUTONOMOUS SANITIZATION
                </h2>
                <p style={{ color: '#94a3b8', maxWidth: '650px', fontSize: '13px', lineHeight: '1.6' }}>
                  When booted from USB or triggered in autonomous mode, VeriWipe auto-discovers all non-boot storage media, strictly isolates the boot pendrive, applies OEM hardware commands + NIST 800-88 Purge, verifies with read-back and forensic carver, and stores signed audit certificates directly on the USB.
                </p>

                <div style={{ display: 'flex', gap: '16px', marginTop: '12px' }}>
                  <button className="btn-danger" onClick={() => triggerAutonuke(false)}>
                    <Zap size={16} /> ENGAGE AUTONUKE (15s Countdown)
                  </button>
                  <button className="btn-outline" onClick={() => triggerAutonuke(true)}>
                    <Shield size={16} /> RUN SAFE DRY-RUN SIMULATION
                  </button>
                </div>
              </div>

              <div className="glass-panel">
                <h3 style={{ fontSize: '15px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Terminal size={16} color="#06b6d4" /> Live Hardware Controller Log
                </h3>
                <div style={{
                  background: '#030712', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px',
                  fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#38bdf8', height: '160px',
                  overflowY: 'auto', whiteSpace: 'pre-wrap', lineHeight: '1.5'
                }}>
                  {autonukeLog}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: CERTIFIED SANITIZER */}
          {activeTab === 'sanitizer' && (
            <div className="glass-panel">
              <h2 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Trash2 size={20} color="#f43f5e" /> Device-Aware Certified Media Sanitizer
              </h2>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
                <div>
                  <label style={{ fontSize: '12px', color: '#94a3b8' }}>Target Device Node or Raw Disk Image</label>
                  <input 
                    type="text" 
                    value={wipeTarget}
                    onChange={(e) => setWipeTarget(e.target.value)}
                    placeholder="./test_artifacts/forensic_demo.img or /dev/sdb" 
                    style={{ width: '100%', padding: '12px', background: 'rgba(15,23,42,0.8)', border: '1px solid #1e293b', color: '#fff', borderRadius: '8px', fontFamily: 'var(--font-mono)', marginTop: '6px' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: '#94a3b8' }}>Sanitization Standard</label>
                  <select 
                    value={wipeMethod}
                    onChange={(e) => setWipeMethod(e.target.value)}
                    style={{ width: '100%', padding: '12px', background: 'rgba(15,23,42,0.8)', border: '1px solid #1e293b', color: '#fff', borderRadius: '8px', fontFamily: 'var(--font-mono)', marginTop: '6px' }}
                  >
                    <option value="NIST_800_88_PURGE">NIST SP 800-88 Rev 1 (Purge: Crypto/Random + Zero + OEM)</option>
                    <option value="NIST_800_88_CLEAR">NIST SP 800-88 Rev 1 (Clear: Zero Overwrite)</option>
                    <option value="DOD_5220_22_M">DoD 5220.22-M NISPOM (3-Pass Military Overwrite)</option>
                    <option value="ZERO_QUICK">Quick Zero Wipe</option>
                  </select>
                </div>
              </div>

              <button className="btn-danger" onClick={executeWipe}>
                <Trash2 size={16} /> EXECUTE CERTIFIED SANITIZATION
              </button>

              <div style={{ width: '100%', height: '10px', background: '#0f172a', borderRadius: '5px', overflow: 'hidden', border: '1px solid #1e293b', margin: '18px 0 8px' }}>
                <div style={{ height: '100%', width: `${wipeProgress.percent}%`, background: 'linear-gradient(90deg, #06b6d4, #10b981)', transition: 'width 0.2s' }}></div>
              </div>
              <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#22d3ee' }}>
                {wipeProgress.text} {wipeProgress.throughput > 0 && `@ ${wipeProgress.throughput.toFixed(1)} MB/s`}
              </div>

              {wipeResult && (
                <div style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid #10b981', borderRadius: '8px', padding: '18px', marginTop: '16px' }}>
                  <div style={{ fontWeight: 700, color: '#34d399', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <CheckCircle2 size={18} /> Sanitization Certified & Anchored on Blockchain!
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: '1.7' }}>
                    <div><strong>Target Media:</strong> {wipeResult.target} ({(wipeResult.total_bytes / (1024*1024)).toFixed(1)} MB)</div>
                    <div><strong>Throughput:</strong> {wipeResult.throughput_mbps.toFixed(1)} MB/s ({wipeResult.duration_seconds.toFixed(2)}s)</div>
                    <div><strong>Read-Back Verification:</strong> {wipeResult.verification.details}</div>
                    <div><strong>Forensic Carver Cross-Check:</strong> {wipeResult.forensic_remnants_found} remnants found (Clean: {wipeResult.forensic_carver_verified_clean ? 'YES' : 'NO'})</div>
                    <div><strong>Blockchain Block Hash:</strong> {wipeResult.blockchain_block_hash}</div>
                    <div><strong>Printable Certificate HTML:</strong> {wipeResult.certificate_html_path}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: FORENSIC CARVER */}
          {activeTab === 'carver' && (
            <div className="glass-panel">
              <h2 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Search size={20} color="#06b6d4" /> Advanced File Carving & Evidence Provenance Graph
              </h2>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginBottom: '20px' }}>
                <div>
                  <label style={{ fontSize: '12px', color: '#94a3b8' }}>Source Raw Image or Block Device</label>
                  <input 
                    type="text" 
                    value={carveSource}
                    onChange={(e) => setCarveSource(e.target.value)}
                    style={{ width: '100%', padding: '12px', background: 'rgba(15,23,42,0.8)', border: '1px solid #1e293b', color: '#fff', borderRadius: '8px', fontFamily: 'var(--font-mono)', marginTop: '6px' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: '#94a3b8' }}>Format Filter</label>
                  <select 
                    value={carveFormat}
                    onChange={(e) => setCarveFormat(e.target.value)}
                    style={{ width: '100%', padding: '12px', background: 'rgba(15,23,42,0.8)', border: '1px solid #1e293b', color: '#fff', borderRadius: '8px', fontFamily: 'var(--font-mono)', marginTop: '6px' }}
                  >
                    <option value="ALL">ALL Supported Formats</option>
                    <option value="PDF">PDF Documents</option>
                    <option value="JPEG">JPEG Images</option>
                    <option value="PNG">PNG Images</option>
                    <option value="ZIP_OFFICE">ZIP / Office Documents</option>
                    <option value="MP4">MP4 Video Containers</option>
                  </select>
                </div>
              </div>

              <button className="btn-primary" onClick={executeCarve}>
                <Search size={16} /> BEGIN STREAMING FORENSIC CARVE
              </button>

              <div style={{ width: '100%', height: '10px', background: '#0f172a', borderRadius: '5px', overflow: 'hidden', border: '1px solid #1e293b', margin: '18px 0 8px' }}>
                <div style={{ height: '100%', width: `${carveProgress.percent}%`, background: 'linear-gradient(90deg, #06b6d4, #10b981)', transition: 'width 0.2s' }}></div>
              </div>
              <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#22d3ee' }}>
                {carveProgress.text}
              </div>

              {carveResult && (
                <div style={{ marginTop: '20px' }}>
                  <h3 style={{ fontSize: '14px', marginBottom: '12px', color: '#22d3ee' }}>
                    Extracted Artifacts & Provenance Graph ({carveResult.provenance.total_artifacts_recovered} Recovered):
                  </h3>
                  <table>
                    <thead>
                      <tr>
                        <th>Artifact Filename</th>
                        <th>Format</th>
                        <th>Confidence</th>
                        <th>Physical Sector Offset</th>
                        <th>Length</th>
                        <th>Validation Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {carveResult.provenance.artifacts.map((a, i) => (
                        <tr key={i}>
                          <td style={{ color: '#22d3ee', fontWeight: 'bold' }}>{a.filename}</td>
                          <td>{a.format}</td>
                          <td><span style={{ color: '#34d399', fontWeight: 'bold' }}>{a.confidence_score}%</span></td>
                          <td>0x{a.start_offset.toString(16).toUpperCase()}</td>
                          <td>{a.length_bytes} B</td>
                          <td>{a.structural_status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: BLOCKCHAIN */}
          {activeTab === 'blockchain' && (
            <div className="glass-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Link2 size={20} color="#06b6d4" /> Append-Only Tamper-Evident Merkle Event Ledger
                </h2>
                <button className="btn-outline" onClick={loadBlockchain}><RefreshCw size={14} /> Verify Integrity</button>
              </div>

              {chainVerify && (
                <div style={{
                  padding: '14px', borderRadius: '8px', fontFamily: 'var(--font-mono)', fontSize: '12px', marginBottom: '16px',
                  background: chainVerify.verification.is_valid ? 'rgba(16,185,129,0.15)' : 'rgba(244,63,94,0.15)',
                  borderColor: chainVerify.verification.is_valid ? '#10b981' : '#f43f5e',
                  border: '1px solid'
                }}>
                  {chainVerify.verification.is_valid ? (
                    <div style={{ color: '#34d399' }}>
                      ✅ <strong>BLOCKCHAIN AUDIT CHAIN CRYPTOGRAPHICALLY VALID</strong> • {chainVerify.verification.verified_blocks} Blocks Verified with Ed25519 Signatures & SHA-256 Hash Links
                    </div>
                  ) : (
                    <div style={{ color: '#f43f5e' }}>
                      ❌ <strong>TAMPERING DETECTED IN AUDIT CHAIN</strong> • Discrepancy at block #{chainVerify.verification.invalid_block_index}
                    </div>
                  )}
                </div>
              )}

              <table>
                <thead>
                  <tr>
                    <th>Index</th>
                    <th>Event Type</th>
                    <th>Target Node</th>
                    <th>Block Hash (SHA-256)</th>
                    <th>Parent Hash Link</th>
                    <th>Digital Signature</th>
                  </tr>
                </thead>
                <tbody>
                  {blocks.map((b, i) => (
                    <tr key={i}>
                      <td style={{ color: '#22d3ee', fontWeight: 'bold' }}>#{b.index}</td>
                      <td>{b.event_type}</td>
                      <td>{b.target_id}</td>
                      <td style={{ fontSize: '11px' }}>{b.block_hash.substring(0, 20)}...</td>
                      <td style={{ fontSize: '11px', color: '#64748b' }}>{b.previous_hash.substring(0, 20)}...</td>
                      <td style={{ color: '#34d399', fontSize: '11px' }}>Ed25519 Valid</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 6: SYNTHETIC TEST LAB */}
          {activeTab === 'lab' && (
            <div className="glass-panel">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Activity size={20} color="#10b981" /> Synthetic Forensic Test Laboratory (Safe Judge Sandbox)
                </h2>
                <button className="btn-primary" onClick={createTestDisk}>🧪 Generate 20MB Synthetic Disk</button>
              </div>

              <p style={{ color: '#94a3b8', fontSize: '13px', lineHeight: '1.6', marginBottom: '20px' }}>
                Generate synthetic raw disk images pre-populated with realistic partition structures and valid forensic files (PDF, JPEG, ZIP, PNG). Judges can test carving, verify hashes, execute NIST wipes, and confirm 0 remnants safely without touching physical drives.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {labDisks.map((d, i) => (
                  <div key={i} style={{ background: 'rgba(15,23,42,0.6)', border: '1px solid #1e293b', padding: '16px', borderRadius: '8px' }}>
                    <div style={{ fontWeight: 700, color: '#22d3ee', marginBottom: '6px' }}>
                      {d.image_path} ({d.size_mb} MB)
                    </div>
                    <div style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '10px' }}>
                      Injected Artifacts: {d.artifacts.map(a => a.name).join(', ')}
                    </div>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      <button className="btn-outline" style={{ padding: '4px 12px', fontSize: '11px' }} onClick={() => { setCarveSource(d.image_path); setActiveTab('carver'); }}>
                        <Search size={12} /> Carve Artifacts
                      </button>
                      <button className="btn-outline" style={{ padding: '4px 12px', fontSize: '11px' }} onClick={() => { setWipeTarget(d.image_path); setActiveTab('sanitizer'); }}>
                        <Trash2 size={12} /> Wipe Disk
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
