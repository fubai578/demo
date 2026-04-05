import React, { useState, useEffect, useRef } from 'react';

// ----------------------
// 1. 常量与配置
// ----------------------
const COLORS = {
  bg: '#0f1117',
  primary: '#00d9c0',
  danger: '#ff6b6b',
  safe: '#51cf66',
};

const STAGES = [
  { id: 1, name: 'APK 解析', time: '约 5s' },
  { id: 2, name: '第三方库识别', time: 'LibHunter' },
  { id: 3, name: 'CVE 漏洞验证', time: 'PHunter' },
];

// ----------------------
// 2. Mock 数据与 API
// ----------------------
const mockApi = {
  // 模拟上传获取基本信息
  uploadApk: (file) => new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        fileName: file.name || 'app-release.apk',
        size: file.size ? (file.size / 1024 / 1024).toFixed(2) + ' MB' : '15.4 MB',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        taskId: 'TASK-' + Math.random().toString(36).substr(2, 9).toUpperCase()
      });
    }, 800);
  }),
  // 模拟获取最终报告
  getReport: (taskId) => new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        apkName: 'app-release.apk',
        size: '15.4 MB',
        timeTaken: '24.5s',
        componentsCount: 3,
        vulnCount: 2,
        components: [
          {
            name: 'okhttp', version: '3.12.0', similarity: 0.95,
            cves: [
              { id: 'CVE-2021-0341', status: 'NOT_PRESENT', similarity: 0.88, desc: 'TLS 验证绕过' }
            ]
          },
          {
            name: 'commons-compress', version: '1.18', similarity: 0.85,
            cves: [
              { id: 'CVE-2018-1324', status: 'UNKNOWN', similarity: 0.45, desc: 'Zip 拒绝服务' }
            ]
          },
          {
            name: 'junrar', version: '7.4.0', similarity: 0.98,
            cves: [
              { id: 'CVE-2026-28208', status: 'PRESENT', similarity: 0.96, desc: '路径穿越漏洞' }
            ]
          }
        ]
      });
    }, 500);
  })
};

// ----------------------
// 3. UI 组件
// ----------------------

// 顶部导航栏
const Navbar = () => (
  <nav className="flex items-center justify-between px-8 py-4 border-b border-white/10 bg-white/5 backdrop-blur-md sticky top-0 z-50">
    <div className="flex items-center gap-3">
      {/* 盾牌 Logo SVG */}
      <svg className="w-8 h-8 text-[#00d9c0]" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
      <span className="text-xl font-mono font-bold tracking-wider text-white">APK Shield</span>
    </div>
    <div className="flex items-center gap-2">
      <span className="w-2.5 h-2.5 rounded-full bg-[#51cf66] animate-pulse"></span>
      <span className="text-sm font-mono text-[#51cf66]">System Online</span>
    </div>
  </nav>
);

// ----------------------
// 页面一：上传检测页
// ----------------------
const UploadView = ({ onUploadStart }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [fileInfo, setFileInfo] = useState(null);
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    setLoading(true);
    const info = await mockApi.uploadApk(file);
    setFileInfo(info);
    setLoading(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    handleFile(e.dataTransfer.files[0]);
  };

  return (
    <div className="max-w-4xl mx-auto mt-12 animate-fade-in transition-opacity duration-300">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-mono font-bold mb-4">Android 漏洞自动验证系统</h1>
        <p className="text-gray-400">基于 LibHunter 与 PHunter 的双引擎极速扫描</p>
      </div>

      {/* 拖拽上传区 */}
      <div
        className={`relative border-2 border-dashed rounded-xl p-16 text-center transition-all duration-300 backdrop-blur-sm bg-white/5 cursor-pointer
          ${isDragging ? 'border-[#00d9c0] bg-[#00d9c0]/10' : 'border-white/20 hover:border-[#00d9c0]'}`}
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => !fileInfo && fileInputRef.current.click()}
      >
        <input 
          type="file" 
          ref={fileInputRef} 
          className="hidden" 
          accept=".apk"
          onChange={(e) => handleFile(e.target.files[0])}
        />
        
        {!fileInfo && !loading && (
          <div className="flex flex-col items-center">
            <svg className="w-16 h-16 text-gray-500 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <p className="text-xl mb-2">点击或拖拽 APK 文件至此</p>
            <p className="text-sm text-gray-500 font-mono">支持扩展名: .apk</p>
          </div>
        )}

        {loading && <div className="text-[#00d9c0] animate-pulse">正在解析文件信息...</div>}

        {fileInfo && !loading && (
          <div className="flex flex-col items-center text-left max-w-md mx-auto p-6 rounded-lg bg-black/40 border border-white/10">
            <div className="w-full flex justify-between mb-2">
              <span className="text-gray-400">文件名:</span>
              <span className="font-mono text-white">{fileInfo.fileName}</span>
            </div>
            <div className="w-full flex justify-between mb-2">
              <span className="text-gray-400">大小:</span>
              <span className="font-mono text-white">{fileInfo.size}</span>
            </div>
            <div className="w-full flex justify-between mb-4">
              <span className="text-gray-400">SHA-256:</span>
              <span className="font-mono text-xs text-[#00d9c0] truncate w-48 text-right">{fileInfo.sha256}</span>
            </div>
            <button 
              onClick={(e) => { e.stopPropagation(); onUploadStart(fileInfo); }}
              className="w-full py-3 mt-4 bg-[#00d9c0] hover:bg-[#00b5a0] text-black font-bold rounded transition-colors"
            >
              开始检测
            </button>
            <button 
              onClick={(e) => { e.stopPropagation(); setFileInfo(null); }}
              className="mt-3 text-xs text-gray-500 hover:text-white transition-colors"
            >
              重新选择文件
            </button>
          </div>
        )}
      </div>

      {/* 底部统计 */}
      <div className="grid grid-cols-3 gap-6 mt-16">
        {[
          { label: '已检测 APK 数', value: '1,204' },
          { label: '发现漏洞数', value: '4,592', color: 'text-[#ff6b6b]' },
          { label: '平均检测时长', value: '28.5s' }
        ].map((stat, i) => (
          <div key={i} className="p-6 rounded-xl bg-white/5 border border-white/10 backdrop-blur-md text-center">
            <p className="text-gray-500 text-sm mb-2">{stat.label}</p>
            <p className={`text-3xl font-mono font-bold ${stat.color || 'text-white'}`}>{stat.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

// ----------------------
// 页面二：检测进度页
// ----------------------
const ProgressView = ({ fileInfo, onComplete }) => {
  const [currentStage, setCurrentStage] = useState(1);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const logsEndRef = useRef(null);

  // 模拟 SSE 日志流和进度推进
  useEffect(() => {
    let logInterval;
    let progressInterval;
    
    const startSimulation = () => {
      let currProg = 0;
      let stage = 1;

      progressInterval = setInterval(() => {
        currProg += Math.random() * 5; // 随机增加进度
        if (currProg >= 100) {
          currProg = 100;
          clearInterval(progressInterval);
          clearInterval(logInterval);
          setTimeout(() => onComplete(fileInfo.taskId), 1000);
        }

        setProgress(Math.min(currProg, 100));

        if (currProg > 30 && currProg < 70) stage = 2;
        if (currProg >= 70) stage = 3;
        setCurrentStage(stage);
      }, 500);

      // 模拟日志产生
      const mockLogLines = [
        "Initializing sandbox environment...",
        "Unpacking APK resources...",
        "Extracting classes.dex...",
        "[LibHunter] Analyzing control flow graphs...",
        "[LibHunter] Matching opcodes with signature DB...",
        "[LibHunter] Found component: okhttp v3.12.0",
        "[LibHunter] Found component: commons-compress v1.18",
        "[PHunter] Preparing vulnerability signatures...",
        "[PHunter] Verifying CVE-2021-0341 in okhttp...",
        "[PHunter] CVE-2021-0341 Status: NOT_PRESENT",
        "[PHunter] Verifying CVE-2018-1324 in commons-compress...",
        "Generating final security report..."
      ];

      let logIndex = 0;
      logInterval = setInterval(() => {
        if (logIndex < mockLogLines.length) {
          setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${mockLogLines[logIndex]}`]);
          logIndex++;
        }
      }, 800);
    };

    startSimulation();
    return () => { clearInterval(logInterval); clearInterval(progressInterval); };
  }, [fileInfo, onComplete]);

  // 自动滚动日志
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  return (
    <div className="max-w-5xl mx-auto mt-8 animate-fade-in transition-opacity duration-300">
      {/* 头部信息 */}
      <div className="flex justify-between items-center mb-8 p-6 bg-white/5 border border-white/10 rounded-xl backdrop-blur-md">
        <div>
          <h2 className="text-xl font-bold">{fileInfo.fileName}</h2>
          <p className="text-sm font-mono text-gray-500 mt-1">SHA256: {fileInfo.sha256.substr(0, 16)}...</p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-400">总进度</p>
          <p className="text-2xl font-mono text-[#00d9c0]">{progress.toFixed(0)}%</p>
        </div>
      </div>

      {/* 步骤条 */}
      <div className="flex items-center justify-between mb-8 px-4">
        {STAGES.map((stage, idx) => {
          const isActive = currentStage === stage.id;
          const isDone = currentStage > stage.id;
          return (
            <React.Fragment key={stage.id}>
              <div className="flex flex-col items-center relative z-10">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center font-mono font-bold transition-colors duration-300
                  ${isActive ? 'bg-[#00d9c0] text-black shadow-[0_0_15px_rgba(0,217,192,0.5)]' : 
                    isDone ? 'bg-[#51cf66] text-black' : 'bg-white/10 text-gray-500'}`}>
                  {isDone ? '✓' : stage.id}
                </div>
                <p className={`mt-3 text-sm ${isActive ? 'text-white' : 'text-gray-500'}`}>{stage.name}</p>
                <p className="text-xs text-gray-600 mt-1">{stage.time}</p>
              </div>
              {/* 连接线 */}
              {idx < STAGES.length - 1 && (
                <div className="flex-1 h-px bg-white/10 mx-4 relative top-[-15px]">
                  <div 
                    className="absolute left-0 top-0 h-full bg-[#51cf66] transition-all duration-500"
                    style={{ width: isDone ? '100%' : '0%' }}
                  />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* 终端日志区 */}
      <div className="bg-black/80 rounded-xl border border-white/10 p-4 h-80 overflow-y-auto font-mono text-sm">
        <div className="flex gap-2 mb-4 sticky top-0 bg-black/80 pb-2">
          <span className="w-3 h-3 rounded-full bg-[#ff6b6b]"></span>
          <span className="w-3 h-3 rounded-full bg-yellow-500"></span>
          <span className="w-3 h-3 rounded-full bg-[#51cf66]"></span>
        </div>
        {logs.map((log, i) => (
          <div key={i} className="text-[#51cf66] mb-1 leading-relaxed">{log}</div>
        ))}
        {currentStage < 4 && (
          <div className="text-[#00d9c0] animate-pulse mt-2">_</div>
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
};

// ----------------------
// 页面三：报告详情页
// ----------------------
const ReportView = ({ reportData, onReset }) => {
  const [expandedLib, setExpandedLib] = useState(null);

  if (!reportData) return <div className="text-center mt-20 text-[#00d9c0] animate-pulse">正在生成报告...</div>;

  return (
    <div className="max-w-6xl mx-auto mt-8 pb-20 animate-fade-in transition-opacity duration-300">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-mono font-bold border-l-4 border-[#00d9c0] pl-4">检测报告</h1>
        <div className="flex gap-4">
          <button className="px-4 py-2 border border-[#00d9c0] text-[#00d9c0] rounded hover:bg-[#00d9c0]/10 transition">
            导出 JSON
          </button>
          <button 
            onClick={onReset}
            className="px-4 py-2 bg-[#00d9c0] text-black font-bold rounded hover:bg-[#00b5a0] transition"
          >
            检测另一个文件
          </button>
        </div>
      </div>

      {/* 摘要卡片 */}
      <div className="grid grid-cols-5 gap-4 mb-8">
        {[
          { label: '文件名称', value: reportData.apkName },
          { label: '文件大小', value: reportData.size },
          { label: '检测耗时', value: reportData.timeTaken },
          { label: '发现组件数', value: reportData.componentsCount, color: 'text-[#00d9c0]' },
          { label: '存在漏洞', value: reportData.vulnCount, color: 'text-[#ff6b6b]' },
        ].map((item, i) => (
          <div key={i} className="bg-white/5 backdrop-blur-md border border-white/10 p-5 rounded-xl">
            <div className="text-xs text-gray-500 mb-2">{item.label}</div>
            <div className={`text-xl font-mono font-bold truncate ${item.color || 'text-white'}`} title={item.value}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      {/* 组件与漏洞列表 */}
      <h2 className="text-xl font-mono mb-4 text-gray-300">检测到的第三方库 ({reportData.components.length})</h2>
      <div className="space-y-4">
        {reportData.components.map((lib, idx) => {
          const isExpanded = expandedLib === idx;
          const hasVuln = lib.cves.some(cve => cve.status === 'PRESENT');
          const hasUnknown = lib.cves.some(cve => cve.status === 'UNKNOWN');
          
          let statusBorder = 'border-white/10';
          if (hasVuln) statusBorder = 'border-[#ff6b6b]/50';
          else if (hasUnknown) statusBorder = 'border-yellow-500/50';

          return (
            <div key={idx} className={`bg-white/5 border ${statusBorder} rounded-xl overflow-hidden transition-all duration-300`}>
              {/* 库头部 */}
              <div 
                className="flex items-center justify-between p-5 cursor-pointer hover:bg-white/5"
                onClick={() => setExpandedLib(isExpanded ? null : idx)}
              >
                <div className="flex items-center gap-6 w-2/3">
                  <div className="w-1/3 font-mono text-lg">{lib.name}</div>
                  <div className="w-1/4 text-sm text-gray-400">v{lib.version}</div>
                  <div className="w-1/3 flex items-center gap-2">
                    <span className="text-xs text-gray-500">特征相似度</span>
                    <div className="flex-1 h-2 bg-black rounded-full overflow-hidden">
                      <div className="h-full bg-[#00d9c0]" style={{ width: `${lib.similarity * 100}%` }}></div>
                    </div>
                    <span className="text-xs font-mono">{(lib.similarity * 100).toFixed(0)}%</span>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  {hasVuln && <span className="px-2 py-1 bg-[#ff6b6b]/20 text-[#ff6b6b] text-xs rounded border border-[#ff6b6b]/30">风险库</span>}
                  <svg className={`w-5 h-5 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* 展开的 CVE 列表 */}
              {isExpanded && (
                <div className="bg-black/40 border-t border-white/10 p-5">
                  <h3 className="text-sm text-gray-500 mb-3">相关的 CVE 漏洞验证结果:</h3>
                  <div className="grid grid-cols-1 gap-3">
                    {lib.cves.map((cve, cidx) => {
                      let statusColor = 'text-gray-400 border-gray-600';
                      let statusBg = 'bg-gray-800/30';
                      let statusText = '未确认 (UNKNOWN)';

                      if (cve.status === 'PRESENT') {
                        statusColor = 'text-[#ff6b6b] border-[#ff6b6b]/30';
                        statusBg = 'bg-[#ff6b6b]/10';
                        statusText = '漏洞存在 (PRESENT)';
                      } else if (cve.status === 'NOT_PRESENT') {
                        statusColor = 'text-[#51cf66] border-[#51cf66]/30';
                        statusBg = 'bg-[#51cf66]/10';
                        statusText = '已修复 (NOT_PRESENT)';
                      }

                      return (
                        <div key={cidx} className={`flex items-center justify-between p-4 border rounded ${statusColor} ${statusBg}`}>
                          <div className="flex items-center gap-4">
                            <span className="font-mono font-bold text-lg">{cve.id}</span>
                            <span className="text-sm opacity-80">{cve.desc}</span>
                          </div>
                          <div className="flex items-center gap-6">
                            <div className="text-sm">
                              <span className="opacity-60 mr-2">补丁相似度</span>
                              <span className="font-mono">{(cve.similarity * 100).toFixed(0)}%</span>
                            </div>
                            <div className={`px-3 py-1 rounded-full text-xs border ${statusColor} font-bold`}>
                              {statusText}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ----------------------
// 主容器
// ----------------------
export default function App() {
  const [currentView, setCurrentView] = useState('upload'); // 'upload' | 'progress' | 'report'
  const [fileInfo, setFileInfo] = useState(null);
  const [reportData, setReportData] = useState(null);

  const startScan = (info) => {
    setFileInfo(info);
    setCurrentView('progress');
  };

  const handleComplete = async (taskId) => {
    const data = await mockApi.getReport(taskId);
    setReportData(data);
    setCurrentView('report');
  };

  const resetApp = () => {
    setFileInfo(null);
    setReportData(null);
    setCurrentView('upload');
  };

  return (
    <div className={`font-sans text-gray-200 min-h-screen selection:bg-[#00d9c0]/30 overflow-x-hidden`} style={{ backgroundColor: COLORS.bg }}>
      <Navbar />
      
      <main className="px-4">
        {currentView === 'upload' && <UploadView onUploadStart={startScan} />}
        {currentView === 'progress' && <ProgressView fileInfo={fileInfo} onComplete={handleComplete} />}
        {currentView === 'report' && <ReportView reportData={reportData} onReset={resetApp} />}
      </main>

      {/* 全局样式补充（如动画） */}
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in {
          animation: fadeIn 0.4s ease-out forwards;
        }
        /* 自定义滚动条 */
        ::-webkit-scrollbar {
          width: 8px;
        }
        ::-webkit-scrollbar-track {
          background: #0f1117; 
        }
        ::-webkit-scrollbar-thumb {
          background: #333; 
          border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
          background: #00d9c0; 
        }
      `}} />
    </div>
  );
}