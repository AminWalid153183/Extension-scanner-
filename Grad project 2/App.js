import React, { useState } from 'react';
import './App.css';

function App() {
  const [scanLevel, setScanLevel] = useState('medium');
  const [results, setResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });

  const handleScan = async () => {
    setIsScanning(true);
    setResults([]);
    try {
      const response = await fetch(`http://localhost:8000/scan-installed?scan_level=${scanLevel}`);
      const data = await response.json();
      setResults(data.extensions);
    } catch (error) {
      console.error('Scan failed:', error);
    }
    setIsScanning(false);
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel.toLowerCase()) {
      case 'high': return 'red';
      case 'medium': return 'orange';
      case 'low': return 'green';
      default: return 'black';
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Chrome Extension Security Scanner</h1>
        
        <div className="controls">
          <select 
            value={scanLevel}
            onChange={(e) => setScanLevel(e.target.value)}
            disabled={isScanning}
          >
            <option value="low">Low Intensity</option>
            <option value="medium">Medium Intensity</option>
            <option value="aggressive">Aggressive</option>
          </select>

          <button 
            onClick={handleScan}
            disabled={isScanning}
          >
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>

        {isScanning && (
          <div className="progress">
            <p>Scanning: {progress.current}/{progress.total} extensions</p>
          </div>
        )}

        <div className="results">
          <h2>Scan Results</h2>
          <table>
            <thead>
              <tr>
                <th>Extension ID</th>
                <th>Version</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result, index) => (
                <tr key={index}>
                  <td>{result.extension_id}</td>
                  <td>{result.version}</td>
                  <td>{result.risk_score.toFixed(1)}</td>
                  <td style={{ color: getRiskColor(result.risk_level) }}>
                    {result.risk_level}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </header>
    </div>
  );
}

export default App;