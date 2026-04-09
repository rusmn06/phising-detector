import React, { useState } from 'react';
import { scanURL } from '../services/api';
import VerdictBadge, { VerdictMessage } from './VerdictBadge';
import LoadingSpinner from './LoadingSpinner';
import { Search, Link as LinkIcon, AlertCircle, CheckCircle, ExternalLink, Shield } from 'lucide-react';

function ScanURL() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // Validasi URL sederhana
  const isValidUrl = (string) => {
    try {
      new URL(string);
      return string.startsWith('http://') || string.startsWith('https://');
    } catch {
      return false;
    }
  };

  // Handle scan
  const handleScan = async () => {
    // Reset state
    setError(null);
    setResult(null);

    // Validasi input
    if (!url.trim()) {
      setError('Masukkan URL yang ingin dicek.');
      return;
    }

    if (!isValidUrl(url)) {
      setError('Format URL tidak valid. Harus dimulai dengan http:// atau https://');
      return;
    }

    setLoading(true);

    try {
      const response = await scanURL(url);
      setResult(response.data);
    } catch (err) {
      console.error('URL scan error:', err);
      setError(err.response?.data?.detail || 'Gagal menganalisis URL. Coba lagi.');
    } finally {
      setLoading(false);
    }
  };

  // Handle Enter key
  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !loading) {
      handleScan();
    }
  };

  // Reset form
  const handleReset = () => {
    setUrl('');
    setResult(null);
    setError(null);
    setLoading(false);
  };

  // Helper untuk warna berdasarkan status
  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'malicious': return 'text-red-600 bg-red-100 border-red-500';
      case 'suspicious': return 'text-yellow-600 bg-yellow-100 border-yellow-500';
      case 'clean': return 'text-green-600 bg-green-100 border-green-500';
      case 'unknown': return 'text-gray-600 bg-gray-100 border-gray-500';
      default: return 'text-gray-600 bg-gray-100 border-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Scan URL</h1>
        <p className="mt-2 text-gray-600">
          Cek link mencurigakan untuk deteksi phishing/malware
        </p>
      </div>

      {/* Input Area */}
      {!result && (
        <div className="bg-white rounded-xl shadow-md p-6 border border-gray-200">
          <div className="space-y-4">
            {/* URL Input */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                URL yang ingin dicek
              </label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="https://example.com/login"
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-sky-500 focus:border-sky-500 outline-none transition-colors"
                    disabled={loading}
                  />
                </div>
                <button
                  onClick={handleScan}
                  disabled={loading}
                  className={`px-5 py-2.5 bg-sky-600 text-white font-semibold rounded-lg hover:bg-sky-700 disabled:bg-sky-300 transition-colors flex items-center ${
                  loading 
                    ? 'bg-sky-400 cursor-not-allowed' 
                    : 'hover:bg-sky-700 hover:shadow-md'
                }`}
                >
                  {loading ? (
                    <div className="flex items-center">
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2" />
                        <span className="text-sm">Scanning...</span>
                      </div>
                    ) : (
                      <div className="flex items-center">
                        <Search className="h-4 w-4 mr-2" />
                        <span>Scan</span>
                      </div>
                  )}
                </button>
              </div>
            </div>

            {/* Error Message */}
            {error && (
              <div className="p-4 bg-red-50 border border-red-200 rounded-lg flex items-start">
                <AlertCircle className="h-5 w-5 text-red-600 mr-3 mt-0.5 flex-shrink-0" />
                <p className="text-red-700">{error}</p>
              </div>
            )}

            {/* Tips */}
            <div className="bg-sky-50 border border-sky-200 rounded-lg p-4">
              <h4 className="font-semibold text-sky-900 mb-2 flex items-center">
                <AlertCircle className="h-4 w-4 mr-2" />
                Tips:
              </h4>
              <ul className="text-sm text-sky-800 space-y-1">
                <li>• Paste URL dari SMS, email, atau media sosial untuk dicek</li>
                <li>• Analisis menggunakan VirusTotal (70+ antivirus engines)</li>
                <li>• Hasil berdasarkan database global threat intelligence</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Result Section */}
      {result && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <div className="bg-white rounded-xl shadow-md p-6 border-l-4 border-red-500">
            <div className="flex items-center justify-between mb-4">
              <VerdictBadge verdict={result.verdict} />
              <button
                onClick={handleReset}
                className="text-sky-600 hover:text-sky-700 font-medium flex items-center"
              >
                <Search className="h-4 w-4 mr-1" />
                Cek URL Lain
              </button>
            </div>
            <VerdictMessage verdict={result.verdict} />
          </div>

          {/* Risk Score */}
          <div className="bg-white rounded-xl shadow-md p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-4">
              Skor Risiko: {result.risk_score}/100
            </h3>
            <div className="w-full bg-gray-200 rounded-full h-4">
              <div
                className={`h-4 rounded-full transition-all ${
                  result.risk_score >= 70
                    ? 'bg-red-600'
                    : result.risk_score >= 40
                    ? 'bg-yellow-500'
                    : 'bg-green-500'
                }`}
                style={{ width: `${result.risk_score}%` }}
              />
            </div>
            <p className="text-sm text-gray-600 mt-2">
              {result.risk_score >= 70
                ? '⚠️ Risiko tinggi - URL ini berbahaya!'
                : result.risk_score >= 40
                ? '⚠️ Risiko sedang - Periksa dengan cermat'
                : '✅ Risiko rendah - URL tampak aman'}
            </p>
          </div>

          {/* URL Info */}
          <div className="bg-white rounded-xl shadow-md p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-4">
              Informasi URL
            </h3>
            <div className="space-y-3">
              <div className="flex items-start">
                <LinkIcon className="h-5 w-5 text-gray-400 mr-3 mt-1 flex-shrink-0" />
                <div>
                  <p className="text-sm text-gray-600">URL:</p>
                  <a
                    href={result.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-600 hover:underline break-all flex items-center"
                  >
                    {result.url}
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </a>
                </div>
              </div>
              <div className="flex items-center">
                <Shield className="h-5 w-5 text-gray-400 mr-3 flex-shrink-0" />
                <div>
                  <p className="text-sm text-gray-600">Provider:</p>
                  <p className="font-medium text-gray-900 capitalize">
                    {result.provider?.replace('_', ' ') || 'VirusTotal'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* VirusTotal Details */}
          {result.details && result.details.status !== 'no_urls' && (
            <div className="bg-white rounded-xl shadow-md p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">
                Analisis VirusTotal
              </h3>
              
              {/* Status Badge */}
              {result.details.threats?.[0] && (
                <div className={`inline-flex items-center px-4 py-2 rounded-full border-2 mb-4 ${getStatusColor(result.details.threats[0].status)}`}>
                  {result.details.threats[0].status === 'malicious' ? (
                    <AlertCircle className="h-5 w-5 mr-2" />
                  ) : (
                    <CheckCircle className="h-5 w-5 mr-2" />
                  )}
                  <span className="font-semibold uppercase">
                    {result.details.threats[0].status}
                  </span>
                </div>
              )}

              {/* Detection Stats */}
              {result.details.threats?.[0]?.malicious !== undefined && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="p-3 bg-red-50 rounded-lg border border-red-200 text-center">
                    <p className="text-2xl font-bold text-red-600">
                      {result.details.threats[0].malicious}
                    </p>
                    <p className="text-xs text-red-700">Malicious</p>
                  </div>
                  <div className="p-3 bg-yellow-50 rounded-lg border border-yellow-200 text-center">
                    <p className="text-2xl font-bold text-yellow-600">
                      {result.details.threats[0].suspicious}
                    </p>
                    <p className="text-xs text-yellow-700">Suspicious</p>
                  </div>
                  <div className="p-3 bg-green-50 rounded-lg border border-green-200 text-center">
                    <p className="text-2xl font-bold text-green-600">
                      {result.details.threats[0].harmless}
                    </p>
                    <p className="text-xs text-green-700">Harmless</p>
                  </div>
                  <div className="p-3 bg-gray-50 rounded-lg border border-gray-200 text-center">
                    <p className="text-2xl font-bold text-gray-600">
                      {result.details.threats[0].total_engines || 'N/A'}
                    </p>
                    <p className="text-xs text-gray-700">Total Engines</p>
                  </div>
                </div>
              )}

              {/* Reputation Score */}
              {result.details.threats?.[0]?.reputation !== undefined && (
                <div className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                  <p className="text-sm text-gray-600 mb-1">Reputation Score:</p>
                  <div className="flex items-center">
                    <div className={`text-lg font-bold ${
                      result.details.threats[0].reputation < 0 
                        ? 'text-red-600' 
                        : result.details.threats[0].reputation > 0 
                        ? 'text-green-600' 
                        : 'text-gray-600'
                    }`}>
                      {result.details.threats[0].reputation}
                    </div>
                    <span className="text-sm text-gray-500 ml-2">
                      (Semakin tinggi semakin terpercaya)
                    </span>
                  </div>
                </div>
              )}

              {/* Categories */}
              {result.details.threats?.[0]?.categories && Object.keys(result.details.threats[0].categories).length > 0 && (
                <div className="mt-4">
                  <p className="text-sm text-gray-600 mb-2">Kategori:</p>
                  <div className="flex flex-wrap gap-2">
                    {Object.values(result.details.threats[0].categories).map((cat, idx) => (
                      <span 
                        key={idx}
                        className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Unknown/Not Analyzed */}
          {result.details?.status === 'unknown' && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-6">
              <div className="flex items-start">
                <AlertCircle className="h-6 w-6 text-yellow-600 mr-3 mt-1 flex-shrink-0" />
                <div>
                  <h4 className="font-semibold text-yellow-900 mb-2">
                    URL Belum Dianalisis
                  </h4>
                  <p className="text-yellow-800">
                    URL ini belum pernah diperiksa oleh VirusTotal sebelumnya. 
                    Ini tidak berarti URL aman — selalu berhati-hati dengan link yang tidak dikenal.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-4">
            <a
              href={result.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 px-6 py-3 bg-gray-200 text-gray-700 font-semibold rounded-lg hover:bg-gray-300 transition-colors flex items-center justify-center"
            >
              <ExternalLink className="h-5 w-5 mr-2" />
              Buka URL (Hati-hati!)
            </a>
            <button
              onClick={handleReset}
              className="px-6 py-3 bg-sky-600 text-white font-semibold rounded-lg hover:bg-sky-700 transition-colors"
            >
              Cek URL Lain
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanURL;