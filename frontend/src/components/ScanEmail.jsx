import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { scanEmail } from '../services/api';
import VerdictBadge, { VerdictMessage } from './VerdictBadge';
import LoadingSpinner from './LoadingSpinner';
import { Upload, FileText, AlertCircle, CheckCircle, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';

function ScanEmail() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showPreview, setShowPreview] = useState(false);

  // Dropzone configuration
  const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
    setError(null);
    setResult(null);
    
    // Handle rejected files
    if (rejectedFiles.length > 0) {
      const rejection = rejectedFiles[0];
      if (rejection.errors[0].code === 'file-too-large') {
        setError('File terlalu besar! Maksimal 10MB.');
      } else if (rejection.errors[0].code === 'file-invalid-type') {
        setError('Format file tidak valid! Hanya file .eml yang diperbolehkan.');
      } else {
        setError('File tidak valid.');
      }
      return;
    }
    
    // Handle accepted file
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'message/rfc822': ['.eml']
    },
    maxFiles: 1,
    maxSize: 10 * 1024 * 1024, // 10MB
  });

  // Handle scan
  const handleScan = async () => {
    if (!file) {
      setError('Pilih file .eml terlebih dahulu.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await scanEmail(file);
      setResult(response.data);
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.response?.data?.detail || 'Gagal melakukan scan. Coba lagi.');
    } finally {
      setLoading(false);
    }
  };

  // Reset form
  const handleReset = () => {
    setFile(null);
    setResult(null);
    setError(null);
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Scan Email</h1>
        <p className="mt-2 text-gray-600">
          Upload file .eml untuk analisis phishing lengkap
        </p>
      </div>

      {/* Upload Area */}
      {!result && (
        <div className="bg-white rounded-xl shadow-md p-8 border-2 border-dashed border-gray-300">
          <div
            {...getRootProps()}
            className={`text-center cursor-pointer transition-colors ${
              isDragActive ? 'bg-sky-50 border-sky-500' : 'hover:bg-gray-50'
            }`}
          >
            <input {...getInputProps()} />
            
            {isDragActive ? (
              <div className="py-12">
                <Upload className="h-16 w-16 mx-auto text-sky-600 mb-4" />
                <p className="text-lg font-semibold text-sky-600">
                  Lepaskan file di sini...
                </p>
              </div>
            ) : (
              <div className="py-12">
                <Upload className="h-16 w-16 mx-auto text-gray-400 mb-4" />
                <p className="text-lg font-semibold text-gray-700 mb-2">
                  Drop file .eml di sini, atau klik untuk memilih
                </p>
                <p className="text-sm text-gray-500 mb-4">
                  ✓ Format: .eml &nbsp;|&nbsp; ✓ Maksimal: 10 MB
                </p>
                <button className="px-6 py-2 bg-sky-600 text-white rounded-lg hover:bg-sky-700 transition-colors">
                  Pilih File
                </button>
              </div>
            )}
          </div>

          {/* Selected File */}
          {file && (
            <div className="mt-6 p-4 bg-sky-50 rounded-lg border border-sky-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <FileText className="h-6 w-6 text-sky-600 mr-3" />
                  <div>
                    <p className="font-semibold text-gray-900">{file.name}</p>
                    <p className="text-sm text-gray-600">
                      {(file.size / 1024).toFixed(2)} KB
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setFile(null)}
                  className="text-red-600 hover:text-red-700 text-sm font-medium"
                >
                  Hapus
                </button>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start">
              <AlertCircle className="h-5 w-5 text-red-600 mr-3 mt-0.5" />
              <p className="text-red-700">{error}</p>
            </div>
          )}

          {/* Action Buttons */}
          {file && (
            <div className="mt-6 flex gap-4">
              <button
                onClick={handleScan}
                disabled={loading}
                className="flex-1 px-6 py-3 bg-sky-600 text-white font-semibold rounded-lg hover:bg-sky-700 disabled:bg-sky-300 transition-colors"
              >
                {loading ? 'Scanning...' : 'Analyze Email'}
              </button>
              <button
                onClick={handleReset}
                className="px-6 py-3 bg-gray-200 text-gray-700 font-semibold rounded-lg hover:bg-gray-300 transition-colors"
              >
                Reset
              </button>
            </div>
          )}

          {/* Loading State */}
          {loading && (
            <div className="mt-6">
              <LoadingSpinner text="Menganalisis email... Ini mungkin memakan waktu beberapa detik." />
            </div>
          )}
        </div>
      )}

      {/* Tips Section */}
      <div className="bg-gray-100 border border-gray-200 rounded-xl p-6">
        <h3 className="font-semibold text-egray-950 mb-3 flex items-center">
          <AlertCircle className="h-5 w-5 mr-2" />
          Tips:
        </h3>
        <ul className="text-sm text-gray-950 space-y-2">
          <li>• File .eml bisa diekspor dari Outlook, Gmail, atau Thunderbird</li>
          <li>• Pastikan email lengkap dengan header untuk hasil analisis akurat</li>
          <li>• Ukuran maksimal file adalah 10 MB</li>
        </ul>
      </div>

      {/* Result Section */}
      {result && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <div className="bg-white rounded-xl shadow-md p-6 border-l-4 border-gray-500">
            <div className="flex items-center justify-between mb-4">
              <VerdictBadge verdict={result.verdict} />
              <button
                onClick={handleReset}
                className="text-sky-600 hover:text-sky-700 font-medium"
              >
                Scan Email Lain
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
                ? '⚠️ Risiko tinggi - Email ini sangat berbahaya!'
                : result.risk_score >= 40
                ? '⚠️ Risiko sedang - Periksa dengan cermat'
                : '✅ Risiko rendah - Email tampak aman'}
            </p>
          </div>

          {/* Email Information */}
          <div className="bg-white rounded-xl shadow-md p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-4">
              Informasi Email
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-600">Dari:</p>
                <p className="font-medium text-gray-900">{result.details.from_domain || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Domain:</p>
                <p className="font-medium text-gray-900">{result.from_domain || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Subjek:</p>
                <p className="font-medium text-gray-900">{result.email_subject || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">URL Ditemukan:</p>
                <p className="font-medium text-gray-900">{result.details.urls_found || 0}</p>
              </div>
            </div>
          </div>

          {/* Risk Factors */}
          {result.risk_factors && result.risk_factors.length > 0 && (
            <div className="bg-white rounded-xl shadow-md p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">
                Faktor Risiko
              </h3>
              <ul className="space-y-2">
                {result.risk_factors.map((factor, index) => (
                  <li key={index} className="flex items-start">
                    {factor.includes('berbahaya') ? (
                      <AlertCircle className="h-5 w-5 text-red-600 mr-3 mt-0.5 flex-shrink-0" />
                    ) : factor.includes('failed') ? (
                      <AlertCircle className="h-5 w-5 text-red-600 mr-3 mt-0.5 flex-shrink-0" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-yellow-600 mr-3 mt-0.5 flex-shrink-0" />
                    )}
                    <span className="text-gray-700">{factor}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* URLs Detected */}
          {result.details.url_analysis?.threats && result.details.url_analysis.threats.length > 0 && (
            <div className="bg-white rounded-xl shadow-md p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">
                URL Terdeteksi
              </h3>
              <ul className="space-y-2">
                {result.details.url_analysis.threats.map((threat, index) => (
                  <li key={index} className="flex items-center justify-between p-3 bg-red-50 rounded-lg border border-red-200">
                    <div className="flex items-center flex-1">
                      <AlertCircle className="h-5 w-5 text-red-600 mr-3 flex-shrink-0" />
                      <span className="text-sm text-red-800 break-all">{threat.url}</span>
                    </div>
                    <span className="text-xs font-semibold text-red-700 bg-red-200 px-2 py-1 rounded ml-2">
                      {threat.threat_type}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Preview Content */}
          {result.sanitized_body_preview && (
            <div className="bg-white rounded-xl shadow-md p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">
                Preview Konten
              </h3>
              <div 
                className={`border border-gray-200 rounded-lg p-4 bg-gray-50 transition-all duration-300 ${
                  showPreview ? 'max-h-none' : 'max-h-48'
                } overflow-y-auto`}
              >
                <div
                  className="prose max-w-none text-sm"
                  dangerouslySetInnerHTML={{ __html: result.sanitized_body_preview }}
                />
              </div>
              
              {result.sanitized_body_preview.length > 200 && (
                <button
                  onClick={() => setShowPreview(!showPreview)}
                  className="mt-3 text-sky-600 hover:text-sky-700 text-sm font-medium flex items-center transition-colors"
                >
                  {showPreview ? (
                    <>
                      <ChevronUp className="h-4 w-4 mr-1" /> Sembunyikan
                    </>
                  ) : (
                    <>
                      <ChevronDown className="h-4 w-4 mr-1" /> Tampilkan Lengkap
                    </>
                  )}
                </button>
              )}
            </div>
          )}

          {/* Authentication Details */}
          {result.details.authentication && (
            <div className="bg-white rounded-xl shadow-md p-6">
              <h3 className="text-lg font-bold text-gray-900 mb-4">
                Analisis Otentikasi
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 border rounded-lg">
                  <p className="text-sm text-gray-600 mb-1">SPF</p>
                  <div className="flex items-center">
                    {result.details.authentication.spf?.status === 'pass' ? (
                      <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
                    )}
                    <span className="font-medium capitalize">
                      {result.details.authentication.spf?.status || 'N/A'}
                    </span>
                  </div>
                </div>
                <div className="p-4 border rounded-lg">
                  <p className="text-sm text-gray-600 mb-1">DMARC</p>
                  <div className="flex items-center">
                    {result.details.authentication.dmarc?.status === 'pass' ? (
                      <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
                    )}
                    <span className="font-medium capitalize">
                      {result.details.authentication.dmarc?.status || 'N/A'}
                    </span>
                  </div>
                </div>
                <div className="p-4 border rounded-lg">
                  <p className="text-sm text-gray-600 mb-1">DKIM</p>
                  <div className="flex items-center">
                    {result.details.authentication.dkim?.status === 'not_checked' ? (
                      <AlertCircle className="h-5 w-5 text-yellow-600 mr-2" />
                    ) : (
                      <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                    )}
                    <span className="font-medium capitalize">
                      {result.details.authentication.dkim?.status || 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default ScanEmail;