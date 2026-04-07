import React from 'react';
import { AlertTriangle, CheckCircle, AlertCircle, ShieldAlert } from 'lucide-react';

const verdictConfig = {
  phishing: {
    color: 'red',
    bg: 'bg-red-100',
    text: 'text-red-800',
    border: 'border-red-500',
    icon: ShieldAlert,
    label: 'PHISHING DETECTED',
    message: '⚠️ Email ini berpotensi berbahaya. Jangan klik link atau download lampiran.'
  },
  suspicious: {
    color: 'yellow',
    bg: 'bg-yellow-100',
    text: 'text-yellow-800',
    border: 'border-yellow-500',
    icon: AlertTriangle,
    label: 'SUSPICIOUS',
    message: '⚠️ Email ini memiliki beberapa indikator mencurigakan. Periksa dengan cermat.'
  },
  safe: {
    color: 'green',
    bg: 'bg-green-100',
    text: 'text-green-800',
    border: 'border-green-500',
    icon: CheckCircle,
    label: 'SAFE',
    message: '✅ Analisis tidak menemukan ancaman yang jelas.'
  },
  malicious: {
    color: 'red',
    bg: 'bg-red-100',
    text: 'text-red-800',
    border: 'border-red-500',
    icon: ShieldAlert,
    label: 'MALICIOUS URL',
    message: '⚠️ URL ini terdeteksi berbahaya. Jangan diakses!'
  },
  unknown: {
    color: 'gray',
    bg: 'bg-gray-100',
    text: 'text-gray-800',
    border: 'border-gray-500',
    icon: AlertCircle,
    label: 'UNKNOWN',
    message: 'ℹ️ URL belum pernah dianalisis sebelumnya.'
  }
};

function VerdictBadge({ verdict, showLabel = true, showIcon = true }) {
  const config = verdictConfig[verdict?.toLowerCase()] || verdictConfig.unknown;
  const Icon = config.icon;
  
  return (
    <div className={`inline-flex items-center px-4 py-2 rounded-full border-2 ${config.bg} ${config.border}`}>
      {showIcon && <Icon className={`h-5 w-5 ${config.text} mr-2`} />}
      {showLabel && (
        <span className={`font-semibold ${config.text}`}>
          {config.label}
        </span>
      )}
    </div>
  );
}

export function VerdictMessage({ verdict }) {
  const config = verdictConfig[verdict?.toLowerCase()] || verdictConfig.unknown;
  
  return (
    <div className={`mt-4 p-4 rounded-lg ${config.bg} border ${config.border}`}>
      <p className={`${config.text} font-medium`}>{config.message}</p>
    </div>
  );
}

export default VerdictBadge;