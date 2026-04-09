import React, { useState, useEffect } from 'react';
import { getDashboardStats, getHistory } from '../services/api';
import LoadingSpinner from './LoadingSpinner';
import { Mail, Shield, AlertTriangle, TrendingUp, Clock, Eye } from 'lucide-react';

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentActivity, setRecentActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      const [statsResponse, historyResponse] = await Promise.all([
        getDashboardStats(),
        getHistory({ page: 1, limit: 5 }) // Ambil 5 activity terbaru
      ]);
      
      setStats(statsResponse.data);
      setRecentActivity(historyResponse.data.items || []);
      setError(null);
    } catch (err) {
      console.error('Failed to load dashboard stats:', err);
      setError('Gagal memuat statistik dashboard');
    } finally {
      setLoading(false);
    }
  };

  const formatRelativeTime = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Baru saja';
    if (diffMins < 60) return `${diffMins} menit yang lalu`;
    if (diffHours < 24) return `${diffHours} jam yang lalu`;
    if (diffDays < 7) return `${diffDays} hari yang lalu`;
    return date.toLocaleDateString('id-ID');
  };

  if (loading) {
    return <LoadingSpinner text="Memuat dashboard..." />;
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
        <p className="text-red-600">{error}</p>
        <button
          onClick={loadStats}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
        >
          Coba Lagi
        </button>
      </div>
    );
  }

  // Card data untuk statistik
  const statCards = [
    {
      title: 'Total Scan',
      value: stats?.total_scans || 0,
      icon: Mail,
      color: 'blue',
      bg: 'bg-sky-100',
      text: 'text-sky-600',
    },
    {
      title: 'Safe Email',
      value: stats?.safe || 0,
      icon: Shield,
      color: 'green',
      bg: 'bg-green-100',
      text: 'text-green-600',
    },
    {
      title: 'Suspicious',
      value: stats?.suspicious || 0,
      icon: AlertTriangle,
      color: 'yellow',
      bg: 'bg-yellow-100',
      text: 'text-yellow-600',
    },
    {
      title: 'Phishing',
      value: stats?.phishing || 0,
      icon: Shield,
      color: 'red',
      bg: 'bg-red-100',
      text: 'text-red-600',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-2 text-gray-600">
          Overview aktivitas scanning email phishing
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.title}
              className="bg-gray-50 rounded-xl shadow-md p-6 border border-gray-200 hover:shadow-lg transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">
                    {card.title}
                  </p>
                  <p className="text-3xl font-bold text-gray-900 mt-2">
                    {card.value}
                  </p>
                </div>
                <div className={`${card.bg} p-4 rounded-full`}>
                  <Icon className={`h-6 w-6 ${card.text}`} />
                </div>
              </div>
              {/* Progress bar visual */}
              <div className="mt-4">
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={`bg-${card.color}-500 h-2 rounded-full transition-all`}
                    style={{
                      width: `${stats?.total_scans > 0 ? (card.value / stats.total_scans) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Activity Section */}
      <div className="bg-gray-50 rounded-xl shadow-md p-6 border border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-900">
            <TrendingUp className="inline h-5 w-5 mr-2" />
            Aktivitas Terbaru
          </h2>
          <p className="text-sm text-gray-500">
            Last 24h: {stats?.recent_24h || 0} scans
          </p>
        </div>

        {recentActivity.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Mail className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Belum ada aktivitas terbaru</p>
            <p className="text-sm mt-2">
              Upload email untuk memulai scanning
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-2 text-sm font-medium text-gray-600">File Name</th>
                  <th className="text-left py-2 text-sm font-medium text-gray-600">Status</th>
                  <th className="text-left py-2 text-sm font-medium text-gray-600">Time</th>
                  <th className="text-right py-2 text-sm font-medium text-gray-600">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {recentActivity.map((record) => (
                  <tr key={record.id} className="hover:bg-gray-50">
                    <td className="py-3 text-sm text-gray-900">{record.filename}</td>
                    <td className="py-3">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        record.verdict === 'phishing' ? 'bg-red-100 text-red-800' :
                        record.verdict === 'suspicious' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-green-100 text-green-800'
                      }`}>
                        {record.verdict}
                      </span>
                    </td>
                    <td className="py-3 text-sm text-gray-600">
                      <Clock className="inline h-3 w-3 mr-1" />
                      {formatRelativeTime(record.scanned_at)}
                    </td>
                    <td className="py-3 text-right">
                      <a
                        href="/history"
                        className="text-sky-600 hover:text-sky-800 text-sm font-medium flex items-center justify-end"
                      >
                        <Eye className="h-3 w-3 mr-1" />
                        View
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gradient-to-r from-emerald-500 to-emerald-600 rounded-xl shadow-md p-6 text-white">
          <h3 className="text-lg font-bold mb-2">Scan Email</h3>
          <p className="text-gray-100 mb-4">
            Upload file .eml untuk analisis phishing lengkap
          </p>
          <a
            href="/scan-email"
            className="inline-block bg-emerald-600 text-gray-100 px-4 py-2 rounded-lg font-semibold hover:bg-blue-50 transition-colors"
          >
            Mulai Scan →
          </a>
        </div>
        <div className="bg-gradient-to-r from-emerald-500 to-emerald-600 rounded-xl shadow-md p-6 text-white">
          <h3 className="text-lg font-bold mb-2">Scan URL</h3>
          <p className="text-gray-100 mb-4">
            Cek link mencurigakan tanpa upload email
          </p>
          <a
            href="/scan-url"
            className="inline-block bg-emerald-600 text-gray-100 px-4 py-2 rounded-lg font-semibold hover:bg-purple-50 transition-colors"
          >
            Cek URL →
          </a>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;