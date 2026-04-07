import React, { useState, useEffect } from 'react';
import { getDashboardStats } from '../services/api';
import LoadingSpinner from './LoadingSpinner';
import { Mail, Shield, AlertTriangle, TrendingUp } from 'lucide-react';

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      const response = await getDashboardStats();
      setStats(response.data);
      setError(null);
    } catch (err) {
      console.error('Failed to load dashboard stats:', err);
      setError('Gagal memuat statistik dashboard');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <LoadingSpinner text="Memuat statistik..." />;
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
      bg: 'bg-blue-100',
      text: 'text-blue-600',
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
              className="bg-white rounded-xl shadow-md p-6 border border-gray-200 hover:shadow-lg transition-shadow"
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
      <div className="bg-white rounded-xl shadow-md p-6 border border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-gray-900">
            <TrendingUp className="inline h-5 w-5 mr-2" />
            Aktivitas Terbaru
          </h2>
          <p className="text-sm text-gray-500">
            Last 24h: {stats?.recent_24h || 0} scans
          </p>
        </div>
        <div className="text-center py-8 text-gray-500">
          <Mail className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Belum ada aktivitas terbaru</p>
          <p className="text-sm mt-2">
            Upload email untuk memulai scanning
          </p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gradient-to-r from-blue-500 to-blue-600 rounded-xl shadow-md p-6 text-white">
          <h3 className="text-lg font-bold mb-2">Scan Email</h3>
          <p className="text-blue-100 mb-4">
            Upload file .eml untuk analisis phishing lengkap
          </p>
          <a
            href="/scan-email"
            className="inline-block bg-white text-blue-600 px-4 py-2 rounded-lg font-semibold hover:bg-blue-50 transition-colors"
          >
            Mulai Scan →
          </a>
        </div>
        <div className="bg-gradient-to-r from-purple-500 to-purple-600 rounded-xl shadow-md p-6 text-white">
          <h3 className="text-lg font-bold mb-2">Scan URL</h3>
          <p className="text-purple-100 mb-4">
            Cek link mencurigakan tanpa upload email
          </p>
          <a
            href="/scan-url"
            className="inline-block bg-white text-purple-600 px-4 py-2 rounded-lg font-semibold hover:bg-purple-50 transition-colors"
          >
            Cek URL →
          </a>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;