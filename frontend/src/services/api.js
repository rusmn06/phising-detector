/**
 * Axios instance dengan interceptors untuk API communication.
 * Menangani error secara global dan menambahkan base URL.
 */

import axios from 'axios';

// Base URL ke backend API
const API_BASE_URL = 'http://localhost:8000/api/v1';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 detik timeout
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor - Ditambahkan sebelum request dikirim
api.interceptors.request.use(
  (config) => {
    // Bisa tambahkan auth token di sini jika perlu
    // const token = localStorage.getItem('token');
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`;
    // }
    console.log(`📡 Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('❌ Request Error:', error);
    return Promise.reject(error);
  }
);

// Response Interceptor - Ditangani setelah response diterima
api.interceptors.response.use(
  (response) => {
    console.log(`✅ Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    // Handle error secara global
    console.error('❌ Response Error:', error);
    
    if (error.response) {
      // Server merespons dengan error status (4xx, 5xx)
      const { status, data } = error.response;
      
      switch (status) {
        case 400:
          console.error('Bad Request:', data.detail);
          break;
        case 404:
          console.error('Not Found:', data.detail);
          break;
        case 413:
          console.error('File terlalu besar! Maksimal 10MB.');
          break;
        case 429:
          console.error('Rate limit exceeded. Tunggu sebentar.');
          break;
        case 500:
          console.error('Server error. Hubungi administrator.');
          break;
        default:
          console.error(`Error ${status}:`, data.detail);
      }
    } else if (error.request) {
      // Request dikirim tapi tidak ada response
      console.error('⚠️ Tidak ada response dari server. Periksa koneksi.');
    } else {
      // Error lain
      console.error('Error:', error.message);
    }
    
    return Promise.reject(error);
  }
);

// Export API methods untuk memudahkan penggunaan
export const scanEmail = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/scan', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};

export const scanURL = (url) => {
  return api.post('/scan-url', { url });
};

export const getDashboardStats = () => {
  return api.get('/dashboard/stats');
};

export const getHistory = (params = {}) => {
  return api.get('/history', { params });
};

export const deleteHistory = (id) => {
  return api.delete(`/history/${id}`);
};

export const getQuotaStatus = () => {
  return api.get('/quota-status');
};

export default api;