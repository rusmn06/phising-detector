import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, Mail, Link as LinkIcon, History, LayoutDashboard } from 'lucide-react';

function Layout() {
  const location = useLocation();
  
  // Helper untuk menentukan active state
  const isActive = (path) => {
    return location.pathname === path 
      ? 'bg-sky-600 text-gray-100 border-sky-300'
      : 'text-gray-950 hover:bg-gray-100 border-transparent';
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Top Navbar */}
      <nav className="bg-emerald-600 shadow-md border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            {/* Logo & Title */}
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-gray-950" />
              <span className="ml-3 text-xl font-bold text-gray-950">
                Email Phishing Scanner
              </span>
            </div>
            
            {/* Navigation Links */}
            <div className="flex items-center space-x-2">
              <Link
                to="/"
                className={`flex items-center px-4 py-2 rounded-lg border-b-2 transition-colors ${isActive('/')}`}
              >
                <LayoutDashboard className="h-5 w-5 mr-2" />
                Dashboard
              </Link>
              <Link
                to="/scan-email"
                className={`flex items-center px-4 py-2 rounded-lg border-b-2 transition-colors ${isActive('/scan-email')}`}
              >
                <Mail className="h-5 w-5 mr-2" />
                Scan Email
              </Link>
              <Link
                to="/scan-url"
                className={`flex items-center px-4 py-2 rounded-lg border-b-2 transition-colors ${isActive('/scan-url')}`}
              >
                <LinkIcon className="h-5 w-5 mr-2" />
                Scan URL
              </Link>
              <Link
                to="/history"
                className={`flex items-center px-4 py-2 rounded-lg border-b-2 transition-colors ${isActive('/history')}`}
              >
                <History className="h-5 w-5 mr-2" />
                History
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-emerald-600 border-t mt-auto flex-shrink-0">
        <div className="max-w-7xl mx-auto px-4 py-4 text-center text-gray-950 text-sm">
          © 2026 Email Phishing Scanner - Internal Security Tool
        </div>
      </footer>
    </div>
  );
}

export default Layout;