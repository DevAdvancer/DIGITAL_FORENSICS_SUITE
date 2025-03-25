import React from 'react';
import { Terminal } from 'lucide-react';
import Documentation from './Documentation';

const Footer = () => {
  return (
    <footer className="cyber-border bg-gray-900/50 mt-8 py-6">
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-red-500" />
            <span className="text-green-500">BYTE_FORENSICS</span>
          </div>

          {/* Documentation Button */}
          <Documentation />

          <div className="flex items-center gap-4 text-gray-500">
            <span className="text-sm">STATUS: <span className="text-green-500">ONLINE</span></span>
            <span className="text-sm">VERSION: <span className="text-red-500">3.1.0</span></span>
          </div>

          <div className="text-sm text-gray-600">
            <span className="text-green-500">[</span> ADVANCED DIGITAL INVESTIGATION SUITE <span className="text-green-500">]</span>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
