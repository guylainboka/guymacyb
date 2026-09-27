import React from 'react';

interface ShadowScanLogoProps {
  className?: string;
  size?: number;
}

export const ShadowScanLogo: React.FC<ShadowScanLogoProps> = ({ className = '', size = 28 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`shrink-0 ${className}`}
    >
      <defs>
        <linearGradient id="shieldGrad" x1="50" y1="5" x2="50" y2="95" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#1e3a8a" />
          <stop offset="100%" stopColor="#0a0f1d" />
        </linearGradient>
        <linearGradient id="blueBorderGrad" x1="10" y1="10" x2="90" y2="90" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="50%" stopColor="#2563eb" />
          <stop offset="100%" stopColor="#1d4ed8" />
        </linearGradient>
        <linearGradient id="greenRadarGrad" x1="30" y1="30" x2="70" y2="70" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#10b981" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      {/* Rounded Outer Container Badge */}
      <rect x="2" y="2" width="96" height="96" rx="22" fill="#0b0f19" stroke="#1f293d" strokeWidth="2.5" />

      {/* Outer Blue Cyber Shield */}
      <path
        d="M50 14L78 26V48C78 66 66 81 50 87C34 81 22 66 22 48V26L50 14Z"
        fill="url(#shieldGrad)"
        stroke="url(#blueBorderGrad)"
        strokeWidth="4"
        strokeLinejoin="round"
        strokeLinecap="round"
        filter="url(#glow)"
      />

      {/* Inner Dark Hex Shield */}
      <path
        d="M50 24L70 33V47C70 60 61 72 50 77C39 72 30 60 30 47V33L50 24Z"
        fill="#070c18"
        stroke="#1d4ed8"
        strokeWidth="1.5"
        opacity="0.85"
      />

      {/* Green/Cyan Speedometer & Radar Gauge Arcs */}
      <path
        d="M36 49A16 16 0 0 1 64 43"
        stroke="url(#greenRadarGrad)"
        strokeWidth="3.5"
        strokeLinecap="round"
      />
      <path
        d="M44 62A16 16 0 0 0 64 54"
        stroke="url(#greenRadarGrad)"
        strokeWidth="3.5"
        strokeLinecap="round"
      />

      {/* Center Radar Core Circle */}
      <circle cx="50" cy="50" r="5.5" fill="#3b82f6" stroke="#93c5fd" strokeWidth="1.5" />

      {/* Dynamic Needle indicator pointing northeast */}
      <line
        x1="50"
        y1="50"
        x2="63"
        y2="38"
        stroke="#34d399"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  );
};
