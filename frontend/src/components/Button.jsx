import React from "react";

export default function Button({ label, onClick }) {
  return (
    <div>
      <button
        className="w-full font-medium text-sm text-center py-4 text-white rounded-lg bg-[#010017] mt-4 hover:bg-[#020024] "
        onClick={onClick}
      >
        {label}
      </button>
    </div>
  );
}
