import React from "react";

export default function Inputbox({ label, placeholder, type, onChange }) {
  return (
    <div className="flex flex-col pt-2">
      <h2 className="font-medium text-sm text-left py-2">{label}</h2>
      {/* so whenever this input change this will call this onChange props */}
      <input
        type={type}
        onChange={onChange}
        placeholder={placeholder}
        className="border border-slate-400 outline-none rounded-lg text-slate-600 w-full px-2 py-1"
      />
    </div>
  );
}
