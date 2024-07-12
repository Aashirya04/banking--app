import React, { useEffect } from "react";
import Button from "./Button";
import { Navigate, useNavigate } from "react-router-dom";

export default function Appbar({ userid }) {
  const navigate = useNavigate();

  return (
    <div className="flex rounded-lg border border-slate-300 p-2 justify-between items-center">
      <h1 className="font-bold text-lg sm:text-2xl drop-shadow-2xl ">
        <span className="text-black ">Send</span>
        <span className="bg-blue-600 rounded-md px-1 py-.75 text-white ">Ease</span>
      </h1>
      <div className="flex justify-center items-center gap-2">
        <h1 className="font-bold text-sm">Hello</h1>
        <div
          className="rounded-full py-1 px-2 sm:py-3 sm:px-4 bg-blue-500 text-black text-sm flex justify-center items-center text-center cursor-pointer"
          onClick={() => {
            navigate("/profile");
          }}
        >
          {userid}
        </div>
        <button
          className="px-2 py-1 sm:px-3 sm:py-2 rounded-lg bg-green-500 text-center font-semibold  sm:text-sm"
          onClick={async () => {
            localStorage.removeItem("token");
            navigate("/signup");
          }}
        >
          Sign Out
        </button>
      </div>
    </div>
  );
}

