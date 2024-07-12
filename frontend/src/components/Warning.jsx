import React from "react";
import Heading from "./Heading";
import { useNavigate } from "react-router-dom";

export default function Warning() {
  const navigate = useNavigate();
  return (
    <div className="bg-[#e1eacd] h-screen w-full flex justify-center items-center">
      <div className="flex bg-white justify-center flex-col rounded-lg self-center items-center p-4 w-80 h-40">
        <h1 className="text-xl font-bold mb-8 text-red-500">
          You're Timed Out
        </h1>
        <div className="flex justify-evenly w-full">
          <button
            className="px-3 py-2 rounded-lg text-sm font-semibold bg-yellow-400"
            onClick={() => {
              navigate("/signup");
            }}
          >
            Signup
          </button>
          <button
            className="px-3 py-2 rounded-lg text-sm font-semibold bg-yellow-400"
            onClick={() => {
              navigate("/signin");
            }}
          >
            Signin
          </button>
        </div>
      </div>
    </div>
  );
}
