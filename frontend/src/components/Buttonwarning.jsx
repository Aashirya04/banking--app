import React from "react";
import { Link } from "react-router-dom";

export default function ({ label, buttontext, to }) {
  return (
    <div className="flex justify-center text-sm p-2 gap-2">
      <h2>{label}</h2>
      <Link to={to} className="te hover:text-red-500">
        <u>{buttontext}</u>
      </Link>
    </div>
  );
}
