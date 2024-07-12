import React from "react";

export default function Balance({ currentbalance }) {
  return (
    <div className="flex mt-3  gap-2">
      <h1 className="font-bold text-lg ">Your balance : </h1>
      <h1 className="font-bold text-lg">Rs.{currentbalance}</h1>
    </div>
  );
}
