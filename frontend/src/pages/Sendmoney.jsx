import React, { useEffect, useState } from "react";
import Heading from "../components/Heading";
import Subheading from "../components/Subheading";
import Inputbox from "../components/Inputbox";
import Button from "../components/Button";
import { useNavigate, useSearchParams } from "react-router-dom";
import axios from "axios";
import { backendurl } from "../config";

const Sendmoney = () => {
  const [searchparams] = useSearchParams();
  const id = searchparams.get("id");
  const name = searchparams.get("name");
  const [amount, setamount] = useState();
  const [balance, setbalance] = useState();
  const navigate = useNavigate();

  useEffect(() => {
    const balancefunc = async () => {
      const res = await axios.get(`${backendurl}/account/balance`, {
        headers: {
          Authorization: "Bearer " + localStorage.getItem("token"),
        },
      });
      setbalance(res.data.accountbalance);
    };

    balancefunc();
  }, [balance]);

  return (
    <div className="relative h-screen w-full bg-white">
      <div className="absolute bottom-0 left-0 right-0 top-0 bg-[linear-gradient(to_right,#4f4f4f2e_1px,transparent_1px),linear-gradient(to_bottom,#4f4f4f2e_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_110%)]"></div>
      <div className="h-screen  relative z-99 justify-center flex bg-transparent items-center  ">
        <div className="flex justify-center items-center flex-col  w-max sm:min-w-[40rem]">
          <div className="rounded-lg bg-white/50 border border-slate-400 w-max sm:w-full  min-h-[20rem] px-4 p-2 text-center shadow-2xl">
            <Heading label={"Send Money "} />
            <div className="flex items-center gap-2 mt-2">
              <div
                className={`border rounded-full px-3 py-2 font-bold text-sm items-center bg-blue-100`}
              >
                {name[0].toUpperCase()}
              </div>
              <div className="flex justify-between items-center gap-3 font-semibold w-full ">
                <h1 className="">{name}</h1>
                {balance < 500 ? (
                  <h1 className="font-extrabold text-2xl">
                    <span className="text-red-700 font-bold ">
                      Low balance:{" "}
                    </span>
                    {balance}
                  </h1>
                ) : (
                  <h1 className="font-extrabold text-lg sm:text-2xl">
                    <span className="text-green-600 font-bold">
                      Your balance:{" "}
                    </span>
                    {balance}
                  </h1>
                )}
              </div>
            </div>
            <Inputbox
              label={"Amount (in Rs) "}
              placeholder={"Enter Amount"}
              type={"text"}
              onChange={(e) => setamount(e.target.value)}
            />
            <Button
              label={"Initiate Transfer"}
              onClick={async () => {
                await axios.post(
                  `${backendurl}/account/transfer`,
                  {
                    to: id,
                    amount: amount,
                  },
                  {
                    headers: {
                      Authorization: "Bearer " + localStorage.getItem("token"),
                    },
                  }
                );
                window.location.reload();
              }}
            />
            <div className="grid grid-cols-2 w-full mt-4 gap-4">
              <button
                className="font-bold border border-slate-500 bg-green-400 py-3 rounded-lg text-lg sm:text-2xl"
                onClick={() => {
                  navigate("/dashboard");
                }}
              >
                DashBoard
              </button>
              <button
                className="font-bold border border-slate-500 bg-green-400 py-3 rounded-lg  text-lg sm:text-2xl"
                onClick={() => {
                  navigate("/");
                }}
              >
                Home
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sendmoney;
