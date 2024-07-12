import React, { useEffect, useState } from "react";
import Appbar from "../components/Appbar";
import Balance from "../components/Balance";
import Users from "../components/Users";
import axios from "axios";
import Warning from "../components/Warning";
import { backendurl } from "../config";

const Dashboard = () => {
  const token = localStorage.getItem("token");
  const [balance, setbalance] = useState();
  useEffect(() => {
    const balancefunc = async () => {
      try {
        let res = await axios.get(`${backendurl}/account/balance`, {
          headers: {
            Authorization: "Bearer " + localStorage.getItem("token"),
          },
        });
        setbalance(res.data.accountbalance);
      } catch (error) {
        console.log(error);
      }
    };

    balancefunc();
  }, [balance]);
  console.log(balance);
  return (
    <>
      {token ? (
        <div className="relative h-screen w-full bg-white">
          <div className="absolute bottom-0 left-0 right-0 top-0 bg-[linear-gradient(to_right,#4f4f4f2e_1px,transparent_1px),linear-gradient(to_bottom,#4f4f4f2e_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_110%)]"></div>
          <div className="h-screen relative flex justify-center bg-transparent">
            <div className="flex flex-col p-4 w-full bg-transparent">
              <div className="p-4 bg-white/20">
                <div className="bg-black w-full h-1 mb-3 rounded-lg "></div>
                <Appbar userid={"U"} />
                <Balance currentbalance={balance} />
                <Users />
              </div>
            </div>
          </div>
        </div>
      ) : (
        <Warning label={"Not logged In"} onClick={"/signin"} />
      )}
    </>
  );
};

export default Dashboard;
