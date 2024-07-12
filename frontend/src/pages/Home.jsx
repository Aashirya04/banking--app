import React from "react";
import share from "../assets/moneytransfer.png";
import { useNavigate } from "react-router-dom";

export default function Home() {
  const token = localStorage.getItem("token");
  const navigate = useNavigate();

  return (
    <div className="relative h-screen w-full bg-white">
      <div className="absolute bottom-0 left-0 right-0 top-0 bg-[linear-gradient(to_right,#4f4f4f2e_1px,transparent_1px),linear-gradient(to_bottom,#4f4f4f2e_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_110%)]"></div>
      <div className="relative h-full w-full z-99 flex justify-center flex-col items-center">
        <nav className="rounded-xl w-max md:min-w-[40rem] h-max border px-3 py-1 bg-transparent mt-20 sm:mt-10 border-slate-400">
          <div className="flex justify-between gap-4 items-center">
            <h1 className="text-center text-4xl font-bold text-blue-500">
              Banking App
            </h1>
            <div className="flex gap-4 justify-center items-center">
              <button
                className="border bg-[#F7E7DC] border-black rounded-xl px-2 py-1 font-bold text-xl"
                onClick={() => {
                  if (token) {
                    navigate("/dashboard");
                  } else {
                    navigate("/signin");
                  }
                }}
              >
                Dashboard
              </button>
              <button
                className="border bg-[#F7E7DC]  border-black rounded-xl px-2 py-1 font-bold text-xl"
                onClick={() => {
                  if (token) {
                    localStorage.clear();
                    window.location.reload();
                  } else {
                    navigate("/signin");
                  }
                }}
              >
                {token ? "Logout" : "Sign In"}
              </button>
            </div>
          </div>
        </nav>
        <div className="w-full  h-full mt-4 sm:mt-10 lg:grid lg:grid-cols-2 flex flex-col">
          <div className="col-span-1 w-full h-full flex-col flex justify-center items-center">
            <h1 className="text-black text-5xl font-bold text-center">
              Welcome to Banking App
            </h1>

            <div className="flex justify-center mt-20  p-4 flex-col w-full gap-7">
              <h1 className="font-bold text-center text-2xl">
                Fast & Secure Money Transfers
              </h1>
              <p className="text-black font-medium text-lg">
                Experience the speed and security of our money transfer service.
                With a few clicks, you can send money to friends and family
                across the globe, knowing your transaction is protected by
                state-of-the-art security measures. Our platform is designed to
                be user-friendly, allowing you to complete transfers quickly and
                effortlessly. Join the millions of satisfied customers who trust
                us for their money transfer needs.
              </p>
            </div>
          </div>
          <div className="col-span-1  bg-transparent flex justify-center items-center">
            <img
              src={share}
              className="object-cover w-[400px] h-auto lg:w-[600px] lg:h-[600px]"
              alt=""
            />
          </div>
        </div>
      </div>
    </div>
  );
}
