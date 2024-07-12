import React, { useState } from "react";
import Inputbox from "../components/Inputbox";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { backendurl } from "../config";
import toast, { Toaster } from "react-hot-toast";

export default function Profile() {
  const navigate = useNavigate();
  const [password, setpassword] = useState("");
  const [firstname, setfirstname] = useState("");
  const [lastname, setlastname] = useState("");

  return (
    <div className="relative h-screen w-full bg-white">
      <div className="absolute bottom-0 left-0 right-0 top-0 bg-[linear-gradient(to_right,#4f4f4f2e_1px,transparent_1px),linear-gradient(to_bottom,#4f4f4f2e_1px,transparent_1px)] bg-[size:14px_24px] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_110%)]"></div>
      <div className="h-screen relative w-full flex justify-center items-center bg-transparent">
        <div className="flex bg-white/50 justify-center flex-col rounded-lg border border-slate-400  p-3 w-80 shadow-2xl h-max">
          <h1 className="font-bold text-2xl text-center">Profile</h1>
          <div className="h-[1px] w-[60%] bg-black mt-2 self-center"></div>

          <Inputbox
            type={"text"}
            placeholder={"password"}
            onChange={(e) => setpassword(e.target.value)}
          />
          <Inputbox
            type={"text"}
            placeholder={"Firstname"}
            onChange={(e) => setfirstname(e.target.value)}
          />
          <Inputbox
            type={"text"}
            placeholder={"Lastname"}
            onChange={(e) => setlastname(e.target.value)}
          />
          <div className="flex justify-between mt-4">
            <button
              className="inline-flex h-12 animate-shimmer items-center justify-center rounded-md border text-white border-slate-800 bg-[linear-gradient(110deg,#000103,45%,#1e2631,55%,#000103)] bg-[length:200%_100%] px-3 font-medium text-xs transition-colors focus:outline-none focus:ring-2 focus:ring-slate-400 focus:ring-offset-2 focus:ring-offset-slate-50"
              onClick={() => {
                console.log("Back to Dashboard");
                navigate("/dashboard");
              }}
            >
              Back to Dashboard
            </button>
            <button
              className="inline-flex h-12 animate-shimmer items-center justify-center rounded-md border text-white border-slate-800 bg-[linear-gradient(110deg,#000103,45%,#1e2631,55%,#000103)] bg-[length:200%_100%] px-3 font-medium text-xs  transition-colors focus:outline-none focus:ring-2 focus:ring-slate-400 focus:ring-offset-2 focus:ring-offset-slate-50"
              onClick={async () => {
                try {
                  const res = await axios.put(
                    `${backendurl}/user/update`,
                    {
                      password: password,
                      firstname: firstname,
                      lastname: lastname,
                    },
                    {
                      headers: {
                        Authorization:
                          "Bearer " + localStorage.getItem("token"),
                      },
                    }
                  );
                  toast.success("Profile Updated");
                } catch (error) {
                  toast.error("Error Updating Profile");
                }
              }}
            >
              Save-Changes
            </button>
          </div>
        </div>
      </div>
      <Toaster
        position="top-right"
        reverseOrder={false}
        gutter={8}
        containerClassName=""
        containerStyle={{}}
        toastOptions={{
          // Define default options
          className: "",
          duration: 5000,
          style: {
            background: "#363636",
            color: "#fff",
          },

          // Default options for specific types
          success: {
            duration: 3000,
            theme: {
              primary: "green",
              secondary: "black",
            },
          },
        }}
      />
    </div>
  );
}
