import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import axios from "axios";
import { useEffect } from "react";
import Signup from "./pages/Signup";
import Signin from "./pages/Signin";
import Dashboard from "./pages/Dashboard";
import Sendmoney from "./pages/Sendmoney";
import Profile from "./pages/Profile";
import Home from "./pages/Home";

function App() {
  const authenticated = localStorage.getItem("token");

  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/signup" element={<Signup />} />
          <Route path="/signin" element={<Signin />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/send" element={<Sendmoney />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/" element={<Home />} />

          <Route
            path="/"
            element={
              authenticated ? (
                <Navigate to={"/dashboard"} />
              ) : (
                <Navigate to={"/signin"} />
              )
            }
          />
        </Routes>
      </BrowserRouter>
    </>
  );
}

export default App;
