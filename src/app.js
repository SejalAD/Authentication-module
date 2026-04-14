import express from "express";
import morgan from "morgan";
import authRouter from "./routes/auth.routes.js";
import cookie from "cookie-parser";    //global middleware

const app = express();

app.use(express.json());
app.use(morgan("dev"));
app.use(cookie());



app.use("/api/auth", authRouter);

export default app;
