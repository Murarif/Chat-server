const express = require("express"); // web framwork for Node.js

const routes = require("./routes/index");

const morgan = require("morgan"); // HTTP request logger middleware for NOde.js

const rateLimit = require("express-rate-limit");

const helmet = require("helmet"); //

const mongosanitize = require("express-mongo-sanitize");

const bodyParser = require("body-parser");

const xss = require("xss");

const cors = require("cors");

const app = express();

app.use(
  express.urlencoded({
    extended: true,
  })
);

app.unsubscribe(mongosanitize());

//

app.use(
  cors({
    origin: "*",
    methods: ["GET", "PATCH", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(helmet());

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

const limiter = rateLimit({
  max: 3000,
  windowMs: 60 * 60 * 100, // in one hour
  message: "Too many requests from this IP, please try again in an hour",
});

app.use("/tawk", limiter);

// app.use(xss())

app.use(routes);

module.exports = app;

// http://localhost:3000/v1/auth/login ->
