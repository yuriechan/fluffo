const dotenv = require("dotenv");
dotenv.config();

const bodyParser = require("body-parser");
const urlencodedParser = bodyParser.urlencoded({ extended: false });
//const router = require('./routes')
const express = require("express");
const mysql = require("mysql");

// Create connection
const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  insecureAuth: true,
});

// Connect
db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log("MySql connected...");
});

const app = express();
const port = process.env.PORT || 5000;
const server = app.listen(port);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ limit: "5mb", extended: true }));
//app.use('/', router)

app.get("/", (req, res, next) => {
  res.send("Hello World");
});

app.post("/signup", urlencodedParser, (req, res, next) => {
  const signupParam = {
    firstName: "first_name",
    lastName: "last_name",
    email: "email",
    password: "password",
  };
  const reqKeys = Object.keys(req.body);
  const reqValues = Object.values(req.body);
  if (
    reqKeys[0] !== signupParam.firstName ||
    reqKeys[1] !== signupParam.lastName ||
    reqKeys[2] != signupParam.email ||
    reqKeys[3] != signupParam.password 
  ) {
    return res.status(400).send({ status: 400, message: "'firstname, 'lastname', 'email', and 'password' keys must be set.'" });
  }
  for (let value of reqValues) {
    if (value.length <= 0) {
      return res.status(400).send({ status: 400, message: "'firstname, 'lastname', 'email', and 'password' values must be set.'" });
    }
  }

  const { first_name, last_name, email, password } = req.body;
  const newUser = {
    first_name: first_name,
    last_name: last_name,
    email: email,
    password: password,
  };
  const sql = "INSERT INTO users SET ?";
  db.query(sql, newUser, (err, result) => {
    if (err) throw err;
    console.log(result);
    return res.send(`User account added`);
  });
});

// app.use((err, req, res, next) => {
//     logger.error(err.stack)
//     setTimeout(() => {
//         if (!res.headersSent) {
//             res.status(500).send('Something broke!')
//         }
//     }, 100)
// })

console.log(`Server started on port ${port}`);

module.exports = server;