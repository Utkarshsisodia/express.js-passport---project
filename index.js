import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";

const app = express();
const port = 3000;
const saltRound = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: "TOPSECRETEWORD",
    resave: false,
    saveUninitialized: true,
  })
);

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "12345",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) {
      res.send("email already exists. Try logging in.");
    } else {
      //Password Hashing
      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          const result = await db.query(
            "INSERT INTO users(email, password) VALUES ($1, $2)",
            [email, hash]
          );
          console.log(result);
          res.render("secrets.ejs");
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const storedHashedPassword = user.password;

      //Verifying Password
      bcrypt.compare(loginPassword, storedHashedPassword, (err, result) => {
        if (err) {
          console.log("Error comparing password", err);
        } else {
          if (result) {
            res.render("secrets.ejs");
          } else {
            res.send("please check your password");
          }
        }
      });
    } else {
      res.send("email does not exist. Please register.");
    }
  } catch (err) {
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port http://localhost:${port}`);
});
