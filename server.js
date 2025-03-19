const express = require("express");
const app = express();

const cors = require("cors");

app.use(express.json());
app.use(cors());

const sqlite = require("sqlite");
const sqlite3 = require("sqlite3");

const { v4: uuidv4 } = require("uuid");
const { open } = sqlite;

const path = require("path");
const dbPath = path.join(__dirname, "expenseTracker.db");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { request } = require("http");

let db;

const initServerAndDb = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    app.listen(4001, () => {
      console.log("The server is running at port 4001");
    });
  } catch (err) {
    console.log(`Database ${err}`);
  }
};

initServerAndDb();

const authenticateToken = (request, response, next) => {
  let jwtToken;

  const authHeader = request.headers["authorization"];

  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }

  if (jwtToken === undefined) {
    return response.status(401).send({ message: "Invalid JWT token" });
  }

  jwt.verify(jwtToken, "MY_TOKEN", async (err, payload) => {
    if (err) {
      return response.status(401).send({ message: "Invalid JWT token" });
    }

    request.email = payload.email;
    next();
  });
};

const getUserId = async (email) => {
  const getUserQuery = `SELECT * FROM user WHERE email=?`;
  const dbUser = await db.get(getUserQuery, [email]);
  return dbUser ? dbUser.id : null;
};

const isValidTransaction = async (userId, transactionId) => {
  const getTransaction = `SELECT * FROM transactions WHERE id=? AND user_id=?`;

  try {
    const transaction = await db.get(getTransaction, [transactionId, userId]);
    return transaction ? true : false;
  } catch (error) {
    console.log(error);
    response.status(500).send({ message: "Internal Server Error" });
  }
};

app.post("/signup", async (request, response) => {
  const { name, email, password } = request.body;

  const selectQuery = `SELECT * FROM user WHERE email=?`;

  try {
    const dbUser = await db.get(selectQuery, [email]);

    if (dbUser) {
      return response.status(400).send({ message: "User ALready Exists" });
    }

    const hashedPwd = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    const createUserQuery = ` INSERT INTO user (id,name,email,password) VALUES (?,?,?,?)`;
    const dbResponse = await db.run(createUserQuery, [
      userId,
      name,
      email,
      hashedPwd,
    ]);

    response
      .status(201)
      .send({ message: "Successfull Created", lastId: dbResponse.lastID });
  } catch (err) {
    response.status(500).send({ message: "Internal Server Error" });
    console.log(err);
  }
});

app.post("/login/", async (request, response) => {
  const { email, password } = request.body;
  const selectQuery = `SELECT * FROM user WHERE email=?`;

  try {
    const dbUser = await db.get(selectQuery, [email]);
    if (!dbUser) {
      return response
        .status(400)
        .send({ message: "Invalid Email or Password" });
    }

    const isPwdMatch = await bcrypt.compare(password, dbUser.password);

    if (isPwdMatch) {
      const payload = {
        email,
      };

      const jwtToken = jwt.sign(payload, "MY_TOKEN");
      response.status(200).send({ jwt_token: jwtToken });
    } else {
      response.status(400).send({ message: "Invalid Email or Password" });
    }
  } catch (err) {
    response.status(500).send({ message: "Internal Server Error" });
    process.exit(1);
  }
});

app.post("/transactions", authenticateToken, async (request, response) => {
  const { email } = request;
  const { amount, type, category, description, date } = request.body;
  const userId = await getUserId(email);

  if (!userId) {
    return response.status(404).send({ message: "User not found" });
  }

  const transactionId = uuidv4();

  try {
    const insertTransactionQuery = `INSERT INTO transactions (id,user_id,amount,type,category,description,date) VALUES (?,?,?,?,?,?,?)`;

    const dbResponse = await db.run(insertTransactionQuery, [
      transactionId,
      userId,
      amount,
      type,
      category,
      description,
      date,
    ]);

    response.status(201).send({
      message: "Transaction Successfully Created",
      transactionId: dbResponse.lastID,
    });
  } catch (error) {
    response.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.get("/transactions", authenticateToken, async (request, response) => {
  const { email } = request;
  const userId = await getUserId(email);
  const { type, category, month, year, search, order } = request.query;

  if (!userId) {
    return response.status(401).send({ message: "Invalid User" });
  }

  let getAllTranctionQuery = `SELECT * FROM transactions WHERE user_id=?`;
  const values = [userId];

  if (type) {
    getAllTranctionQuery += ` AND type=?`;
    values.push(type);
  }

  if (category) {
    getAllTranctionQuery += ` AND category=?`;
    values.push(category);
  }

  if (month && year) {
    getAllTranctionQuery += ` AND strftime('%m',date)=? AND strftime('%Y',date)=?`;
    values.push(month.padStart(2, "0"), year);
  }

  if (year && !month) {
    getAllTranctionQuery += ` AND strftime('%Y',date)=?`;
    values.push(year);
  }

  if (search) {
    getAllTranctionQuery += ` AND description LIKE ?`;
    values.push(`%${search}%`);
  }

  if (
    order &&
    (order.toUpperCase() === "ASC" || order.toUpperCase() === "DESC")
  ) {
    getAllTranctionQuery += ` ORDER BY amount ${order.toUpperCase()}`;
  }

  try {
    const dbResponse = await db.all(getAllTranctionQuery, values);
    response.status(200).send(dbResponse);
  } catch (error) {
    console.error(error);
    response.status(500).send({ message: "Internal Server Error" });
  }
});

app.get("/transactions/:id", authenticateToken, async (request, response) => {
  const { email } = request;
  const { id } = request.params;

  const userId = await getUserId(email);

  if (!userId) {
    return response.status(401).send({ message: "Invalid User" });
  }

  const getAllTranctionQuery = `SELECT * FROM transactions WHERE id=? AND user_id=? `;

  try {
    const dbResponse = await db.all(getAllTranctionQuery, [id, userId]);
    response.status(200).send(dbResponse);
  } catch (error) {
    response.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.delete(
  "/transactions/:id",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    const { id } = request.params;

    const userId = await getUserId(email);

    const deleteTransactionQuery = `DELETE FROM transactions WHERE id=? AND user_id=?`;

    const validity = await isValidTransaction(userId, id);

    if (!validity) {
      return response
        .status(404)
        .send({ message: "Invalid User or Transaction" });
    }

    try {
      await db.run(deleteTransactionQuery, [id, userId]);
      response.status(200).send({ message: "Successfully Deleted" });
    } catch (error) {
      response.status(500).send({ message: "Internal Server Error" });
      console.log(error);
    }
  }
);

app.put("/transactions/:id", authenticateToken, async (request, response) => {
  const { email } = request;
  const { id } = request.params;
  const userId = await getUserId(email);
  const { amount, type, category, description, date } = request.body;

  const validity = await isValidTransaction(userId, id);
  if (!validity) {
    return response
      .status(400)
      .send({ message: "Invalid User or Transaction" });
  }

  const updates = [];
  const values = [];

  if (amount) {
    updates.push("amount=?");
    values.push(amount);
  }

  if (type) {
    updates.push("type=?");
    values.push(type);
  }

  if (category) {
    updates.push("category=?");
    values.push(category);
  }

  if (description) {
    updates.push("description=?");
    values.push(description);
  }

  if (date) {
    updates.push("date=?");
    values.push(date);
  }

  values.push(id, userId);

  const updateQuerry = `UPDATE transactions SET ${updates.join(
    ", "
  )} WHERE id=? AND user_id=?`;

  await db.run(updateQuerry, values);

  response.send({ message: "Successfully Updated" });
});

app.get("/summary", authenticateToken, async (request, response) => {
  const { email } = request;
  const userId = await getUserId(email);
  if (!userId) {
    return response.status(401).send({ message: "Invalid User" });
  }

  const summaryQuery = `SELECT 
    SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as total_income,
    SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as total_expense
    FROM transactions WHERE user_id=?`;

  try {
    const dbresponse = await db.get(summaryQuery, [userId]);

    const balance = dbresponse.total_income - dbresponse.total_expense;
    response.status(200).send({ ...dbresponse, balance });
  } catch (error) {
    response.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.get("/reports/monthly/", authenticateToken, async (request, response) => {
  const { email } = request;
  const userId = await getUserId(email);
  const { year } = request.query;

  if (!userId) {
    return response.status(401).send({ message: "Invalid User" });
  }

  const monthlyReportQuery = `
      SELECT 
          strftime('%m',date) AS month_number,
          CASE strftime('%m', date)
            WHEN '01' THEN 'January'
            WHEN '02' THEN 'February'
            WHEN '03' THEN 'March'
            WHEN '04' THEN 'April'
            WHEN '05' THEN 'May'
            WHEN '06' THEN 'June'
            WHEN '07' THEN 'July'
            WHEN '08' THEN 'August'
            WHEN '09' THEN 'September'
            WHEN '10' THEN 'October'
            WHEN '11' THEN 'November'
            WHEN '12' THEN 'December'
          END AS month_name,
          SUM(CASE WHEN type='income' THEN amount ELSE 0 END) AS total_income,
          SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS total_expense,
          SUM(CASE WHEN type='income' THEN amount ELSE -amount END) AS balance
      FROM transactions 
      WHERE user_id=? AND strftime('%Y',date)=?
      GROUP BY month_number 
      ORDER BY month_number`;

  try {
    const dbResponse = await db.all(monthlyReportQuery, [userId, year]);
    response.status(200).send(dbResponse);
  } catch (error) {
    response.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});

app.get("/reports/category/", authenticateToken, async (request, response) => {
  const { email } = request;
  const userId = await getUserId(email);
  const { month, year } = request.query;

  if (!userId) {
    return response.status(401).send({ message: "Invalid User" });
  }

  const categoryReport = `
    SELECT 
      category, type, SUM(amount) as total_amount
    FROM transactions 
    WHERE user_id=? AND strftime('%Y',date)=? AND strftime('%m',date)=?
    GROUP BY category`;

  try {
    const dbResponse = await db.all(categoryReport, [userId, year, month]);
    response.status(200).send(dbResponse);
  } catch (error) {
    response.status(500).send({ message: "Internal Server Error" });
  }
});

app.get("/reports/yearly", authenticateToken, async (request, response) => {
  const { email } = request;
  const userId = await getUserId(email);

  if (!userId) {
    return response.status(401).send({ message: "Invalid User" });
  }

  const yearlyQuerry = `
    SELECT 
        strftime('%Y', date) AS year,
        SUM(CASE WHEN type='income' THEN amount ELSE 0 END) AS total_income,
        SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS total_expense,
        SUM(CASE WHEN type='income' THEN amount ELSE -amount END) AS balance
      FROM transactions
      WHERE user_id=?
      GROUP BY year
      ORDER BY strftime('%Y', date) ASC

    `;

  try {
    const dbResponse = await db.all(yearlyQuerry, [userId]);
    response.status(200).send(dbResponse);
  } catch (error) {
    response.status(500).send({ message: "Internal Server Error" });
    console.log(error);
  }
});
