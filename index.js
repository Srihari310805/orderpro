// index.js (CSV-only, corrected)
import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import fs from "fs";
import dotenv from "dotenv";
import pkg from "pg";
import { Parser } from "json2csv";
import csvParser from "csv-parser";

dotenv.config();
const { Pool } = pkg;

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 3000;

// ------------------ Middleware ------------------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "superSecretKey",
    resave: false,
    saveUninitialized: false,
    // do not set cookie.maxAge here statically; change per-session on login if needed
  })
);

// ------------------ EJS Setup ------------------
app.set("view engine", "ejs");
app.set("views", join(__dirname, "views"));

// ------------------ PostgreSQL Setup -----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // optional SSL config if needed:
  // ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false
});

pool
  .connect()
  .then((client) => {
    client.release();
    console.log("✅ Database connected!");
  })
  .catch((err) => {
    console.error("❌ DB connection failed:", err?.message ?? err);
  });

// ------------------ Upload Folder ------------------
const uploadDir = join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// ------------------ Auth Middleware ------------------
function checkAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

// ------------------ UTIL ------------------
function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function computeDiscountAmount(discountPercent, qty, netrate) {
  const base = safeNumber(qty, 0) * safeNumber(netrate, 0);
  const disc = safeNumber(discountPercent, 0) / 100;
  const amount = base * disc;
  // ensure two decimals, return number
  return Number.isFinite(amount) ? +amount.toFixed(2) : 0;
}

// ------------------ ROUTES ------------------

// Login page
app.get("/", (req, res) =>
  res.render("pages/index", { title: "Login", error: null })
);

// Login handler
app.post("/check", async (req, res) => {
  const { companyname = "", username = "", password = "", remember } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(company_name)=LOWER($1) AND username=$2",
      [companyname.trim(), username.trim()]
    );

    if (!result.rows.length)
      return res.render("pages/index", { title: "Login", error: "Invalid credentials." });

    const user = result.rows[0];

    if ((password || "").trim() !== (user.password || "").trim())
      return res.render("pages/index", { title: "Login", error: "Incorrect password." });

    req.session.user = {
      username: user.username,
      company_name: user.company_name,
      is_admin: user.is_admin,
    };

    // Set session cookie expiry only if 'remember' is on; otherwise default session cookie
    if (remember === "on") {
      req.session.cookie.maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    } else {
      // ensure browser-session cookie (no maxAge)
      delete req.session.cookie.maxAge;
    }

    res.redirect(user.is_admin ? "/admin-login" : "/user-login");
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).send("Server error");
  }
});

// Upload page
app.get("/upload", checkAuth, (req, res) => {
  if (!req.session.user.is_admin) return res.redirect("/user-login");
  res.render("pages/upload");
});

// Admin dashboard
app.get("/admin-login", checkAuth, (req, res) => {
  if (!req.session.user.is_admin) return res.redirect("/user-login");
  res.render("pages/admin-login", { title: "Admin Panel" });
});

// User dashboard
app.get("/user-login", checkAuth, (req, res) => {
  const user = req.session.user;
  res.render("pages/user-login", {
    username: user.username,
    company_name: user.company_name,
  });
});

// Order entry (show edit if edit query present)
app.get("/order-entry", checkAuth, async (req, res) => {
  const editId = req.query.edit ?? null;

  if (editId) {
    let client;
    try {
      client = await pool.connect();
      const orderRes = await client.query(
        "SELECT id, route, party_name, item_group, created_by FROM orders WHERE id=$1",
        [editId]
      );

      if (!orderRes.rows.length) return res.redirect("/order-entry");

      const itemsRes = await client.query(
        `SELECT id, item_id, item_name, item_group, qty, uom, netrate, 
                discount_percent, discount_amount, batch, gst_percent, mrp
         FROM order_items 
         WHERE order_id=$1 ORDER BY id ASC`,
        [editId]
      );

      const order = { ...orderRes.rows[0], items: itemsRes.rows };

      return res.render("pages/order-entry", {
        title: `Edit Order #${editId}`,
        editMode: true,
        order,
      });
    } catch (err) {
      console.error("❌ Load edit error:", err);
      return res.status(500).send("Server error");
    } finally {
      if (client) client.release();
    }
  }

  res.render("pages/order-entry", { title: "Order Entry", editMode: false, order: null });
});

// Order details page
app.get("/order-details", checkAuth, (req, res) => res.render("pages/order-details"));

// ------------------ API ROUTES ------------------
app.get("/api/routes", async (req, res) => {
  try {
    const result = await pool.query("SELECT DISTINCT route FROM party_routes ORDER BY route ASC");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/routes error:", err);
    res.status(500).json({ error: "Failed to fetch routes." });
  }
});

app.get("/api/parties/:route", async (req, res) => {
  try {
    const { route } = req.params;
    const result = await pool.query(
      "SELECT party_name FROM party_routes WHERE route=$1 ORDER BY party_name ASC",
      [route]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/parties error:", err);
    res.status(500).json({ error: "Failed to fetch parties." });
  }
});

// Fetch item groups
app.get("/api/item-groups", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT item_group 
      FROM items 
      WHERE item_group IS NOT NULL AND item_group <> '' 
      ORDER BY item_group ASC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/item-groups error:", err);
    res.status(500).json({ error: "Failed to fetch item groups." });
  }
});

// Item search
app.get("/api/items", async (req, res) => {
  const searchRaw = req.query.search ?? "";
  const itemGroup = req.query.itemGroup ?? "";
  const search = `%${searchRaw.toLowerCase()}%`;

  try {
    let query = `
      SELECT id, name, quantity, uom, netrate, mrp, gst_percent
      FROM items
      WHERE LOWER(name) LIKE $1
    `;
    const params = [search];

    if (itemGroup) {
      query += " AND LOWER(item_group)=LOWER($2)";
      params.push(itemGroup);
    }

    query += " ORDER BY name ASC LIMIT 100;";
    const result = await pool.query(query, params);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/items error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Fetch item details
app.get("/api/items/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, quantity, uom, netrate, mrp, gst_percent FROM items WHERE id=$1",
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: "Item not found" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ /api/items/:id error:", err);
    res.status(500).json({ error: "Failed to fetch item" });
  }
});

// ------------------ ORDERS ------------------
/**
 * Save new order
 * Expected req.body: { route, partyname, itemgroup, items: [ { id, itemname, qty, netrate, discount_percent, ... } ] }
 */
app.post("/api/save-order", checkAuth, async (req, res) => {
  const { route, partyname, itemgroup, items } = req.body;

  if (!route || !partyname || !items?.length)
    return res.status(400).json({ success: false, message: "Invalid data" });

  const createdBy = req.session.user.username;

  let client;
  try {
    client = await pool.connect();
    await client.query("BEGIN");

    const orderRes = await client.query(
      `INSERT INTO orders (route, party_name, item_group, created_at, created_by)
       VALUES ($1,$2,$3,NOW(),$4)
       RETURNING id`,
      [route, partyname, itemgroup, createdBy]
    );

    const orderId = orderRes.rows[0].id;

    for (const it of items) {
      let itemId = it.id || null;

      if (!itemId && it.itemname) {
        const r = await client.query(
          "SELECT id FROM items WHERE LOWER(name)=LOWER($1) LIMIT 1",
          [it.itemname]
        );
        if (r.rows.length) itemId = r.rows[0].id;
      }

      const qty = safeNumber(it.qty, 0);
      const discountPercent = safeNumber(it.discount_percent ?? it.disc, 0);
      const netrate = safeNumber(it.netrate, 0);
      const discountAmount = computeDiscountAmount(discountPercent, qty, netrate);

      await client.query(
        `INSERT INTO order_items
          (order_id, item_id, item_name, item_group, qty, uom, netrate,
           discount_percent, discount_amount, batch, gst_percent, mrp)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          orderId,
          itemId,
          it.itemname || it.name || null,
          itemgroup,
          qty,
          it.uom ?? null,
          netrate,
          discountPercent,
          discountAmount,
          it.batch ?? null,
          safeNumber(it.gst_percent ?? it.gst, 0),
          safeNumber(it.mrp, 0),
        ]
      );

      // Update stock safely
      if (itemId) {
        await client.query("UPDATE items SET quantity=quantity-$1 WHERE id=$2", [qty, itemId]);
      } else if (it.itemname) {
        await client.query("UPDATE items SET quantity=quantity-$1 WHERE LOWER(name)=LOWER($2)", [
          qty,
          it.itemname,
        ]);
      }
    }

    await client.query("COMMIT");
    res.json({ success: true, orderId });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("❌ /api/save-order error:", err);
    res.status(500).json({ success: false, message: err.message || "Server error" });
  } finally {
    if (client) client.release();
  }
});

// Update order
app.put("/api/update-order/:id", checkAuth, async (req, res) => {
  const orderId = req.params.id;
  const { route, partyname, itemgroup, items } = req.body;

  if (!route || !partyname || !items?.length)
    return res.status(400).json({ success: false, message: "Invalid update data." });

  let client;
  try {
    client = await pool.connect();
    await client.query("BEGIN");

    const owner = await client.query("SELECT created_by FROM orders WHERE id=$1", [orderId]);

    if (!owner.rows.length) throw new Error("Order not found");

    if (!req.session.user.is_admin && owner.rows[0].created_by !== req.session.user.username)
      throw new Error("Unauthorized");

    // Restore stock for old items
    const oldItems = await client.query(
      "SELECT item_id, item_name, qty FROM order_items WHERE order_id=$1",
      [orderId]
    );

    for (const old of oldItems.rows) {
      if (old.item_id) {
        await client.query("UPDATE items SET quantity=quantity+$1 WHERE id=$2", [
          old.qty,
          old.item_id,
        ]);
      } else {
        await client.query("UPDATE items SET quantity=quantity+$1 WHERE LOWER(name)=LOWER($2)", [
          old.qty,
          old.item_name,
        ]);
      }
    }

    await client.query(
      `UPDATE orders 
       SET route=$1, party_name=$2, item_group=$3, updated_at=NOW() 
       WHERE id=$4`,
      [route, partyname, itemgroup, orderId]
    );

    await client.query("DELETE FROM order_items WHERE order_id=$1", [orderId]);

    for (const it of items) {
      let itemId = it.id || null;

      if (!itemId && it.itemname) {
        const r = await client.query(
          "SELECT id FROM items WHERE LOWER(name)=LOWER($1) LIMIT 1",
          [it.itemname]
        );
        if (r.rows.length) itemId = r.rows[0].id;
      }

      const qty = safeNumber(it.qty, 0);

      let avail = 0;
      if (itemId) {
        const s = await client.query("SELECT quantity FROM items WHERE id=$1", [itemId]);
        avail = s.rows[0]?.quantity ?? 0;
      } else {
        const s = await client.query("SELECT quantity FROM items WHERE LOWER(name)=LOWER($1)", [
          it.itemname,
        ]);
        avail = s.rows[0]?.quantity ?? 0;
      }

      if (avail < qty) throw new Error(`Not enough stock for ${it.itemname || it.name || "item"}`);

      const discPercent = safeNumber(it.discount_percent ?? it.disc, 0);
      const netrate = safeNumber(it.netrate, 0);
      const discAmount = computeDiscountAmount(discPercent, qty, netrate);

      await client.query(
        `INSERT INTO order_items 
         (order_id, item_id, item_name, item_group, qty, uom, 
          netrate, discount_percent, discount_amount, batch, gst_percent, mrp)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          orderId,
          itemId,
          it.itemname || it.name || null,
          itemgroup,
          qty,
          it.uom ?? null,
          netrate,
          discPercent,
          discAmount,
          it.batch ?? null,
          safeNumber(it.gst_percent ?? it.gst, 0),
          safeNumber(it.mrp, 0),
        ]
      );

      if (itemId) {
        await client.query("UPDATE items SET quantity=quantity-$1 WHERE id=$2", [qty, itemId]);
      } else if (it.itemname) {
        await client.query("UPDATE items SET quantity=quantity-$1 WHERE LOWER(name)=LOWER($2)", [
          qty,
          it.itemname,
        ]);
      }
    }

    await client.query("COMMIT");
    res.json({ success: true, message: `Order #${orderId} updated.` });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("❌ /api/update-order error:", err);
    res.status(400).json({ success: false, message: err.message || "Failed to update order." });
  } finally {
    if (client) client.release();
  }
});

// ---------------- DELETE ORDER ----------------
app.delete("/api/orders/:id", checkAuth, async (req, res) => {
  const orderId = req.params.id;

  let client;
  try {
    client = await pool.connect();
    await client.query("BEGIN");

    const owner = await client.query("SELECT created_by FROM orders WHERE id=$1", [orderId]);

    if (!owner.rows.length) throw new Error("Order not found");

    if (!req.session.user.is_admin && owner.rows[0].created_by !== req.session.user.username)
      throw new Error("Unauthorized");

    const oldItems = await client.query(
      "SELECT item_id, item_name, qty FROM order_items WHERE order_id=$1",
      [orderId]
    );

    for (const old of oldItems.rows) {
      if (old.item_id) {
        await client.query("UPDATE items SET quantity=quantity+$1 WHERE id=$2", [
          old.qty,
          old.item_id,
        ]);
      } else {
        await client.query("UPDATE items SET quantity=quantity+$1 WHERE LOWER(name)=LOWER($2)", [
          old.qty,
          old.item_name,
        ]);
      }
    }

    await client.query("DELETE FROM order_items WHERE order_id=$1", [orderId]);
    await client.query("DELETE FROM orders WHERE id=$1", [orderId]);

    await client.query("COMMIT");
    res.json({ success: true, message: `Order #${orderId} deleted.` });
  } catch (err) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("❌ /api/orders DELETE error:", err);
    res.status(400).json({ success: false, message: err.message || "Failed to delete order." });
  } finally {
    if (client) client.release();
  }
});

// ---------------- FETCH ORDERS (ADMIN & USER) ----------------
app.get("/api/orders", checkAuth, async (req, res) => {
  try {
    let result;
    if (req.session.user.is_admin) {
      result = await pool.query(`
        SELECT 
          o.id AS order_id, o.route, o.party_name, o.item_group, 
          o.created_at, o.created_by,
          oi.id AS order_item_id, oi.item_id, oi.item_name, oi.qty, 
          oi.uom, oi.netrate, oi.discount_percent, oi.discount_amount, 
          oi.batch, oi.gst_percent, oi.mrp
        FROM orders o
        JOIN order_items oi ON o.id = oi.order_id
        ORDER BY o.created_at DESC, oi.id ASC
      `);
    } else {
      result = await pool.query(
        `
        SELECT 
          o.id AS order_id, o.route, o.party_name, o.item_group,
          o.created_at, o.created_by,
          oi.id AS order_item_id, oi.item_id, oi.item_name, oi.qty,
          oi.uom, oi.netrate, oi.discount_percent, oi.discount_amount,
          oi.batch, oi.gst_percent, oi.mrp
        FROM orders o
        JOIN order_items oi ON o.id = oi.order_id
        WHERE o.created_by = $1
        ORDER BY o.created_at DESC, oi.id ASC
      `,
        [req.session.user.username]
      );
    }

    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/orders GET error:", err);
    res.status(500).json({ message: "Failed to fetch orders." });
  }
});

// ---------------- DOWNLOAD SINGLE ORDER (CSV ONLY) ----------------
app.get("/api/orders/download/:id", checkAuth, async (req, res) => {
  const orderId = req.params.id;

  let client;
  try {
    client = await pool.connect();

    const orderHeader = await client.query("SELECT * FROM orders WHERE id=$1", [orderId]);

    if (!orderHeader.rows.length) return res.status(404).send("Order not found");

    if (!req.session.user.is_admin && orderHeader.rows[0].created_by !== req.session.user.username)
      return res.status(403).send("Access denied");

    const rows = await client.query(
      `
      SELECT 
        o.id AS order_id, o.party_name, o.route, o.item_group, 
        o.created_at, o.created_by,
        oi.item_name, oi.qty, oi.uom, oi.netrate, oi.discount_percent, 
        oi.discount_amount, oi.batch, oi.gst_percent, oi.mrp
      FROM orders o
      JOIN order_items oi ON o.id = oi.order_id
      WHERE o.id=$1
      ORDER BY oi.id ASC
    `,
      [orderId]
    );

    const parser = new Parser();
    const csv = parser.parse(rows.rows);

    res.header("Content-Type", "text/csv");
    res.attachment(`order_${orderId}.csv`);
    return res.send(csv);
  } catch (err) {
    console.error("❌ /api/orders/download/:id error:", err);
    res.status(500).send("Error exporting the order.");
  } finally {
    if (client) client.release();
  }
});

// ---------------- DOWNLOAD ALL ORDERS (CSV ONLY) ----------------
app.get("/download-orders", checkAuth, async (req, res) => {
  if (!req.session.user.is_admin) return res.status(403).send("Access denied.");

  try {
    const rows = await pool.query(`
      SELECT 
        o.id AS order_id,
        o.party_name,
        o.route,
        o.item_group,
        o.created_at,
        oi.item_name,
        oi.qty,
        oi.netrate,
        oi.discount_percent,
        oi.mrp
      FROM orders o
      JOIN order_items oi ON o.id = oi.order_id
      ORDER BY o.created_at DESC;
    `);

    if (!rows.rows.length) return res.status(404).send("No orders found.");

    const fields = Object.keys(rows.rows[0]);
    const parser = new Parser({ fields });
    const csv = parser.parse(rows.rows);

    res.header("Content-Type", "text/csv");
    res.attachment(`all_orders_${Date.now()}.csv`);
    return res.send(csv);
  } catch (err) {
    console.error("❌ /download-orders error:", err);
    res.status(500).send("Server error while downloading orders.");
  }
});

// ---------------- UPLOAD PARTY ROUTES CSV ----------------
app.post("/upload-party", checkAuth, upload.single("csvfile"), async (req, res) => {
  if (!req.session.user.is_admin) return res.status(403).send("Access denied.");
  if (!req.file) return res.status(400).send("No file uploaded.");

  const filePath = req.file.path;
  const partyData = [];

  fs.createReadStream(filePath)
    .pipe(csvParser())
    .on("data", (row) => partyData.push(row))
    .on("end", async () => {
      let client;
      try {
        client = await pool.connect();
        await client.query("BEGIN");
        await client.query("DELETE FROM party_routes");

        for (const p of partyData) {
          await client.query(
            "INSERT INTO party_routes (route, party_name) VALUES ($1,$2)",
            [
              p.route ?? p.Route ?? "",
              p["party name"] ?? p.party_name ?? p.partyName ?? p.Party ?? "",
            ]
          );
        }

        await client.query("COMMIT");

        res.send(
          `<script>alert('✔ Party routes uploaded successfully!');window.location.href="/upload";</script>`
        );
      } catch (err) {
        if (client) await client.query("ROLLBACK").catch(() => {});
        console.error("❌ /upload-party error:", err);
        res.status(500).send("Error saving routes");
      } finally {
        if (client) client.release();
        fs.unlink(filePath, (e) => e && console.error("Failed to delete upload file:", e));
      }
    })
    .on("error", (err) => {
      console.error("❌ CSV parse error (party):", err);
      fs.unlink(filePath, () => {});
      res.status(400).send("Invalid CSV file.");
    });
});

// ---------------- UPLOAD ITEMS CSV ----------------
app.post("/upload-items", checkAuth, upload.single("csvfile"), async (req, res) => {
  if (!req.session.user.is_admin) return res.status(403).send("Access denied.");
  if (!req.file) return res.status(400).send("No file uploaded.");

  const filePath = req.file.path;
  const itemsData = [];

  fs.createReadStream(filePath)
    .pipe(csvParser())
    .on("data", (row) => itemsData.push(row))
    .on("end", async () => {
      let client;
      try {
        client = await pool.connect();
        await client.query("BEGIN");
        await client.query("DELETE FROM items");

        for (const i of itemsData) {
          await client.query(
            `INSERT INTO items
              (name, item_group, uom, quantity, netrate, mrp, gst_percent)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [
              i.name ?? i.Name ?? "",
              i.item_group ?? i.itemGroup ?? "",
              i.uom ?? i.UOM ?? "",
              safeNumber(i.quantity, 0),
              safeNumber(i.netrate, 0),
              safeNumber(i.mrp, 0),
              safeNumber(i.gst_percent, 0),
            ]
          );
        }

        await client.query("COMMIT");

        res.send(
          `<script>alert('✔ Items uploaded successfully!');window.location.href="/upload";</script>`
        );
      } catch (err) {
        if (client) await client.query("ROLLBACK").catch(() => {});
        console.error("❌ /upload-items error:", err);
        res.status(500).send("Error uploading items");
      } finally {
        if (client) client.release();
        fs.unlink(filePath, (e) => e && console.error("Failed to delete upload file:", e));
      }
    })
    .on("error", (err) => {
      console.error("❌ CSV parse error (items):", err);
      fs.unlink(filePath, () => {});
      res.status(400).send("Invalid CSV file.");
    });
});

// ---------------- LOGOUT ----------------
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ---------------- START SERVER ----------------
app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}`));
