import "dotenv/config";
import express from "express";
import path from "path";
import crypto from "crypto";
import { createServer as createViteServer } from "vite";

function getExpectedPassword(): string {
  return process.env.APP_PASSWORD || process.env.VITE_APP_PASSWORD || "admin123";
}

function generateToken(password: string): string {
  return crypto.createHash("sha256").update(`${password}_app_salt_secret_key`).digest("hex");
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json());

  // Health check route
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  // Check auth status
  app.get("/api/auth/status", (req, res) => {
    res.json({ passwordRequired: true });
  });

  // Verify token
  app.get("/api/auth/verify", (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith("Bearer ") 
      ? authHeader.slice(7) 
      : (req.query.token as string);

    const expectedPass = getExpectedPassword();
    const validToken = generateToken(expectedPass);

    if (token && token === validToken) {
      return res.json({ authenticated: true });
    }
    return res.status(401).json({ authenticated: false, message: "Geçersiz veya süresi dolmuş oturum." });
  });

  // Login with single app_password
  app.post("/api/auth/login", (req, res) => {
    const { password } = req.body;
    const expectedPass = getExpectedPassword();

    if (typeof password === "string" && password.trim() === expectedPass.trim()) {
      const token = generateToken(expectedPass);
      return res.json({ success: true, token });
    }

    return res.status(401).json({ 
      success: false, 
      message: "Hatalı parola! Lütfen tekrar deneyin." 
    });
  });

  // Logout
  app.post("/api/auth/logout", (req, res) => {
    res.json({ success: true });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
