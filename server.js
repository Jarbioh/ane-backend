require('dotenv').config();
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const winston = require("winston");
const { promisify } = require("util");
const sanitizeHtml = require("sanitize-html");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [
      'http://localhost:5173',
      'http://localhost:4173',
      'https://ane-software.vercel.app',              // Adicione aqui também para WebSocket
      'https://ane-software-qvu95hlai-jarbios-projects.vercel.app',
      'https://ane-backend-nin2.onrender.com'
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
  },
});
const PORT = process.env.PORT || 3000;

// Configuração de Logs com Winston
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

// Configuração de CORS para rotas HTTP
app.use(
  cors({
    origin: [
    'http://localhost:5173',                          // Desenvolvimento local (Vite)
    'http://localhost:4173',                          // Preview local (Vite)
    'https://ane-software.vercel.app',                // Frontend em produção no Vercel
    'https://ane-software-qvu95hlai-jarbios-projects.vercel.app', // URL específica do deploy
    'https://ane-backend-nin2.onrender.com'           // Backend em produção
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  })
);
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Configuração do Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) =>
    cb(null, `${Date.now()}${path.extname(file.originalname)}`),
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // Alinhado com o frontend: 10 MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "audio/webm", // Suporte a áudio do frontend
    ];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Apenas PDFs, JPEG, PNG e áudio WEBM são permitidos."));
    }
    cb(null, true);
  },
});

// Dados persistentes (simulação com cache em disco)
let stats = { files: 0, users: 10, messages: 35, groups: 1 };
let users = [
  { id: 1, name: "Usuário Teste", email: "teste@ane.com", status: "ativo" },
];
let messages = [];
const readdirAsync = promisify(fs.readdir);

const loadDataFromDisk = async () => {
  try {
    const userData = fs.existsSync("users.json")
      ? JSON.parse(fs.readFileSync("users.json"))
      : [];
    const fileData = (await readdirAsync(uploadsDir)).filter(
      (f) => f !== ".gitignore"
    );
    users = userData.map((u, i) => ({ id: i + 1, ...u }));
    stats.files = fileData.length;
    stats.users = users.length;
    logger.info("Dados carregados do disco com sucesso");
  } catch (err) {
    logger.error("Erro ao carregar dados do disco:", err);
  }
};

const saveDataToDisk = () => {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
  logger.info("Dados salvos no disco com sucesso");
};

loadDataFromDisk();

// Rotas HTTP
app.get("/", (req, res) => {
  logger.info("Rota raiz acessada");
  res.send("Servidor funcionando! Acesse as rotas ou use o WebSocket.");
});

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    logger.error("Nenhum arquivo enviado em /upload");
    return res.status(400).json({ error: "Nenhum arquivo enviado" });
  }
  stats.files += 1;
  io.emit("stats-update", stats);
  io.emit("file-uploaded", req.file.filename);
  logger.info(`Arquivo ${req.file.filename} enviado`);
  res.json({ filename: req.file.filename, message: "Arquivo enviado com sucesso" });
});

app.get("/files", async (req, res) => {
  try {
    const files = await readdirAsync(uploadsDir);
    logger.info("Lista de arquivos retornada");
    res.json({ files: files.filter((f) => f !== ".gitignore") });
  } catch (err) {
    logger.error("Erro ao listar arquivos:", err);
    res.status(500).json({ error: "Erro ao listar arquivos" });
  }
});

app.get("/download/:filename", (req, res) => {
  const filePath = path.join(uploadsDir, req.params.filename);
  if (fs.existsSync(filePath)) {
    res.download(filePath, req.params.filename, (err) => {
      if (err) logger.error(`Erro ao enviar arquivo ${req.params.filename}:`, err);
      else logger.info(`Arquivo ${req.params.filename} baixado`);
    });
  } else {
    logger.error(`Arquivo ${req.params.filename} não encontrado`);
    res.status(404).json({ error: "Arquivo não encontrado" });
  }
});

app.delete("/files/:filename", (req, res) => {
  const filePath = path.join(uploadsDir, req.params.filename);
  if (fs.existsSync(filePath)) {
    fs.unlink(filePath, (err) => {
      if (err) {
        logger.error(`Erro ao excluir arquivo ${req.params.filename}:`, err);
        return res.status(500).json({ error: "Erro ao excluir arquivo" });
      }
      stats.files = Math.max(0, stats.files - 1);
      io.emit("stats-update", stats);
      io.emit("file-deleted", req.params.filename);
      logger.info(`Arquivo ${req.params.filename} excluído`);
      res.json({ message: "Arquivo excluído com sucesso" });
    });
  } else {
    logger.error(`Arquivo ${req.params.filename} não encontrado para exclusão`);
    res.status(404).json({ error: "Arquivo não encontrado" });
  }
});

app.get("/stats", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || auth !== "Bearer admin-token") {
    logger.warn("Acesso negado: sem autorização para stats");
    return res.status(403).json({ error: "Permissão negada" });
  }
  logger.info("Estatísticas retornadas");
  res.json(stats);
});

app.get("/users", (req, res) => {
  logger.info("Lista de usuários retornada");
  res.json(users);
});

app.post("/users", (req, res) => {
  const { name, email, status } = req.body;
  const auth = req.headers.authorization;
  if (!auth || auth !== "Bearer admin-token") {
    logger.warn("Acesso negado: sem autorização para adicionar usuário");
    return res.status(403).json({ error: "Permissão negada" });
  }
  if (!name || !email) {
    logger.error("Dados inválidos para adicionar usuário:", req.body);
    return res.status(400).json({ error: "Nome e email são obrigatórios" });
  }
  const newUser = { id: users.length + 1, name, email, status: status || "ativo" };
  users.push(newUser);
  stats.users += 1;
  saveDataToDisk();
  io.emit("stats-update", stats);
  io.emit("user-updated", users);
  logger.info(`Usuário ${name} (${email}) adicionado`);
  res.status(201).json(newUser);
});

app.put("/users/:id", (req, res) => {
  const { id } = req.params;
  const { name, email, status } = req.body;
  const auth = req.headers.authorization;
  if (!auth || auth !== "Bearer admin-token") {
    logger.warn(`Acesso negado: sem autorização para editar usuário ${id}`);
    return res.status(403).json({ error: "Permissão negada" });
  }
  if (!name || !email) {
    logger.error(`Dados inválidos para editar usuário ${id}:`, req.body);
    return res.status(400).json({ error: "Nome e email são obrigatórios" });
  }
  const userIndex = users.findIndex((u) => u.id === parseInt(id));
  if (userIndex === -1) {
    logger.error(`Usuário ${id} não encontrado para edição`);
    return res.status(404).json({ error: "Usuário não encontrado" });
  }
  users[userIndex] = { ...users[userIndex], name, email, status };
  saveDataToDisk();
  io.emit("user-updated", users);
  logger.info(`Usuário ${id} atualizado`);
  res.json(users[userIndex]);
});

app.delete("/users/:id", (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const auth = req.headers.authorization;
  if (!auth || auth !== "Bearer admin-token") {
    logger.warn(`Acesso negado: sem autorização para excluir usuário ${userId}`);
    return res.status(403).json({ error: "Permissão negada" });
  }
  const initialLength = users.length;
  users = users.filter((user) => user.id !== userId);
  if (users.length < initialLength) {
    stats.users = Math.max(0, stats.users - 1);
    saveDataToDisk();
    io.emit("stats-update", stats);
    io.emit("user-deleted", userId);
    logger.info(`Usuário ${userId} excluído`);
    res.json({ message: "Usuário excluído com sucesso" });
  } else {
    logger.error(`Usuário ${userId} não encontrado para exclusão`);
    res.status(404).json({ error: "Usuário não encontrado" });
  }
});

app.get("/messages", (req, res) => {
  logger.info("Mensagens retornadas");
  res.json(messages);
});

app.post("/sanitize", (req, res) => {
  const { text } = req.body;
  const auth = req.headers.authorization;
  if (!auth || auth !== "Bearer admin-token") {
    logger.warn("Acesso negado: sem autorização para sanitizar texto");
    return res.status(403).json({ error: "Permissão negada" });
  }
  if (!text) {
    logger.error("Nenhum texto enviado para sanitização");
    return res.status(400).json({ error: "Texto é obrigatório" });
  }
  const sanitized = sanitizeHtml(text, {
    allowedTags: ["b", "i", "em", "strong", "a"],
    allowedAttributes: { a: ["href"] },
  });
  logger.info("Texto sanitizado com sucesso");
  res.json({ sanitized });
});

// WebSocket
io.on("connection", (socket) => {
  logger.info(`WebSocket conectado: ${socket.id}`);
  socket.emit("stats-update", stats);

  socket.on("join-room", (roomID) => {
    socket.join(roomID);
    logger.info(`Usuário ${socket.id} entrou na sala ${roomID}`);
    socket.to(roomID).emit("user-joined", { signal: null, callerID: socket.id });
    io.to(roomID).emit("update-participants", {
      participants: Array.from(io.sockets.adapter.rooms.get(roomID) || []).map(
        (id) => id
      ),
    });
  });

  socket.on("sendMessage", (msg) => {
    stats.messages += 1;
    messages.push({ ...msg, timestamp: new Date().toISOString() });
    socket.broadcast.emit("message", { ...msg, timestamp: new Date().toISOString() });
    io.emit("stats-update", stats);
    logger.info(`Mensagem enviada: ${msg.text} (${msg.chatType})`);
  });

  socket.on("returning-signal", (payload) => {
    io.to(payload.callerID).emit("receiving-returned-signal", {
      signal: payload.signal,
      id: socket.id,
    });
    logger.info(`Sinal retornado para ${payload.callerID}`);
  });

  socket.on("chat-message", (payload) => {
    io.to(payload.room).emit("chat-message", { message: payload.message });
    stats.messages += 1;
    messages.push({
      text: payload.message,
      sender: socket.id,
      timestamp: new Date().toISOString(),
    });
    io.emit("stats-update", stats);
    logger.info(`Mensagem de chat da sala ${payload.room}: ${payload.message}`);
  });

  socket.on("update-participants", (payload) => {
    io.to(payload.room).emit("update-participants", {
      participants: Array.from(io.sockets.adapter.rooms.get(payload.room) || []).map(
        (id) => id
      ),
    });
    logger.info(`Participantes atualizados na sala ${payload.room}`);
  });

  socket.on("invite", (payload) => {
    io.to(payload.participantID).emit("invited", {
      room: payload.room,
      participantID: socket.id,
    });
    logger.info(`Convite enviado para ${payload.participantID} para a sala ${payload.room}`);
  });

  socket.on("call", (payload) => {
    io.to(payload.to).emit("incoming-call", { from: socket.id });
    logger.info(`Chamada iniciada de ${socket.id} para ${payload.to}`);
  });

  socket.on("accept-call", (payload) => {
    io.to(payload.to).emit("call-accepted", { from: socket.id });
    logger.info(`Chamada aceita por ${socket.id} para ${payload.to}`);
  });

  socket.on("reject-call", (payload) => {
    io.to(payload.to).emit("call-rejected", { from: socket.id });
    logger.info(`Chamada rejeitada por ${socket.id} para ${payload.to}`);
  });

  socket.on("hand-raised", (payload) => {
    io.to(payload.room).emit("hand-raised-update", {
      user: payload.user,
      raised: payload.raised,
    });
    logger.info(`Mão levantada por ${payload.user} na sala ${payload.room}`);
  });

  socket.on("reaction", (payload) => {
    io.to(payload.room).emit("reaction-update", {
      user: payload.user,
      reaction: payload.reaction,
    });
    logger.info(`Reação ${payload.reaction} por ${payload.user} na sala ${payload.room}`);
  });

  socket.on("leave-room", (roomID) => {
    socket.leave(roomID);
    socket.to(roomID).emit("user-disconnected", socket.id);
    io.to(roomID).emit("update-participants", {
      participants: Array.from(io.sockets.adapter.rooms.get(roomID) || []).map(
        (id) => id
      ),
    });
    logger.info(`Usuário ${socket.id} saiu da sala ${roomID}`);
  });

  socket.on("disconnect", () => {
    logger.info(`WebSocket desconectado: ${socket.id}`);
    const rooms = io.sockets.adapter.rooms;
    for (const roomID of socket.rooms) {
      if (roomID !== socket.id) {
        io.to(roomID).emit("update-participants", {
          participants: Array.from(rooms.get(roomID) || []).map((id) => id),
        });
      }
    }
  });

  socket.on("error", (err) => {
    logger.error(`Erro no WebSocket ${socket.id}:`, err.message);
  });
});

server.listen(PORT, () => {
  logger.info(`Servidor rodando em http://localhost:${PORT} com WebSocket`);
});

process.on("uncaughtException", (err) => {
  logger.error("Erro não tratado:", err);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Rejeição não tratada:", reason);
  process.exit(1);
});