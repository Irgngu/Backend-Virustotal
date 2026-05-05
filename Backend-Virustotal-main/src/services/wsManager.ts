import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";

let wss: WebSocketServer | null = null;

export function initWSS(server: Server): void {
  wss = new WebSocketServer({ server, path: "/ws" });

  wss.on("connection", (ws: WebSocket) => {
    console.log(`[WS] Client connected — total: ${wss?.clients.size}`);

    // Kirim history awal saat client connect (opsional, bisa dari REST juga)
    ws.on("close", () => console.log("[WS] Client disconnected"));
    ws.on("error", (err) => console.error("[WS] Error:", err.message));
  });

  console.log("[WS] WebSocket server ready on ws://localhost/ws");
}

export function broadcastNewReport(entry: object): void {
  if (!wss) return;
  const payload = JSON.stringify({ type: "NEW_REPORT", data: entry });
  wss.clients.forEach((client: WebSocket) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}
