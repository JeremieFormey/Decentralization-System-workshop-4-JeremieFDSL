// For registry.ts
import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // In-memory storage for nodes
  const nodes: Node[] = [];

  // Status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });
  
  // Route to register nodes
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;
    
    // Check if node already exists
    const existingNode = nodes.find(node => node.nodeId === nodeId);
    if (existingNode) {
      // Update public key if node exists
      existingNode.pubKey = pubKey;
    } else {
      // Add new node
      nodes.push({ nodeId, pubKey });
    }
    
    res.send("success");
  });
  
  // Route to get node registry
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}