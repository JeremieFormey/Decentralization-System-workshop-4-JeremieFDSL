import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { 
  createRandomSymmetricKey, 
  exportSymKey, 
  importPubKey, 
  rsaEncrypt, 
  symEncrypt 
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

  _user.get("/status", (req, res) => {
    res.send("live");
  });
  
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });
  
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });
  
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });
  
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });
  
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body as SendMessageBody;
      lastSentMessage = message;
      
      const registry = await fetch(`http://localhost:8080/getNodeRegistry`)
        .then(res => res.json())
        .then(json => (json as { nodes: any[] }).nodes);
      
      const nodeIds = registry.map(node => node.nodeId);
      const circuit = getRandomCircuit(nodeIds, 3);
      lastCircuit = circuit;
      
      const finalDestination = BASE_USER_PORT + destinationUserId;
      
      let currentMessage = message;
      let currentDestination = finalDestination;
      
      for (let i = circuit.length - 1; i >= 0; i--) {
        const currentNodeId = circuit[i];
        const currentNode = registry.find(n => n.nodeId === currentNodeId);
        
        if (!currentNode) {
          throw new Error(`Node ${currentNodeId} not found in registry`);
        }
        
        const paddedDestination = currentDestination.toString().padStart(10, '0');
        const dataToEncrypt = paddedDestination + currentMessage;
        
        const symmetricKey = await createRandomSymmetricKey();
        const symmetricKeyStr = await exportSymKey(symmetricKey);
        
        const encryptedData = await symEncrypt(symmetricKey, dataToEncrypt);
        
        const encryptedKey = await rsaEncrypt(symmetricKeyStr, currentNode.pubKey);
        
        currentMessage = encryptedKey + encryptedData;
        
        currentDestination = BASE_ONION_ROUTER_PORT + currentNodeId;
      }
      
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0]}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: currentMessage
        })
      });
      
      res.send("success");
    } catch (error) {
      console.error(`Error sending message from user ${userId}:`, error);
      res.status(500).send("error");
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}

function getRandomCircuit(nodeIds: number[], length: number): number[] {
  if (nodeIds.length < length) {
    throw new Error('Not enough nodes to create a circuit');
  }
  
  const shuffled = [...nodeIds].sort(() => 0.5 - Math.random());
  return shuffled.slice(0, length);
}
